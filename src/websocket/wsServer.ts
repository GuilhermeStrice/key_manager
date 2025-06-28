// WebSocket server logic
import WebSocket from 'ws';
import * as DataManager from '../lib/dataManager';
import { getConfig } from '../lib/configManager'; // Import getConfig

// Extend WebSocket instance type to hold authentication state and rate limit data
interface AuthenticatedWebSocket extends WebSocket {
  clientRegisteredName?: string; // Store the name given during REGISTER_CLIENT
  clientServerId?: string; // Store the server-assigned ID (from DataManager)
  // Rate limiting properties
  lastMessageTime?: number;
  messageCount?: number;
  // For IP based limiting before registration
  ip?: string;
}

// Define response codes
const WsResponseCodes = {
  // Success
  OK: 2000,
  REGISTRATION_SUBMITTED: 2001,
  // CLIENT_APPROVED: 2002, // Not used directly in responses yet
  // NO_CONTENT: 2004, // Not used directly in responses yet

  // Client Errors
  BAD_REQUEST: 4000,
  UNAUTHORIZED: 4001, // For when client status is not 'approved' for an action
  // FORBIDDEN: 4003, // Not used yet
  NOT_FOUND: 4004,
  CLIENT_NOT_REGISTERED: 4005, // Client hasn't sent REGISTER_CLIENT yet
  CLIENT_REGISTRATION_EXPIRED: 4006, // Client's pending registration expired
  RATE_LIMIT_EXCEEDED: 4029, // Standard "Too Many Requests"
  // CONFLICT: 4009, // Not used yet

  // Server Errors
  INTERNAL_SERVER_ERROR: 5000,
};

// Rate Limiting Configuration
const WS_RATE_LIMIT_WINDOW_MS = parseInt(process.env.WS_RATE_LIMIT_WINDOW_MS || (60 * 1000).toString(), 10); // 1 minute
const WS_MAX_MESSAGES_PER_WINDOW = parseInt(process.env.WS_MAX_MESSAGES_PER_WINDOW || '100', 10); // 100 messages per minute
const WS_REGISTER_RATE_LIMIT_WINDOW_MS = parseInt(process.env.WS_REGISTER_RATE_LIMIT_WINDOW_MS || (60 * 60 * 1000).toString(), 10); // 1 hour
const WS_MAX_REGISTRATIONS_PER_WINDOW = parseInt(process.env.WS_MAX_REGISTRATIONS_PER_WINDOW || '10', 10); // 10 registration attempts per hour (per IP)

// Store for IP-based rate limiting for registration attempts
const registrationRateLimiter = new Map<string, { count: number, windowStart: number }>();


// Helper function to send structured responses
function sendWsResponse(ws: AuthenticatedWebSocket, type: string, code: number, payload: object, requestId?: string) {
  const response = { type, code, payload, requestId };
  ws.send(JSON.stringify(response));
}

// Map to store active WebSocket connections by their server-assigned client ID
const activeConnections: Map<string, AuthenticatedWebSocket> = new Map();

// Function to be exported for HTTP server to call
export function notifyClientStatusUpdate(clientId: string, newStatus: DataManager.ClientStatus, detail?: string) {
    const ws = activeConnections.get(clientId);
    if (ws && ws.readyState === WebSocket.OPEN) {
        let responseCode = WsResponseCodes.OK; // Generic OK for status update
        let messageType = "STATUS_UPDATE";

        if (newStatus === 'approved') {
            // Optionally use a more specific code or rely on payload.
            // For now, client will get 'approved' in payload.
            // responseCode = WsResponseCodes.CLIENT_APPROVED; // If we had this code used for responses
            console.log(`Notifying client ${clientId} of approval.`);
        } else if (newStatus === 'rejected') {
            responseCode = WsResponseCodes.UNAUTHORIZED; // Or a specific "CLIENT_REJECTED" code if defined
            console.log(`Notifying client ${clientId} of rejection.`);
        }
        // Add more cases if other statuses are pushed (e.g., 'expired' if distinct from 'rejected')

        sendWsResponse(ws, messageType, responseCode, {
            newStatus: newStatus,
            detail: detail || `Your registration status is now: ${newStatus}`
        });
    } else {
        console.log(`Client ${clientId} not actively connected or WebSocket not open. Cannot send status update.`);
    }
}


export function startWebSocketServer(port: number) {
  // Removed initialConnectionMode and acceptAllWebSocketConnections global toggle
  console.log(`WebSocket server starting. All connections require registration and approval.`);
  console.log(`WS Rate Limiting: General: ${WS_MAX_MESSAGES_PER_WINDOW} msgs / ${WS_RATE_LIMIT_WINDOW_MS / 1000}s. Register: ${WS_MAX_REGISTRATIONS_PER_WINDOW} attempts / ${WS_REGISTER_RATE_LIMIT_WINDOW_MS / 1000 / 60}m.`);


  const wss = new WebSocket.Server({ port });

  wss.on('connection', (ws: AuthenticatedWebSocket, req) => {
    // Get client IP - req.socket.remoteAddress might be undefined if connection is already closed or proxied without proper headers.
    // For proxies, ensure 'x-forwarded-for' is trusted and used if available.
    // Simplified: use remoteAddress directly.
    ws.ip = req.socket.remoteAddress || 'unknown';
    console.log(`Client connected from IP: ${ws.ip}. Awaiting registration.`);

    // Initialize rate limiting properties for general messages
    ws.messageCount = 0;
    ws.lastMessageTime = Date.now();


    ws.on('message', async (messageData) => {
      let parsedMessage;
      let clientRequestId: string | undefined;

      // --- General Per-Client Rate Limiting (for registered clients) ---
      if (ws.clientServerId) { // Only apply this to registered clients
        const now = Date.now();
        if (now - (ws.lastMessageTime || now) > WS_RATE_LIMIT_WINDOW_MS) {
          ws.messageCount = 1;
          ws.lastMessageTime = now;
        } else {
          ws.messageCount = (ws.messageCount || 0) + 1;
          if (ws.messageCount > WS_MAX_MESSAGES_PER_WINDOW) {
            console.warn(`Client ${ws.clientServerId} (${ws.clientRegisteredName}) exceeded general message rate limit from IP ${ws.ip}.`);
            sendWsResponse(ws, "ERROR", WsResponseCodes.RATE_LIMIT_EXCEEDED, { detail: `Too many messages. Please slow down. Limit: ${WS_MAX_MESSAGES_PER_WINDOW} per ${WS_RATE_LIMIT_WINDOW_MS / 1000}s.` });
            // Optionally, could implement a short cooldown or temporary ignore here.
            // For now, just sending error and processing no further for this message.
            return;
          }
        }
      }
      // --- End General Per-Client Rate Limiting ---


      try {
        const messageString = messageData.toString();
        parsedMessage = JSON.parse(messageString);
        clientRequestId = parsedMessage.requestId; // Capture client's requestId if provided
        console.log('Received from client:', parsedMessage);
      } catch (error) {
        console.error('Failed to parse message or message not JSON:', messageData.toString());
        sendWsResponse(ws, "ERROR", WsResponseCodes.BAD_REQUEST, { detail: "Invalid message format. Expected JSON." });
        return;
      }

      const { type, payload } = parsedMessage;

      if (type !== 'REGISTER_CLIENT' && !ws.clientServerId) {
        console.log("Client sent command before registration.");
        sendWsResponse(ws, "ERROR", WsResponseCodes.CLIENT_NOT_REGISTERED, { detail: "Client must register first using REGISTER_CLIENT." }, clientRequestId);
        return;
      }


      switch (type) {
        case 'REGISTER_CLIENT':
          // --- IP-based Rate Limiting for Registration ---
          const ip = ws.ip!; // Should be set on connection
          const now = Date.now();
          let ipInfo = registrationRateLimiter.get(ip);

          if (ipInfo && (now - ipInfo.windowStart < WS_REGISTER_RATE_LIMIT_WINDOW_MS)) {
            ipInfo.count++;
          } else { // New window or first attempt for this IP
            ipInfo = { count: 1, windowStart: now };
            registrationRateLimiter.set(ip, ipInfo);
          }
          // Clean up old entries from the registrationRateLimiter map periodically (not shown here for brevity, but important for long-running servers)

          if (ipInfo.count > WS_MAX_REGISTRATIONS_PER_WINDOW) {
            console.warn(`IP ${ip} exceeded registration rate limit.`);
            sendWsResponse(ws, "ERROR", WsResponseCodes.RATE_LIMIT_EXCEEDED, { detail: `Too many registration attempts from this IP. Please try again later. Limit: ${WS_MAX_REGISTRATIONS_PER_WINDOW} per ${WS_REGISTER_RATE_LIMIT_WINDOW_MS / 1000 / 60} minutes.` }, clientRequestId);
            return; // Stop processing this registration request
          }
          // --- End IP-based Rate Limiting for Registration ---

          try {
            if (ws.clientServerId) {
                sendWsResponse(ws, "ERROR", WsResponseCodes.BAD_REQUEST, { detail: "Client already registered for this connection." }, clientRequestId);
                return;
            }
            if (!payload || !payload.clientName) {
              sendWsResponse(ws, "ERROR", WsResponseCodes.BAD_REQUEST, { detail: "clientName is required for registration." }, clientRequestId);
              return;
            }
            // Add to DataManager as pending
            const newClient = await DataManager.addPendingClient(payload.clientName, payload.requestedSecretKeys);

            ws.clientRegisteredName = newClient.name;
            ws.clientRegisteredName = newClient.name;
            ws.clientServerId = newClient.id;

            // Store active connection
            activeConnections.set(newClient.id, ws);
            console.log(`Active connections: ${activeConnections.size}`);


            sendWsResponse(ws, "REGISTRATION_ACK", WsResponseCodes.REGISTRATION_SUBMITTED, {
                clientId: newClient.id,
                detail: `Registration for "${newClient.name}" submitted. Awaiting admin approval. Your Client ID is ${newClient.id}.`
            }, clientRequestId);
            console.log(`Client "${newClient.name}" (ID: ${newClient.id}) registration submitted.`);

            // Auto-approve if flag is set
            if (getConfig().autoApproveWebSocketRegistrations) {
              console.log(`Auto-approving client ${newClient.id} (debug mode).`);
              try {
                await DataManager.approveClient(newClient.id);
                notifyClientStatusUpdate(newClient.id, 'approved', 'Client registration automatically approved (debug mode).');
              } catch (approvalError) {
                console.error(`Error auto-approving client ${newClient.id}:`, approvalError);
                // Optionally notify client of auto-approval failure, though they'll remain pending
              }
            }

          } catch (error: any) {
            console.error("Registration error:", error);
            sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: "An internal error occurred during registration. Please try again later or contact support if the issue persists." }, clientRequestId);
          }
          break;

        // Placeholder for other message types (e.g., REQUEST_SECRET) - will be handled in next step
        // For now, if not authenticated, reject other types.
        default:
          // At this point, ws.clientServerId should be set if type is not REGISTER_CLIENT.
          // Now, we check the client's status from DataManager.
          const clientInfo = ws.clientServerId ? DataManager.getClient(ws.clientServerId) : undefined;

          if (!clientInfo) {
            console.log(`Client data not found for ID: ${ws.clientServerId}. Terminating connection.`);
            sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: "Client not recognized or registration incomplete. Please re-register." }, clientRequestId);
            ws.terminate(); // Or close, terminate is more abrupt
            return;
          }

          if (clientInfo.status === 'pending') {
            // Check if registration might have expired
            if (clientInfo.registrationTimestamp && (Date.now() - clientInfo.registrationTimestamp > (60 * 1000 + 5000))) { // Add 5s buffer to expiry check
                 sendWsResponse(ws, "ERROR", WsResponseCodes.CLIENT_REGISTRATION_EXPIRED, { detail: "Your registration request has expired. Please register again." }, clientRequestId);
            } else {
                 sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: "Client registration is pending admin approval." }, clientRequestId);
            }
            return;
          }

          if (clientInfo.status === 'rejected') {
            sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: "Client registration was rejected by admin." }, clientRequestId);
            return;
          }

          if (clientInfo.status !== 'approved') {
            sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: `Client not approved. Current status: ${clientInfo.status}.` }, clientRequestId);
            return;
          }

          // If we reach here, client is approved.
          console.log(`Processing message type "${type}" for approved client: ${clientInfo.name} (${clientInfo.id})`);

          // Handle messages for authenticated clients
          switch(type) {
            case 'REQUEST_SECRET':
              try {
                if (!payload || !payload.secretKey) {
                  sendWsResponse(ws, "ERROR", WsResponseCodes.BAD_REQUEST, { detail: "secretKey is required for REQUEST_SECRET." }, clientRequestId);
                  return;
                }
                const secretKeyToRequest = payload.secretKey;
                // Use new DataManager function to get all keys client is authorized for
                const authorizedKeys = DataManager.getSecretsForClient(clientInfo.id);

                if (authorizedKeys.includes(secretKeyToRequest)) {
                  const secretData = DataManager.getSecretWithValue(secretKeyToRequest); // Fetch {value, groupId}
                  if (secretData && secretData.value !== undefined) {
                    sendWsResponse(ws, "SECRET_DATA", WsResponseCodes.OK, { secretKey: secretKeyToRequest, value: secretData.value }, clientRequestId);
                  } else {
                    // This case implies an inconsistency: client is authorized for a key that doesn't exist in secrets store.
                    console.error(`Client ${clientInfo.name} (ID: ${clientInfo.id}) authorized for non-existent secret key "${secretKeyToRequest}". Data inconsistency.`);
                    sendWsResponse(ws, "ERROR", WsResponseCodes.NOT_FOUND, { detail: `Secret key "${secretKeyToRequest}" not found on server, though client is authorized. Please contact admin.` }, clientRequestId);
                  }
                } else {
                  sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: `You are not authorized to access the secret key "${secretKeyToRequest}".` }, clientRequestId);
                }
              } catch (error: any) {
                console.error("Error processing REQUEST_SECRET:", error);
                sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: "An internal error occurred while requesting the secret. Please try again later." }, clientRequestId);
              }
              break;

            case 'LIST_AUTHORIZED_SECRETS':
              try {
                const authorizedKeys = DataManager.getSecretsForClient(clientInfo.id);
                sendWsResponse(ws, "AUTHORIZED_SECRETS_LIST", WsResponseCodes.OK, { authorizedSecretKeys: authorizedKeys }, clientRequestId);
              } catch (error: any) {
                console.error("Error processing LIST_AUTHORIZED_SECRETS:", error);
                sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: "An internal error occurred while listing authorized secrets. Please try again later." }, clientRequestId);
              }
              break;

            default:
              console.log(`Approved client ${clientInfo.name} sent unhandled message type: ${type}`);
              sendWsResponse(ws, "ERROR", WsResponseCodes.BAD_REQUEST, { detail: `Unknown message type: ${type}` }, clientRequestId);
              break;
          }
          break;
      }
    });

    ws.on('close', async () => { // Made async to await DataManager call
      const clientName = ws.clientRegisteredName || 'Unknown';
      const clientId = ws.clientServerId;
      console.log(`Client ${clientName} (${clientId || 'N/A'}) disconnected from WebSocket server`);

      if (clientId) {
        activeConnections.delete(clientId);
        console.log(`Removed client ${clientId} from active connections. Remaining: ${activeConnections.size}`);

        // Check client status before calling handleClientDisconnect
        const clientInfo = DataManager.getClient(clientId);
        if (clientInfo && clientInfo.status === 'approved') {
          try {
            await DataManager.handleClientDisconnect(clientId);
          } catch (dbError) {
            console.error(`Error updating DataManager on disconnect for client ${clientId}:`, dbError);
          }
        }
      }
    });

    ws.on('error', (error) => {
      console.error(`WebSocket error for client ${ws.clientRegisteredName || 'Unknown'}:`, error);
    });

    sendWsResponse(ws, "WELCOME", WsResponseCodes.OK, { detail: "Welcome! Please register your client using REGISTER_CLIENT message." });
  });

  console.log(`WebSocket server started on ws://localhost:${port}`);
  return wss;
}
