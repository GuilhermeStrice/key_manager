// WebSocket server logic
import WebSocket from 'ws';
import * as DataManager from '../lib/dataManager';

// Extend WebSocket instance type to hold authentication state
interface AuthenticatedWebSocket extends WebSocket {
  // isAuthenticated is now effectively controlled by acceptAllWebSocketConnections
  // clientInfo might not be relevant if not uniquely identifying for auth.
  // For now, we'll keep it to store basic info if registered.
  clientRegisteredName?: string; // Store the name given during REGISTER_CLIENT
  clientServerId?: string; // Store the server-assigned ID (from DataManager)
}

// Define response codes (as defined in the plan step)
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
  // CONFLICT: 4009, // Not used yet

  // Server Errors
  INTERNAL_SERVER_ERROR: 5000,
};

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

  const wss = new WebSocket.Server({ port });

  wss.on('connection', (ws: AuthenticatedWebSocket) => {
    console.log('Client connected to WebSocket server. Awaiting registration.');

    ws.on('message', async (messageData) => {
      let parsedMessage;
      let clientRequestId: string | undefined;

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

          } catch (error: any) {
            console.error("Registration error:", error);
            sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: `Registration failed: ${error.message}` }, clientRequestId);
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
                const secretKey = payload.secretKey;
                if (clientInfo.associatedSecretKeys.includes(secretKey)) {
                  const secretValue = DataManager.getSecretItem(secretKey);
                  if (secretValue !== undefined) {
                    sendWsResponse(ws, "SECRET_DATA", WsResponseCodes.OK, { secretKey, value: secretValue }, clientRequestId);
                  } else {
                    console.error(`Client ${clientInfo.name} authorized for non-existent secret ${secretKey}`);
                    sendWsResponse(ws, "ERROR", WsResponseCodes.NOT_FOUND, { detail: `Secret key "${secretKey}" not found on server, though authorized.` }, clientRequestId);
                  }
                } else {
                  sendWsResponse(ws, "ERROR", WsResponseCodes.UNAUTHORIZED, { detail: "You are not authorized to access this secret." }, clientRequestId);
                }
              } catch (error: any) {
                console.error("Error requesting secret:", error);
                sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: `Error requesting secret: ${error.message}` }, clientRequestId);
              }
              break;

            case 'LIST_AUTHORIZED_SECRETS':
              try {
                sendWsResponse(ws, "AUTHORIZED_SECRETS_LIST", WsResponseCodes.OK, { authorizedSecretKeys: clientInfo.associatedSecretKeys }, clientRequestId);
              } catch (error: any) {
                console.error("Error listing authorized secrets:", error);
                sendWsResponse(ws, "ERROR", WsResponseCodes.INTERNAL_SERVER_ERROR, { detail: `Error listing authorized secrets: ${error.message}` }, clientRequestId);
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
