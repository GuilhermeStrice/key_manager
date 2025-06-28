// WebSocket server logic
import WebSocket from 'ws';
import * as DataManager from '../lib/dataManager';

// Extend WebSocket instance type to hold authentication state
interface AuthenticatedWebSocket extends WebSocket {
  isAuthenticated?: boolean;
  clientInfo?: DataManager.ClientInfo;
}

export function startWebSocketServer(port: number) {
  const wss = new WebSocket.Server({ port });

  wss.on('connection', (ws: AuthenticatedWebSocket) => {
    console.log('Client connected to WebSocket server');
    ws.isAuthenticated = false;

    ws.on('message', async (messageData) => {
      let parsedMessage;
      try {
        // Ensure messageData is a string before parsing
        const messageString = messageData.toString();
        parsedMessage = JSON.parse(messageString);
        console.log('Received from client:', parsedMessage);
      } catch (error) {
        console.error('Failed to parse message or message not JSON:', messageData.toString());
        ws.send(JSON.stringify({ type: "ERROR", payload: { message: "Invalid message format. Expected JSON." } }));
        return;
      }

      const { type, payload } = parsedMessage;

      switch (type) {
        case 'REGISTER_CLIENT':
          try {
            if (!payload || !payload.clientName) {
              throw new Error("clientName is required for registration.");
            }
            // Add to DataManager as pending
            const newClient = await DataManager.addPendingClient(payload.clientName, payload.requestedSecretKeys);
            ws.send(JSON.stringify({
              type: "REGISTRATION_PENDING",
              payload: {
                clientId: newClient.id, // This is the server-side ID for admin tracking
                temporaryId: newClient.temporaryId, // Client should hold onto this if needed for status checks (not implemented yet)
                message: `Registration for "${newClient.name}" is pending approval. Your client ID is ${newClient.id}.`
              }
            }));
          } catch (error: any) {
            ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Registration failed: ${error.message}` } }));
          }
          break;

        case 'AUTHENTICATE':
          try {
            if (!payload || !payload.authToken) {
                throw new Error("authToken is required for authentication.");
            }
            const clientInfo = DataManager.getClientByAuthToken(payload.authToken);
            if (clientInfo && clientInfo.status === 'approved') {
              ws.isAuthenticated = true;
              ws.clientInfo = clientInfo;
              ws.send(JSON.stringify({
                type: "AUTHENTICATED",
                payload: {
                  message: `Client "${clientInfo.name}" authenticated successfully.`,
                  clientId: clientInfo.id,
                  name: clientInfo.name,
                  associatedSecretKeys: clientInfo.associatedSecretKeys
                }
              }));
              console.log(`Client ${clientInfo.name} (${clientInfo.id}) authenticated.`);
            } else {
              ws.isAuthenticated = false;
              ws.clientInfo = undefined;
              ws.send(JSON.stringify({ type: "AUTH_FAILED", payload: { message: "Authentication failed: Invalid or unapproved token." } }));
              console.log(`Authentication failed for token: ${payload.authToken}`);
            }
          } catch (error: any) {
            ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Authentication error: ${error.message}` } }));
          }
          break;

        // Placeholder for other message types (e.g., REQUEST_SECRET) - will be handled in next step
        // For now, if not authenticated, reject other types.
        default:
          if (!ws.isAuthenticated || !ws.clientInfo) {
            ws.send(JSON.stringify({ type: "ERROR", payload: { message: "Client not authenticated. Please register or authenticate before sending other commands." } }));
            return; // Important to return to prevent further processing for unauthenticated users
          }

          // Handle messages for authenticated clients
          switch(type) {
            case 'REQUEST_SECRET':
              try {
                if (!payload || !payload.secretKey) {
                  throw new Error("secretKey is required for REQUEST_SECRET.");
                }
                const secretKey = payload.secretKey;
                if (ws.clientInfo.associatedSecretKeys.includes(secretKey)) {
                  const secretValue = DataManager.getSecretItem(secretKey);
                  if (secretValue !== undefined) {
                    ws.send(JSON.stringify({
                      type: "SECRET_RESPONSE",
                      payload: { secretKey, value: secretValue }
                    }));
                  } else {
                    // Should not happen if associatedSecretKeys is in sync with actual secrets
                    console.error(`Client ${ws.clientInfo.name} authorized for non-existent secret ${secretKey}`);
                    ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Secret key "${secretKey}" not found on server, though authorized.` } }));
                  }
                } else {
                  ws.send(JSON.stringify({
                    type: "UNAUTHORIZED_SECRET_ACCESS",
                    payload: { secretKey, message: "You are not authorized to access this secret." }
                  }));
                }
              } catch (error: any) {
                ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Error requesting secret: ${error.message}` } }));
              }
              break;

            case 'LIST_AUTHORIZED_SECRETS':
              try {
                ws.send(JSON.stringify({
                  type: "AUTHORIZED_SECRETS_LIST",
                  payload: { authorizedSecretKeys: ws.clientInfo.associatedSecretKeys }
                }));
              } catch (error: any) {
                 ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Error listing authorized secrets: ${error.message}` } }));
              }
              break;

            default:
              console.log(`Authenticated client ${ws.clientInfo?.name} sent unhandled message type: ${type}`);
              ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Unknown message type: ${type}` } }));
              break;
          }
          break;
      }
    });

    ws.on('close', () => {
      console.log(`Client ${ws.clientInfo ? ws.clientInfo.name + ' (' + ws.clientInfo.id + ')' : 'Unknown'} disconnected from WebSocket server`);
    });

    ws.on('error', (error) => {
      console.error(`WebSocket error for client ${ws.clientInfo ? ws.clientInfo.name : 'Unknown'}:`, error);
    });

    ws.send(JSON.stringify({ type: "WELCOME", payload: { message: "Welcome to the WebSocket server! Please register or authenticate." } }));
  });

  console.log(`WebSocket server started on ws://localhost:${port}`);
  return wss;
}
