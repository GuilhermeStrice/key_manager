// WebSocket server logic
import WebSocket, { WebSocketServer } from 'ws'; // Import WebSocketServer as well
import * as DataManager from '../lib/dataManager';

// Extend WebSocket instance type to hold authentication state
interface AuthenticatedWebSocket extends WebSocket {
  isAuthenticated?: boolean;
  clientInfo?: DataManager.ClientInfo;
}

// WebSocket Message Type Integer Codes
// Client-to-Server:
// 1: REGISTER_CLIENT
// 2: AUTHENTICATE
// 3: REQUEST_SECRET
// 4: LIST_AUTHORIZED_SECRETS
//
// Server-to-Client:
// 100: WELCOME
// 101: REGISTRATION_PENDING
// 102: AUTHENTICATED
// 103: AUTH_FAILED
// 104: SECRET_RESPONSE
// 105: UNAUTHORIZED_SECRET_ACCESS
// 106: AUTHORIZED_SECRETS_LIST
// 200: ERROR

export function startWebSocketServer(port: number) {
  const wss = new WebSocketServer({ port }); // Use WebSocketServer for server creation

  wss.on('connection', (ws: AuthenticatedWebSocket) => {
    console.log('Client connected to WebSocket server');
    ws.isAuthenticated = false;

    ws.on('message', async (messageData: WebSocket.RawData, isBinary: boolean) => { // Add types for messageData and isBinary
      let parsedMessage;
      try {
        // Ensure messageData is a string before parsing
        const messageString = messageData.toString();
        parsedMessage = JSON.parse(messageString);
        console.log('Received from client:', parsedMessage);
      } catch (error) {
        console.error('Failed to parse message or message not JSON:', messageData.toString());
        ws.send(JSON.stringify({ type: 200, payload: { message: "Invalid message format. Expected JSON." } })); // ERROR code
        return;
      }

      const { type, payload } = parsedMessage; // type is now expected to be an integer

      switch (type) {
        case 1: // REGISTER_CLIENT
          console.log('[WebSocket] Attempting to register client (type 1). Payload:', payload);
          try {
            if (!payload || !payload.clientName) {
              throw new Error("clientName is required for registration.");
            }
            // Add to DataManager as pending
            const newClient = await DataManager.addPendingClient(payload.clientName, payload.requestedSecretKeys);
            console.log('[WebSocket] Client registration pending in DataManager. Client Temp ID:', newClient.temporaryId);
            ws.send(JSON.stringify({
              type: 101, // REGISTRATION_PENDING
              payload: {
                clientId: newClient.id, // This is the server-side ID for admin tracking
                temporaryId: newClient.temporaryId, // Client should hold onto this if needed for status checks (not implemented yet)
                message: `Registration for "${newClient.name}" is pending approval. Your client ID is ${newClient.id}.`
              }
            }));
          } catch (error: any) {
            console.error('[WebSocket] Error during client registration:', error);
            ws.send(JSON.stringify({ type: 200, payload: { message: `Registration failed: ${error.message}` } })); // ERROR code
          }
          break;

        case 2: // AUTHENTICATE
          try {
            if (!payload || !payload.authToken) {
                throw new Error("authToken is required for authentication.");
            }
            const clientInfo = DataManager.getClientByAuthToken(payload.authToken);
            if (clientInfo && clientInfo.status === 'approved') {
              ws.isAuthenticated = true;
              ws.clientInfo = clientInfo;
              ws.send(JSON.stringify({
                type: 102, // AUTHENTICATED
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
              ws.send(JSON.stringify({ type: 103, payload: { message: "Authentication failed: Invalid or unapproved token." } })); // AUTH_FAILED
              console.log(`Authentication failed for token: ${payload.authToken}`);
            }
          } catch (error: any) {
            ws.send(JSON.stringify({ type: 200, payload: { message: `Authentication error: ${error.message}` } })); // ERROR code
          }
          break;

        // Default case for main switch handles unauthenticated access for other types
        default:
          if (!ws.isAuthenticated || !ws.clientInfo) {
            ws.send(JSON.stringify({ type: 200, payload: { message: "Client not authenticated. Please register or authenticate before sending other commands." } })); // ERROR code
            return;
          }

          // Handle messages for authenticated clients (nested switch)
          switch(type) {
            case 3: // REQUEST_SECRET
              try {
                if (!payload || !payload.secretKey) {
                  throw new Error("secretKey is required for REQUEST_SECRET.");
                }
                const secretKey = payload.secretKey;
                if (ws.clientInfo.associatedSecretKeys.includes(secretKey)) {
                  const secretValue = DataManager.getSecretItem(secretKey);
                  if (secretValue !== undefined) {
                    ws.send(JSON.stringify({
                      type: 104, // SECRET_RESPONSE
                      payload: { secretKey, value: secretValue }
                    }));
                  } else {
                    console.error(`Client ${ws.clientInfo.name} authorized for non-existent secret ${secretKey}`);
                    ws.send(JSON.stringify({ type: 200, payload: { message: `Secret key "${secretKey}" not found on server, though authorized.` } })); // ERROR code
                  }
                } else {
                  ws.send(JSON.stringify({
                    type: 105, // UNAUTHORIZED_SECRET_ACCESS
                    payload: { secretKey, message: "You are not authorized to access this secret." }
                  }));
                }
              } catch (error: any) {
                ws.send(JSON.stringify({ type: 200, payload: { message: `Error requesting secret: ${error.message}` } })); // ERROR code
              }
              break;

            case 4: // LIST_AUTHORIZED_SECRETS
              try {
                ws.send(JSON.stringify({
                  type: 106, // AUTHORIZED_SECRETS_LIST
                  payload: { authorizedSecretKeys: ws.clientInfo.associatedSecretKeys }
                }));
              } catch (error: any) {
                 ws.send(JSON.stringify({ type: 200, payload: { message: `Error listing authorized secrets: ${error.message}` } })); // ERROR code
              }
              break;

            default: // Handles unknown types for authenticated clients
              console.log(`Authenticated client ${ws.clientInfo?.name} sent unhandled message type code: ${type}`);
              ws.send(JSON.stringify({ type: 200, payload: { message: `Unknown message type code: ${type}` } })); // ERROR code
              break;
          }
          break; // Break for the outer switch's default case
      }
    });

    ws.on('close', () => {
      console.log(`Client ${ws.clientInfo ? ws.clientInfo.name + ' (' + ws.clientInfo.id + ')' : 'Unknown'} disconnected from WebSocket server`);
    });

    ws.on('error', (error: Error) => { // Add Error type for error
      console.error(`WebSocket error for client ${ws.clientInfo ? ws.clientInfo.name : 'Unknown'}:`, error);
    });

    ws.send(JSON.stringify({ type: 100, payload: { message: "Welcome to the WebSocket server! Please register or authenticate." } })); // WELCOME code
  });

  console.log(`WebSocket server started on ws://localhost:${port}`);
  return wss;
}
