// WebSocket server logic
import WebSocket from 'ws';
import * as DataManager from '../lib/dataManager';

// Extend WebSocket instance type to hold authentication state
interface AuthenticatedWebSocket extends WebSocket {
  // isAuthenticated is now effectively controlled by acceptAllWebSocketConnections
  // clientInfo might not be relevant if not uniquely identifying for auth.
  // For now, we'll keep it to store basic info if registered.
  clientRegisteredName?: string; // Store the name given during REGISTER_CLIENT
  clientServerId?: string; // Store the server-assigned ID
}

// Global toggle for WebSocket connections
// TODO: Make this configurable (e.g., via admin UI or env variable)
let acceptAllWebSocketConnections: boolean = true; // Default to true for now

export function startWebSocketServer(port: number, initialConnectionMode?: 'accept' | 'reject') {
  if (initialConnectionMode === 'reject') {
    acceptAllWebSocketConnections = false;
  } else {
    acceptAllWebSocketConnections = true; // Default or 'accept'
  }
  console.log(`WebSocket server starting. Global connection policy: ${acceptAllWebSocketConnections ? 'ACCEPT ALL' : 'REJECT ALL'}`);

  const wss = new WebSocket.Server({ port });

  wss.on('connection', (ws: AuthenticatedWebSocket) => {
    console.log('Client attempting to connect to WebSocket server...');

    if (!acceptAllWebSocketConnections) {
      console.log('Global policy is REJECT ALL. Terminating connection.');
      ws.send(JSON.stringify({ type: "CONNECTION_REJECTED_POLICY", payload: { message: "Server is not accepting new WebSocket connections at this time." } }));
      ws.terminate();
      return;
    }

    console.log('Client connected (globally accepted).');
    // ws.isAuthenticated = false; // No longer using token-based isAuthenticated flag per connection in the same way

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
                // temporaryId: newClient.temporaryId, // temporaryId removed from ClientInfo
                message: `Registration for "${newClient.name}" is recorded. Your client ID is ${newClient.id}. Server is in global accept mode.`
              }
            }));
            // Store client name and server ID on the WebSocket connection object
            ws.clientRegisteredName = newClient.name;
            ws.clientServerId = newClient.id;
          } catch (error: any) {
            ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Registration failed: ${error.message}` } }));
          }
          break;

        // case 'AUTHENTICATE': // AUTHENTICATE message type is removed
        //   // This entire case is no longer needed as authentication is global
        //   break;

        default:
          // If globally accepted, all connected clients are considered "authenticated" to interact.
          // The old check `if (!ws.isAuthenticated || !ws.clientInfo)` is no longer directly applicable in the same way.
          // We can check if the client has at least registered a name.
          if (!ws.clientRegisteredName) {
             ws.send(JSON.stringify({ type: "ERROR", payload: { message: "Client has not registered. Please send a REGISTER_CLIENT message first." } }));
             return;
          }

          console.log(`Processing message type "${type}" for registered client: ${ws.clientRegisteredName} (${ws.clientServerId})`);

          // Handle messages for "authenticated" (i.e., globally accepted and registered) clients
          switch(type) {
            case 'REQUEST_SECRET':
              try {
                if (!payload || !payload.secretKey) {
                  throw new Error("secretKey is required for REQUEST_SECRET.");
                }
                const secretKey = payload.secretKey;
                // TODO: Re-evaluate secret access logic.
                // For now, if globally accepted, assume access to all requested secrets.
                // This part needs to align with the new auth model:
                // Does "global accept" mean access to ALL secrets for any connected client?
                // Or should clients still declare what they need and admin associates them?
                // For simplicity of this step, let's assume any registered client in global accept mode can request any secret.
                // This is a placeholder and likely needs refinement for security.
                const clientData = DataManager.getClient(ws.clientServerId!); // Get client data to check their *requested* keys
                                                                              // or associated keys if admin still manages that.
                                                                              // For now, let's simplify and allow any secret.

                const secretValue = DataManager.getSecretItem(secretKey);
                if (secretValue !== undefined) {
                  ws.send(JSON.stringify({
                    type: "SECRET_RESPONSE",
                    payload: { secretKey, value: secretValue }
                  }));
                } else {
                  ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Secret key "${secretKey}" not found on server.` } }));
                }
              } catch (error: any) {
                ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Error requesting secret: ${error.message}` } }));
              }
              break;

            case 'LIST_AUTHORIZED_SECRETS':
              try {
                // TODO: Re-evaluate this. If globally accepted, what does "authorized" mean?
                // For now, let's list all available secret keys on the server.
                // This is a placeholder and needs security review.
                const allSecretKeys = DataManager.getAllSecretKeys();
                ws.send(JSON.stringify({
                  type: "AVAILABLE_SECRETS_LIST", // Changed from AUTHORIZED_SECRETS_LIST
                  payload: { availableSecretKeys: allSecretKeys }
                }));
              } catch (error: any) {
                 ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Error listing available secrets: ${error.message}` } }));
              }
              break;

            default:
              console.log(`Client ${ws.clientRegisteredName} (${ws.clientServerId}) sent unhandled message type: ${type}`);
              ws.send(JSON.stringify({ type: "ERROR", payload: { message: `Unknown message type: ${type}` } }));
              break;
          }
          break;
      }
    });

    ws.on('close', () => {
      console.log(`Client ${ws.clientRegisteredName || 'Unknown'} (${ws.clientServerId || 'N/A'}) disconnected from WebSocket server`);
    });

    ws.on('error', (error) => {
      console.error(`WebSocket error for client ${ws.clientRegisteredName || 'Unknown'}:`, error);
    });

    // Updated welcome message
    ws.send(JSON.stringify({ type: "WELCOME", payload: { message: "Welcome to the WebSocket server! Connections are globally managed. Please register your client name." } }));
  });

  console.log(`WebSocket server started on ws://localhost:${port}`);
  return wss;
}
