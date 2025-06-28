const wsUrlInput = document.getElementById('wsUrl');
const connectBtn = document.getElementById('connectBtn');
const disconnectBtn = document.getElementById('disconnectBtn');
const messagesDiv = document.getElementById('messages');

const registerBtn = document.getElementById('registerBtn');
const clientNameInput = document.getElementById('clientNameInput');
const authenticateBtn = document.getElementById('authenticateBtn');
const authTokenInput = document.getElementById('authTokenInput');
const requestSecretBtn = document.getElementById('requestSecretBtn');
const secretKeyInput = document.getElementById('secretKeyInput');
const listSecretsBtn = document.getElementById('listSecretsBtn');
const customMessageInput = document.getElementById('customMessageInput');
const sendCustomBtn = document.getElementById('sendCustomBtn');

const clientIdSpan = document.getElementById('clientIdSpan');
const tempIdSpan = document.getElementById('tempIdSpan');
const clientStatusSpan = document.getElementById('clientStatusSpan');


// WebSocket Message Type Integer Codes (mirrored from server)
// Client-to-Server:
const MSG_TYPE_REGISTER_CLIENT = 1;
const MSG_TYPE_AUTHENTICATE = 2;
const MSG_TYPE_REQUEST_SECRET = 3;
const MSG_TYPE_LIST_AUTHORIZED_SECRETS = 4;
// Server-to-Client:
const MSG_TYPE_WELCOME = 100;
const MSG_TYPE_REGISTRATION_PENDING = 101;
const MSG_TYPE_AUTHENTICATED = 102;
const MSG_TYPE_AUTH_FAILED = 103;
const MSG_TYPE_SECRET_RESPONSE = 104;
const MSG_TYPE_UNAUTHORIZED_SECRET_ACCESS = 105;
const MSG_TYPE_AUTHORIZED_SECRETS_LIST = 106;
const MSG_TYPE_ERROR = 200;


let socket = null;
let clientId = null; // Server-assigned client ID (for admin tracking)
let temporaryId = null; // Server-assigned temporary ID (while pending)
// Auth token will be taken from authTokenInput.value when needed

function updateClientStateDisplay() {
    clientIdSpan.textContent = clientId || 'N/A';
    tempIdSpan.textContent = temporaryId || 'N/A';
    // authTokenInput value is the source of truth for sending
}

function logMessage(message, type = 'info') {
    const p = document.createElement('p');
    p.textContent = message;
    p.className = `message ${type}`;
    messagesDiv.appendChild(p);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

connectBtn.addEventListener('click', () => {
    if (socket) {
        logMessage('Already connected or connecting.', 'error');
        return;
    }
    const url = wsUrlInput.value;
    logMessage(`Attempting to connect to ${url}...`);
    socket = new WebSocket(url);

    socket.onopen = () => {
        logMessage('Connected to WebSocket server.', 'server');
        clientStatusSpan.textContent = 'Connected (Not Authenticated)';
        connectBtn.disabled = true;
        disconnectBtn.disabled = false;
        registerBtn.disabled = false;
        authenticateBtn.disabled = false;
        // requestSecretBtn, listSecretsBtn, sendCustomBtn remain disabled until authenticated
        sendCustomBtn.disabled = false; // Allow sending custom messages once connected
    };

    socket.onmessage = (event) => {
        try {
            const serverMessage = JSON.parse(event.data);
            logMessage(`Server: ${JSON.stringify(serverMessage, null, 2)}`, 'server');

            // Handle different message types from server
            switch(serverMessage.type) { // serverMessage.type is now an integer
                case MSG_TYPE_WELCOME: // 100
                    // Already logged by the generic logMessage above or specific welcome message from server
                    break;
                case MSG_TYPE_REGISTRATION_PENDING: // 101
                    clientId = serverMessage.payload.clientId;
                    temporaryId = serverMessage.payload.temporaryId;
                    clientStatusSpan.textContent = 'Registration Pending Approval';
                    updateClientStateDisplay();
                    logMessage(`IMPORTANT: Your Client ID for admin tracking is ${clientId}. Your temporary ID is ${temporaryId}. Store your permanent Auth Token from admin once approved.`, 'info');
                    break;
                case MSG_TYPE_AUTHENTICATED: // 102
                    clientStatusSpan.textContent = `Authenticated as ${serverMessage.payload.name} (${serverMessage.payload.clientId})`;
                    requestSecretBtn.disabled = false;
                    listSecretsBtn.disabled = false;
                    logMessage(`Associated secrets: ${serverMessage.payload.associatedSecretKeys.join(', ')}`, 'info');
                    break;
                case MSG_TYPE_AUTH_FAILED: // 103
                    clientStatusSpan.textContent = 'Authentication Failed';
                    authTokenInput.value = '';
                    requestSecretBtn.disabled = true;
                    listSecretsBtn.disabled = true;
                    break;
                case MSG_TYPE_SECRET_RESPONSE: // 104
                    logMessage(`Secret "${serverMessage.payload.secretKey}": ${JSON.stringify(serverMessage.payload.value)}`, 'info');
                    break;
                case MSG_TYPE_AUTHORIZED_SECRETS_LIST: // 106
                    logMessage(`You are authorized to access: ${serverMessage.payload.authorizedSecretKeys.join(', ')}`, 'info');
                    break;
                case MSG_TYPE_UNAUTHORIZED_SECRET_ACCESS: // 105
                    logMessage(`Access denied for secret: ${serverMessage.payload.secretKey}`, 'error');
                    break;
                case MSG_TYPE_ERROR: // 200
                    logMessage(`Server Error: ${serverMessage.payload.message}`, 'error');
                    break;
                default:
                    logMessage(`Unknown message type code from server: ${serverMessage.type}`, 'error');
            }
        } catch (e) {
            logMessage(`Received non-JSON message from server: ${event.data}`, 'error');
        }
    };

    socket.onclose = (event) => {
        logMessage(`Disconnected from WebSocket server. Code: ${event.code}, Reason: ${event.reason || 'N/A'}`, 'error');
        clientStatusSpan.textContent = 'Disconnected';
        socket = null;
        connectBtn.disabled = false;
        disconnectBtn.disabled = true;
        registerBtn.disabled = true;
        authenticateBtn.disabled = true;
        requestSecretBtn.disabled = true;
        listSecretsBtn.disabled = true;
        sendCustomBtn.disabled = true;
        clientId = null;
        temporaryId = null;
        updateClientStateDisplay();
    };

    socket.onerror = (error) => {
        logMessage('WebSocket error. See console for details.', 'error');
        console.error('WebSocket error:', error);
        // Note: onclose will usually be called after onerror.
    };
});

disconnectBtn.addEventListener('click', () => {
    if (socket) {
        logMessage('Disconnecting...');
        socket.close();
    }
});

function sendWebSocketMessage(messageObject) {
    if (socket && socket.readyState === WebSocket.OPEN) {
        const messageString = JSON.stringify(messageObject);
        logMessage(`Client: ${messageString}`, 'client');
        socket.send(messageString);
    } else {
        logMessage('Not connected. Cannot send message.', 'error');
    }
}

registerBtn.addEventListener('click', () => {
    const clientName = clientNameInput.value.trim();
    if (!clientName) {
        logMessage('Please enter a client name for registration.', 'error');
        return;
    }
    sendWebSocketMessage({
        type: MSG_TYPE_REGISTER_CLIENT, // 1
        payload: { clientName: clientName }
    });
});

authenticateBtn.addEventListener('click', () => {
    const authToken = authTokenInput.value.trim();
    if (!authToken) {
        logMessage('Please enter an auth token to authenticate.', 'error');
        return;
    }
    sendWebSocketMessage({
        type: MSG_TYPE_AUTHENTICATE, // 2
        payload: { authToken: authToken }
    });
});

requestSecretBtn.addEventListener('click', () => {
    const secretKey = secretKeyInput.value.trim();
    if (!secretKey) {
        logMessage('Please enter a secret key to request.', 'error');
        return;
    }
    sendWebSocketMessage({
        type: MSG_TYPE_REQUEST_SECRET, // 3
        payload: { secretKey: secretKey }
    });
});

listSecretsBtn.addEventListener('click', () => {
    sendWebSocketMessage({
        type: MSG_TYPE_LIST_AUTHORIZED_SECRETS // 4
    });
});

sendCustomBtn.addEventListener('click', () => {
    try {
        const customJson = JSON.parse(customMessageInput.value);
        sendWebSocketMessage(customJson);
    } catch (e) {
        logMessage('Invalid JSON in custom message input.', 'error');
    }
});
