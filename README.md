# Key/Info Manager

A secure Key/Info Management system with a WebSocket interface for client applications and an HTTP admin panel for management. Data is stored encrypted at rest.

## Features

*   **Secure Storage**: Secrets are encrypted using AES-256-GCM. The master encryption key is derived from a password provided at server startup.
*   **Admin UI**: Web-based interface for:
    *   Managing secrets (CRUD operations).
    *   Managing client applications:
        *   Viewing pending client registrations.
        *   Approving or rejecting clients.
        *   Generating authentication tokens for approved clients.
        *   Associating secrets with approved clients to grant access.
        *   Revoking client access.
*   **WebSocket API**: For client applications to:
    *   Register themselves with the server.
    *   Authenticate using a pre-approved token.
    *   Request authorized secrets.
    *   List secret keys they are authorized to access.
*   **Password Protection**: Admin UI and server startup require a master password.

## Prerequisites

*   Node.js (v16 or later recommended)
*   npm (usually comes with Node.js)

## Setup and Installation

1.  **Clone the repository (if applicable) or download the files.**
2.  **Install dependencies:**
    ```bash
    npm install
    ```
3.  **Build TypeScript:**
    ```bash
    npm run build
    ```

## Running the Server

1.  **Start the server:**
    ```bash
    npm start
    ```
    Alternatively, for development with auto-rebuild and restart on changes:
    ```bash
    npm run dev
    ```
2.  **Master Password**:
    *   On first startup, or if the `MASTER_PASSWORD` environment variable is not set, the server will prompt you to enter a master password in the console. This password is used to derive the key that encrypts your data file. **Choose a strong password and remember it.** If you lose it, your encrypted data will be inaccessible.
    *   A salt for the master key will be generated and stored in `data/masterkey.salt`. This file should be backed up but is not as critical as the password itself.
    *   The encrypted data is stored in `data/secrets.json.enc`. **This file contains your sensitive data and should be protected and backed up.**

## Environment Variables

You can configure the server using a `.env` file in the project root or by setting system environment variables.

*   `MASTER_PASSWORD`: If set, this password will be used directly, bypassing the console prompt. Useful for automated deployments.
*   `HTTP_PORT`: Port for the HTTP admin server (default: `3000`).
*   `WS_PORT`: Port for the WebSocket server (default: `3001`).
*   `HTTP_ADMIN_RATE_LIMIT_WINDOW_MS`: Time window in milliseconds for general admin API rate limiting (default: `900000`, 15 minutes).
*   `HTTP_ADMIN_RATE_LIMIT_MAX`: Max requests per IP for general admin API in the window (default: `100`).
*   `HTTP_LOGIN_RATE_LIMIT_WINDOW_MS`: Time window in milliseconds for admin login attempt rate limiting (default: `3600000`, 1 hour).
*   `HTTP_LOGIN_RATE_LIMIT_MAX`: Max login attempts per IP in the window (default: `5`).
*   `WS_RATE_LIMIT_WINDOW_MS`: Time window in milliseconds for general WebSocket message rate limiting (default: `60000`, 1 minute).
*   `WS_MAX_MESSAGES_PER_WINDOW`: Max WebSocket messages per client in the window (default: `100`).
*   `WS_REGISTER_RATE_LIMIT_WINDOW_MS`: Time window in milliseconds for WebSocket registration attempts per IP (default: `3600000`, 1 hour).
*   `WS_MAX_REGISTRATIONS_PER_WINDOW`: Max WebSocket registration attempts per IP in the window (default: `10`).


Example `.env` file:
```
HTTP_PORT=3005
WS_PORT=3006
# MASTER_PASSWORD=yourSuperStrongPasswordHere (Use with caution, especially in shared environments)

# Optional Rate Limiting Configuration Examples
# HTTP_ADMIN_RATE_LIMIT_WINDOW_MS=900000
# HTTP_ADMIN_RATE_LIMIT_MAX=100
# HTTP_LOGIN_RATE_LIMIT_WINDOW_MS=3600000
# HTTP_LOGIN_RATE_LIMIT_MAX=5
# WS_RATE_LIMIT_WINDOW_MS=60000
# WS_MAX_MESSAGES_PER_WINDOW=100
# WS_REGISTER_RATE_LIMIT_WINDOW_MS=3600000
# WS_MAX_REGISTRATIONS_PER_WINDOW=10
```

## Admin UI

Access the Admin UI by navigating to `http://localhost:<HTTP_PORT>/admin` (e.g., `http://localhost:3000/admin`) in your web browser.
You will be prompted to log in using the same master password you set/entered when starting the server.

### Features:

*   **Manage Secrets**:
    *   View, add, edit, and delete secrets (key-value pairs).
    *   Values can be simple strings or JSON objects/arrays.
*   **Manage Clients**:
    *   Navigate to the "Manage Clients" tab.
    *   **Pending Clients**: View clients that have registered via the WebSocket API but are awaiting approval.
        *   **Approve**: Approves the client and generates an authentication token for them. The token will be briefly displayed. **This token must be securely communicated to the client application.**
        *   **Reject**: Rejects the client's registration request.
    *   **Approved Clients**: View clients that have been approved.
        *   **Auth Token**: Shows the client's ID. The actual auth token is sensitive and usually only shown once upon generation or needs a secure way to be re-issued/viewed by an admin.
        *   **Manage Secrets**: For each approved client, you can manage which specific secrets they are authorized to access.
        *   **Revoke**: Deletes the client and revokes their access and authentication token.

## WebSocket API

Client applications connect to `ws://localhost:<WS_PORT>` (e.g., `ws://localhost:3001`). All messages are exchanged in JSON format: `{ "type": "MESSAGE_TYPE", "payload": { ... } }`.

### Message Types:

1.  **Client to Server: Register Client**
    *   Purpose: For a new client application to register itself.
    *   Message:
        ```json
        {
          "type": "REGISTER_CLIENT",
          "payload": {
            "clientName": "My Awesome Application",
            "requestedSecretKeys": ["optional_key1", "optional_key2"] // Optional
          }
        }
        ```
    *   Server Response (`REGISTRATION_PENDING`):
        ```json
        {
          "type": "REGISTRATION_PENDING",
          "payload": {
            "clientId": "server_generated_client_id", // For admin tracking
            "temporaryId": "server_generated_temp_id", // Client might hold this (currently informational)
            "message": "Registration for 'My Awesome Application' is pending approval..."
          }
        }
        ```
        The client needs to be approved in the Admin UI, and its `authToken` obtained from there.

2.  **Client to Server: Authenticate**
    *   Purpose: For an approved client to authenticate its WebSocket session.
    *   Message:
        ```json
        {
          "type": "AUTHENTICATE",
          "payload": {
            "authToken": "client_auth_token_from_admin"
          }
        }
        ```
    *   Server Response (`AUTHENTICATED` or `AUTH_FAILED`):
        *   Success:
            ```json
            {
              "type": "AUTHENTICATED",
              "payload": {
                "message": "Client 'Client Name' authenticated successfully.",
                "clientId": "client_id_on_server",
                "name": "Client Name",
                "associatedSecretKeys": ["key1", "key2"]
              }
            }
            ```
        *   Failure:
            ```json
            {
              "type": "AUTH_FAILED",
              "payload": { "message": "Authentication failed: Invalid or unapproved token." }
            }
            ```

3.  **Client to Server: Request Secret (Authenticated Clients Only)**
    *   Purpose: To request the value of an authorized secret.
    *   Message:
        ```json
        {
          "type": "REQUEST_SECRET",
          "payload": { "secretKey": "the_secret_key_to_fetch" }
        }
        ```
    *   Server Response (`SECRET_RESPONSE`, `UNAUTHORIZED_SECRET_ACCESS`, or `ERROR`):
        *   Success:
            ```json
            {
              "type": "SECRET_RESPONSE",
              "payload": {
                "secretKey": "the_secret_key_to_fetch",
                "value": "the_actual_secret_value"
              }
            }
            ```
        *   Unauthorized:
            ```json
            {
              "type": "UNAUTHORIZED_SECRET_ACCESS",
              "payload": {
                "secretKey": "the_secret_key_to_fetch",
                "message": "You are not authorized to access this secret."
              }
            }
            ```

4.  **Client to Server: List Authorized Secrets (Authenticated Clients Only)**
    *   Purpose: To get a list of secret keys the client is authorized to access.
    *   Message:
        ```json
        {
          "type": "LIST_AUTHORIZED_SECRETS"
        }
        ```
    *   Server Response (`AUTHORIZED_SECRETS_LIST`):
        ```json
        {
          "type": "AUTHORIZED_SECRETS_LIST",
          "payload": {
            "authorizedSecretKeys": ["key1", "key2", "another_key"]
          }
        }
        ```

### Server Welcome Message:
*   Upon connection, the server sends:
    ```json
    {
      "type": "WELCOME",
      "payload": { "message": "Welcome to the WebSocket server! Please register or authenticate." }
    }
    ```

### Error Messages:
*   Generic server errors or specific action errors are sent as:
    ```json
    {
      "type": "ERROR",
      "payload": { "message": "Descriptive error message here." }
    }
    ```

## Testing

Unit tests for the `DataManager` are available.
1.  **Run tests:**
    ```bash
    npm test
    ```
    Or for watch mode:
    ```bash
    npm run test:watch
    ```

Manual testing of the Admin UI and WebSocket API is recommended using the `client-example.html` page (open in a browser) and tools like Postman or `wscat` for WebSocket interaction.

## Security Considerations

*   **Master Password**: The security of all your encrypted data relies on the strength of your master password and its protection.
*   **Auth Tokens**: Client authentication tokens are bearer tokens. They should be treated as sensitive credentials and protected by the client applications. (Note: WebSocket authentication has moved to a sessionless, approval-based model).
*   **HTTPS/WSS**: For production deployments, always run the HTTP and WebSocket servers over HTTPS and WSS respectively to protect data in transit, including the master password during admin login. This setup does not include HTTPS/WSS by default.
*   **Data Directory**: The `data/` directory (containing `secrets.json.enc`, `masterkey.salt`, and `runtime-config.json`) should have restricted file permissions and be regularly backed up. It is ignored by git by default.
*   **Input Validation**: While basic validation is in place, thorough validation of all inputs (admin UI, WebSocket messages) is crucial for robust security.
*   **Rate Limiting/Brute-Force Protection**: Implemented for HTTP admin endpoints and WebSocket messages. These are configurable via environment variables (see Environment Variables section).
*   **Runtime Configuration**: Settings like the WebSocket auto-approval flag are stored in `data/runtime-config.json` and are persistent across server restarts.

## Project Structure

```
.
├── data/                  # Encrypted data, salt, and runtime config (gitignored)
│   ├── secrets.json.enc
│   ├── masterkey.salt
│   └── runtime-config.json
├── dist/                  # Compiled JavaScript output
├── node_modules/          # Dependencies (gitignored)
├── src/                   # TypeScript source files
│   ├── http/              # HTTP server (Express) and Admin UI logic
│   │   └── httpServer.ts
│   ├── lib/               # Core libraries
│   │   ├── configManager.ts # Runtime configuration management
│   │   ├── dataManager.ts   # Data storage, encryption/decryption logic
│   │   ├── dataManager.spec.ts # Unit tests for DataManager
│   │   └── encryption.ts    # Low-level encryption utilities
│   ├── types/             # Custom type definitions (if any)
│   ├── websocket/         # WebSocket server logic
│   │   └── wsServer.ts
│   └── main.ts            # Main application entry point
├── views/                 # EJS templates for Admin UI
│   ├── admin.ejs
│   └── clients.ejs
├── .env                   # Optional: for environment variables
├── .gitignore
├── client-example.html    # Basic HTML WebSocket client for testing
├── jest.config.js         # Jest configuration
├── package-lock.json
├── package.json
└── tsconfig.json
```
