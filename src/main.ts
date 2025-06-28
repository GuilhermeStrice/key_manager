// Main application entry point
import readline from 'readline';
import { initializeDataManager } from './lib/dataManager';
import { startHttpServer } from './http/httpServer';
import { startWebSocketServer } from './websocket/wsServer';
import dotenv from 'dotenv';
import { getConfig } from './lib/configManager';

// Load environment variables from .env file (e.g., for MASTER_PASSWORD)
dotenv.config();

// Configuration will be loaded by configManager and accessed via getConfig()
// const HTTP_PORT = parseInt(process.env.HTTP_PORT || '3000', 10); // Now from config
// const WS_PORT = parseInt(process.env.WS_PORT || '3001', 10); // Now from config

// Store servers for graceful shutdown
let httpServerInstance: ReturnType<typeof startHttpServer> | null = null;
let wsServerInstance: ReturnType<typeof startWebSocketServer> | null = null;


async function getPassword(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (process.env.MASTER_PASSWORD) {
        console.log("Using MASTER_PASSWORD from environment variable.");
        resolve(process.env.MASTER_PASSWORD);
        return;
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    // Handle Ctrl+C during password prompt gracefully
    rl.on('SIGINT', () => {
        console.log('\nPassword input cancelled. Exiting.');
        rl.close();
        process.exit(0);
    });

    rl.question('Enter the master password for the server: ', (password) => {
      rl.close();
      if (!password) {
        // If running in a non-interactive environment and password is required but not provided via env.
        // This specific check might be more relevant if stdin is not a TTY.
        // For now, an empty password here would just proceed.
        // A more robust check for actual empty input vs. just pressing enter might be needed.
        console.warn("Warning: Empty password entered.");
      }
      resolve(password);
    });
  });
}

async function startServer() {
  console.log('Starting Key/Info Manager Server...');
  const password = await getPassword();

  if (!password && !process.env.MASTER_PASSWORD) {
      console.error('ERROR: Master password is required to start the server.');
      console.error('Please provide it when prompted or set the MASTER_PASSWORD environment variable.');
      process.exit(1);
      return; // Ensure function exits if process.exit doesn't immediately terminate in all contexts
  }

  console.log('Initializing data manager...');
  try {
    await initializeDataManager(password);
    console.log('Data manager initialized successfully.');
  } catch (error) {
    console.error('Failed to initialize data manager:', error);
    console.error('This could be due to an incorrect password or corrupted data file.');
    process.exit(1);
    return;
  }

  const config = getConfig(); // Load configuration

  console.log(`Attempting to start HTTP server on port ${config.httpPort}...`);
  httpServerInstance = startHttpServer(config.httpPort, password);

  console.log(`Attempting to start WebSocket server on port ${config.wsPort}...`);
  wsServerInstance = startWebSocketServer(config.wsPort);

  console.log('Server started successfully.');
  console.log(`Admin UI accessible via HTTP server (e.g., http://localhost:${config.httpPort}/admin)`);
  console.log(`WebSocket connections on ws://localhost:${config.wsPort}`);
}

function gracefulShutdown(signal: string) {
    console.log(`\nReceived ${signal}. Shutting down gracefully...`);

    // Close WebSocket server connections
    if (wsServerInstance) {
        console.log('Closing WebSocket server...');
        wsServerInstance.clients.forEach(client => client.close());
        wsServerInstance.close((err) => {
            if (err) {
                console.error('Error closing WebSocket server:', err);
            } else {
                console.log('WebSocket server closed.');
            }
        });
    }

    // Close HTTP server
    // Note: Express app itself doesn't have a direct 'close' method.
    // The app.listen() returns a Node.js http.Server instance, which does.
    // We need to ensure startHttpServer returns the actual server instance if we want to close it.
    // For now, the current startHttpServer returns `app`, not the server instance.
    // This will be improved if startHttpServer is modified to return the http.Server.
    // As a simple measure, just logging. For true graceful HTTP shutdown, more work is needed.
    if (httpServerInstance && typeof httpServerInstance.close === 'function') {
        console.log('Closing HTTP server...');
        httpServerInstance.close((err?: Error) => {
            if (err) {
                console.error('Error closing HTTP server:', err);
            } else {
                console.log('HTTP server closed.');
            }
            // Consider waiting for all servers to close before exiting
            // This might require more complex promise handling if multiple async closes
            // For now, exiting after attempting to close WebSocket server.
        });
    } else if (httpServerInstance) {
        console.log('HTTP server instance does not have a close method or is not the expected type.');
    }


    // Perform any other cleanup tasks here (e.g., saving data if not done automatically)
    // For DataManager, saves are typically per-operation, but a final save could be added.

    console.log('Exiting now.');
    process.exit(0);
}

// Listen for termination signals
process.on('SIGINT', () => gracefulShutdown('SIGINT')); // Ctrl+C
process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // kill command

if (require.main === module) {
  startServer().catch(error => {
    console.error('FATAL: Failed to start server:', error);
    process.exit(1);
  });
}
