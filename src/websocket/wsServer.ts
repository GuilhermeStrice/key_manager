// WebSocket server logic
import WebSocket from 'ws';

export function startWebSocketServer(port: number) {
  const wss = new WebSocket.Server({ port });

  wss.on('connection', (ws) => {
    console.log('Client connected to WebSocket server');

    ws.on('message', (message) => {
      console.log('Received from client: %s', message);
      ws.send(`Echo: ${message}`);
    });

    ws.on('close', () => {
      console.log('Client disconnected from WebSocket server');
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    ws.send('Welcome to the WebSocket server!');
  });

  console.log(`WebSocket server started on ws://localhost:${port}`);
  return wss;
}
