/**
 * Server entrypoint — TS analog of running `uvicorn server.app:app`.
 *
 * Creates the Express app, wraps it in an http.Server, attaches the WebSocket
 * progress handler to the same server (so `/ws/runs/:id` shares the port with
 * the `/api` REST surface), and listens on `TF_PORT` (default 8000).
 */
import { createServer } from 'node:http';
import { createApp } from './app.js';
import { attachProgressWebSocket } from './ws.js';

const PORT = Number(process.env.TF_PORT ?? 8000);
const HOST = process.env.TF_HOST ?? '0.0.0.0';

function main(): void {
  const app = createApp();
  const server = createServer(app);
  attachProgressWebSocket(server);

  server.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.log(`ThreatForest server listening on http://${HOST}:${PORT}`);
  });
}

main();
