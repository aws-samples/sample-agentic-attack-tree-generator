/**
 * Server entrypoint — TS analog of running `uvicorn server.app:app`.
 *
 * Creates the Express app, wraps it in an http.Server, attaches the WebSocket
 * progress handler to the same server (so `/ws/runs/:id` shares the port with
 * the `/api` REST surface), and listens on `PORT` (default 8000).
 *
 * Bind address: defaults to LOOPBACK. This server has no authentication, so
 * binding all interfaces exposes every threat model — and the ability to start
 * runs against arbitrary local paths — to anyone who can reach the host. Use
 * `--host 0.0.0.0` (or HOST=0.0.0.0) only deliberately.
 *
 * `HOST`/`PORT` are the names the CLI launcher sets (cli/src/server-launch.ts).
 * `TF_HOST`/`TF_PORT` are accepted as aliases: the server previously read ONLY
 * those, so the launcher's variables were ignored and the CLI's 127.0.0.1
 * default was dead code — every launch silently bound 0.0.0.0.
 */
import { createServer } from 'node:http';
import { createApp } from './app.js';
import { attachProgressWebSocket } from './ws.js';

const PORT = Number(process.env.PORT ?? process.env.TF_PORT ?? 8000);
const HOST = process.env.HOST ?? process.env.TF_HOST ?? '127.0.0.1';

/** Loopback addresses that keep the unauthenticated API off the network. */
function isLoopback(host: string): boolean {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

function main(): void {
  const app = createApp();
  const server = createServer(app);
  attachProgressWebSocket(server);

  server.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.log(`ThreatForest server listening on http://${HOST}:${PORT}`);
    if (!isLoopback(HOST)) {
      // eslint-disable-next-line no-console
      console.warn(
        `WARNING: bound to ${HOST} — this API has NO authentication. Anyone who can reach ` +
          'this host can read every threat model and start runs that read local files. ' +
          'Use 127.0.0.1 unless you have put your own auth in front of it.',
      );
    }
  });
}

main();
