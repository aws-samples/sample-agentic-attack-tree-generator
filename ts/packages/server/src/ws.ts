/**
 * WebSocket progress streaming — TS port of the `/ws/runs/{run_id}` endpoint in
 * `src/server/routes/runs.py`.
 *
 * Mounted at root (NO `/api` prefix) on path `/ws/runs/:id`. Drains the
 * RunManager's per-run progress queue and sends each event as JSON. After
 * `WS_HEARTBEAT_INTERVAL` seconds of silence a lightweight heartbeat keeps the
 * connection alive through idle-closing proxies/browsers. The socket closes
 * after a terminal event (completion/error/pause/stop), or with code 4004 if the
 * run_id is unknown. Reconnecting clients get the full event history replayed
 * first so late subscribers catch up.
 */
import type { IncomingMessage, Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { getRunManager, WS_HEARTBEAT_INTERVAL } from './routes/runs.js';
import type { ProgressEvent } from './run-manager.js';

// Terminal event types. The TS engine emits run_* names; the legacy Python
// server emitted error/scan_paused/scan_stopped/stage_complete — accept both so
// the close-on-terminal contract holds regardless of which the engine produces.
const TERMINAL_TYPES = new Set([
  'run_complete',
  'run_failed',
  'run_stopped',
  'run_paused',
  'error',
  'scan_paused',
  'scan_stopped',
]);

/** Is this the event that should close the socket? */
function isTerminal(event: ProgressEvent): boolean {
  const type = event.type ?? '';
  if (type === 'stage_complete') {
    return (event.stage ?? '') === 'complete';
  }
  return TERMINAL_TYPES.has(type);
}

/**
 * Path matcher for the progress WebSocket — returns the run id or null.
 *
 * Accepts both the frozen `/ws/runs/:id` contract and the `/ws/runs/:id/progress`
 * variant so existing and newer clients connect to the same handler.
 */
function matchRunPath(url: string | undefined): string | null {
  if (!url) return null;
  const pathname = url.split('?')[0] ?? '';
  const m = /^\/ws\/runs\/([^/]+)(?:\/progress)?\/?$/.exec(pathname);
  return m ? decodeURIComponent(m[1]!) : null;
}

/**
 * Attach the progress WebSocket handler to an existing HTTP server. Uses a
 * `noServer` WSS and handles the `upgrade` event so non-WS routes are untouched.
 */
export function attachProgressWebSocket(server: HttpServer): WebSocketServer {
  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (req: IncomingMessage, socket, head) => {
    const runId = matchRunPath(req.url);
    if (runId === null) {
      // Not our path — let other upgrade handlers (or the default) deal with it.
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      void handleConnection(ws, runId);
    });
  });

  return wss;
}

async function handleConnection(ws: WebSocket, runId: string): Promise<void> {
  const manager = getRunManager();

  // Subscribe FIRST so any event published between the history snapshot and the
  // live loop lands in this connection's private queue (no gap, no double-send
  // issue beyond at-most-one duplicate the client already dedupes by stage).
  let subscription: ReturnType<typeof manager.subscribeProgress> | null = null;
  try {
    subscription = manager.subscribeProgress(runId);
  } catch {
    // Broadcaster gone — the run is terminal; replay history then close.
    const history = manager.getHistory(runId);
    if (history.length === 0) {
      ws.close(4004, `Unknown run_id: ${runId}`);
      return;
    }
    for (const event of history) ws.send(JSON.stringify(event));
    ws.close(1000, 'Run is in terminal state');
    return;
  }

  const queue = subscription.queue;

  // Replay event history for reconnecting clients (so a late viewer sees the
  // stages already completed before it connected).
  const history = manager.getHistory(runId);
  for (const event of history) ws.send(JSON.stringify(event));

  // If already terminal, close cleanly with 1000 so the client doesn't reconnect.
  if (history.length > 0 && isTerminal(history[history.length - 1]!)) {
    subscription.unsubscribe();
    ws.close(1000, 'Run is in terminal state');
    return;
  }

  let closed = false;
  ws.on('close', () => {
    closed = true;
  });
  ws.on('error', () => {
    closed = true;
  });

  try {
    // Hold ONE pending `next()` across heartbeat windows. If we re-requested a
    // fresh `next()` after every heartbeat the abandoned promise would consume
    // (and drop) the next queued event — so the same pending promise is raced
    // against successive timeouts until it actually resolves.
    let pending: Promise<ProgressEvent> | null = null;
    while (!closed && ws.readyState === WebSocket.OPEN) {
      if (pending === null) pending = queue.next();
      const event = await raceWithTimeout(pending, WS_HEARTBEAT_INTERVAL * 1000);
      if (closed || ws.readyState !== WebSocket.OPEN) break;

      if (event === HEARTBEAT) {
        ws.send(JSON.stringify({ type: 'heartbeat', timestamp: Date.now() / 1000 }));
        continue; // keep awaiting the SAME pending promise
      }

      pending = null; // consumed — request a fresh one next iteration
      ws.send(JSON.stringify(event));
      if (isTerminal(event)) break;
    }
  } catch (err) {
    console.error(`WebSocket error for run ${runId}:`, (err as Error).message);
  } finally {
    // Detach THIS connection's queue. Other live subscribers (and reconnects)
    // keep streaming — the broadcaster is only dropped by cleanupRun once the
    // run is terminal, so a closed tab mid-run no longer starves the rest.
    subscription.unsubscribe();
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, 'Run is in terminal state');
    }
    manager.cleanupRun(runId);
  }
}

/** Sentinel returned when the heartbeat window elapses before an event arrives. */
const HEARTBEAT = Symbol('heartbeat');

/**
 * Resolve with the queue event, or the HEARTBEAT sentinel if `ms` elapse first.
 * The losing promise is abandoned (the queue's pending resolver stays armed and
 * delivers on the next loop iteration), matching the Python `asyncio.wait_for`
 * + retry-the-get behaviour.
 */
function raceWithTimeout<T>(p: Promise<T>, ms: number): Promise<T | typeof HEARTBEAT> {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve(HEARTBEAT);
    }, ms);
    void p.then((value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    });
  });
}
