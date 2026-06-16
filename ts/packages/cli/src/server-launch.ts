/**
 * Web-console launcher — TS analog of `launch_server()` in cli.py.
 *
 * The Python version runs `uvicorn server.app:app` and opens a browser. Here we
 * start `@threatforest/server` and open the browser. Because the server's HTTP
 * app is owned by WS-4 (and its public start API is still settling), we launch
 * it via its package `start` script in the workspace rather than importing an
 * internal entrypoint — this keeps the CLI decoupled from the server internals
 * and contract-faithful (the server reads HOST/PORT from the environment).
 *
 * The build_ui.py step (npm run build in console-ui/ + sync) has no analog in
 * the TS tree: the Next.js UI (WS-6) is a separate app the server serves, so the
 * CLI does not rebuild it. We just remind the user that the ML service must be
 * running, then hand off to the server process.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import pc from 'picocolors';
import * as display from './display.js';

/** Resolve the `ts/` workspace root from this module's location. */
function workspaceRoot(): string {
  // .../ts/packages/cli/dist/server-launch.js  ->  .../ts
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', '..', '..');
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
  try {
    spawn(cmd, [url], { stdio: 'ignore', detached: true, shell: platform === 'win32' }).unref();
  } catch {
    // Best-effort; the URL is printed regardless.
  }
}

export async function launchServer(host = '127.0.0.1', port = 8000): Promise<void> {
  display.blank();
  display.print(pc.bold(pc.cyan(`🌳 Starting ThreatForest Web Console on http://${host}:${port}`)));
  display.print(
    pc.dim('Reminder: the ML service must be running for TTP matching — start it with:  python -m ml_service'),
  );
  display.blank();

  const root = workspaceRoot();
  const env = { ...process.env, HOST: host, PORT: String(port) };

  // Launch the server package's start script (node --import tsx/esm src/main.ts).
  const child = spawn('npm', ['run', 'start', '--workspace=@threatforest/server'], {
    cwd: root,
    env,
    stdio: 'inherit',
  });

  // Open the browser shortly after the process starts (mirrors the 1.5s delay).
  const timer = setTimeout(() => openBrowser(`http://${host}:${port}`), 1500);

  return new Promise<void>((resolvePromise, reject) => {
    const onSigint = (): void => {
      clearTimeout(timer);
      child.kill('SIGINT');
    };
    process.on('SIGINT', onSigint);

    child.on('exit', (code) => {
      clearTimeout(timer);
      process.off('SIGINT', onSigint);
      if (code && code !== 0) {
        display.blank();
        display.showError(
          `Web console server exited with code ${code}.`,
          'Server stopped',
          [
            'Ensure @threatforest/server is built/runnable (WS-4).',
            `Check that port ${port} is free — retry with: threatforest --port ${port + 1}`,
          ],
        );
        reject(new Error(`server exited with code ${code}`));
      } else {
        display.blank();
        display.print(pc.cyan('👋 ThreatForest Web Console stopped.'));
        resolvePromise();
      }
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      process.off('SIGINT', onSigint);
      reject(err);
    });
  });
}
