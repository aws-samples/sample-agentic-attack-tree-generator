/**
 * Filesystem browse routes — TS port of `src/server/routes/filesystem.py`.
 * Mounted under `/api`.
 *
 *   GET  /filesystem/browse?path=<abs dir>   directory listing for the picker
 *   POST /filesystem/pick-directory          OS-native directory dialog
 */
import { Router, type Request, type Response } from 'express';
import { execFile } from 'node:child_process';
import { homedir, platform } from 'node:os';
import {
  FilesystemBrowser,
  PathNotFoundError,
  PathTraversalError,
  NotADirectoryError,
} from '../filesystem.js';

export const filesystemRouter: Router = Router();

// Module-level browser — allowed roots default to home + cwd, matching Python.
let _browser = new FilesystemBrowser([homedir(), process.cwd()]);

export function getBrowser(): FilesystemBrowser {
  return _browser;
}

export function setBrowser(browser: FilesystemBrowser): void {
  _browser = browser;
}

/** GET /filesystem/browse — list a server-side directory for the File Picker. */
filesystemRouter.get('/filesystem/browse', (req: Request, res: Response) => {
  const path = typeof req.query.path === 'string' ? req.query.path : undefined;
  if (path === undefined) {
    res.status(422).json({ detail: 'Query parameter `path` is required.' });
    return;
  }
  try {
    res.json(getBrowser().listDirectory(path));
  } catch (err) {
    if (err instanceof PathNotFoundError) {
      res.status(404).json({ detail: err.message });
      return;
    }
    if (err instanceof PathTraversalError) {
      res.status(403).json({ detail: err.message });
      return;
    }
    if (err instanceof NotADirectoryError) {
      res.status(400).json({ detail: err.message });
      return;
    }
    throw err;
  }
});

/** POST /filesystem/pick-directory — open the OS-native directory dialog. */
filesystemRouter.post('/filesystem/pick-directory', async (_req: Request, res: Response) => {
  const path = await nativePickDirectory();
  res.json({ path });
});

/** Open the OS-native directory picker and return the selected path (or null). */
function nativePickDirectory(): Promise<string | null> {
  const sys = platform();
  if (sys === 'darwin') {
    return run('osascript', [
      '-e',
      'POSIX path of (choose folder with prompt "Select project directory")',
    ]).then((out) => (out === null ? null : out.trim().replace(/\/+$/, '')));
  }
  if (sys === 'linux') {
    return runFirst([
      ['zenity', ['--file-selection', '--directory', '--title=Select project directory']],
      [
        'kdialog',
        ['--getexistingdirectory', homedir(), '--title', 'Select project directory'],
      ],
    ]).then((out) => (out === null ? null : out.trim()));
  }
  if (sys === 'win32') {
    const ps =
      'Add-Type -AssemblyName System.Windows.Forms; ' +
      '$d = New-Object System.Windows.Forms.FolderBrowserDialog; ' +
      "$d.Description = 'Select project directory'; " +
      "if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }";
    return run('powershell', ['-Command', ps]).then((out) =>
      out === null || out.trim() === '' ? null : out.trim(),
    );
  }
  return Promise.resolve(null);
}

/** Run a command, resolving its stdout on success or null on any failure. */
function run(cmd: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 120_000 }, (err, stdout) => {
      if (err) {
        resolve(null);
        return;
      }
      resolve(stdout);
    });
  });
}

/** Try each command in order; return the first that succeeds, else null. */
async function runFirst(commands: Array<[string, string[]]>): Promise<string | null> {
  for (const [cmd, args] of commands) {
    const out = await run(cmd, args);
    if (out !== null) return out;
  }
  return null;
}
