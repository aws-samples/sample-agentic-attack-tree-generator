/**
 * Workspace abstraction for per-run state and output files.
 *
 * Port of `src/threatforest/workspace.py` (LocalFilesystemWorkspace) plus the
 * `resolve_state_dir` / `_resolve_output_dir` helpers from the scanner and
 * report agents. Agents read/write JSON state files under a run's state dir
 * (run_dir/state/) instead of touching the filesystem directly, preserving the
 * existing on-disk layout so state round-trips byte-for-byte.
 *
 * Keys are forward-slash relative paths (e.g. `"threats.json"`). The root is
 * the per-run state (or output) directory, so callers pass bare state
 * filenames like `scanner_context.json`.
 *
 * Dependency-free (node:fs, node:path only).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/** Legacy default state dir, overridden by run_dir. Mirrors scanner/agent.py STATE_DIR. */
const STATE_DIR = '.threatforest/state';
/** Legacy default output dir, overridden by run_dir. Mirrors report/agent.py OUTPUT_DIR. */
const OUTPUT_DIR = '.threatforest/output';

/**
 * Workspace backed by a directory on local disk.
 *
 * The directory is the existing per-run directory used by the CLI. Keys map to
 * files beneath it.
 */
export class LocalFilesystemWorkspace {
  private readonly rootDir: string;

  constructor(stateDir: string) {
    this.rootDir = stateDir;
  }

  /** Absolute/joined path for a key, rejecting unsafe keys (mirrors Python `_path`). */
  private resolveKey(key: string): string {
    if (!key || key.startsWith('/') || key.split('/').includes('..')) {
      throw new Error(`Invalid workspace key: ${JSON.stringify(key)}`);
    }
    return path.join(this.rootDir, key);
  }

  /** The root directory backing this workspace. */
  get root(): string {
    return this.rootDir;
  }

  exists(key: string): boolean {
    return fs.existsSync(this.resolveKey(key));
  }

  readText(key: string): string {
    return fs.readFileSync(this.resolveKey(key), 'utf-8');
  }

  /**
   * Read and parse JSON, tolerating the trailing-comma artifacts the Python
   * report path scrubs (`.replace(",\n]", "\n]").replace(",]", "]")`).
   */
  readJson<T>(key: string): T {
    const raw = this.readText(key).replace(/,\n]/g, '\n]').replace(/,]/g, ']');
    return JSON.parse(raw) as T;
  }

  writeText(key: string, content: string): void {
    const target = this.resolveKey(key);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content, 'utf-8');
  }

  /** Serialize with 2-space indent (matches `json.dumps(obj, indent=2, ensure_ascii=False)`). */
  writeJson(key: string, obj: unknown): void {
    this.writeText(key, JSON.stringify(obj, null, 2));
  }
}

/**
 * Return the state directory — uses `runDir/state` if provided, else legacy path.
 *
 * Mirrors scanner/agent.py `resolve_state_dir`: only creates the directory when
 * `runDir` is given. The legacy fallback returns the path WITHOUT creating it,
 * so scanned projects are never polluted with a `.threatforest/` folder.
 */
export function resolveStateDir(repoPath: string, runDir?: string): string {
  if (runDir) {
    const sd = path.join(runDir, 'state');
    fs.mkdirSync(sd, { recursive: true });
    return sd;
  }
  return path.join(repoPath, STATE_DIR);
}

/**
 * Return the output directory — uses `runDir/output` if provided, else legacy path.
 *
 * Mirrors report/agent.py `_resolve_output_dir`. NOTE: unlike `resolveStateDir`,
 * the Python version always `mkdir -p`s the output dir (including the legacy
 * `repoPath/.threatforest/output` fallback), so this does too.
 */
export function resolveOutputDir(repoPath: string, runDir?: string): string {
  const od = runDir ? path.join(runDir, 'output') : path.join(repoPath, OUTPUT_DIR);
  fs.mkdirSync(od, { recursive: true });
  return od;
}
