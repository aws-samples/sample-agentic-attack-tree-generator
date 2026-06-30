/**
 * Scanner Agent — TS port of `src/threatforest/agents/scanner/agent.py`.
 *
 * Explores a repository with the sandboxed read/structural tools and writes a
 * `scanner_context.json` ProjectContext to the run's state dir. The agent writes
 * JSON itself via `sandboxed_file_write` (no `structuredOutputSchema`), exactly
 * like the Python — so on-disk state round-trips byte-for-byte.
 *
 * Parity notes:
 * - `resolveStateDir` mirrors `resolve_state_dir`: when `runDir` is given we use
 *   `runDir/state` and create it; otherwise we return the legacy
 *   `<repo>/.threatforest/state` path WITHOUT creating it (never pollute scanned
 *   repos). `STATE_DIR` / `resolveStateDir` are re-used by threat.ts and tree.ts.
 * - `countSourceFiles` reproduces the exclusion-based walk with the same skip
 *   dirs/exts, the same `count >= 50` early-return inside the walk loop, and the
 *   same dotfile/dotdir skipping.
 * - `loadSeededBusinessContext` and the in-prompt `## Repo Info` /
 *   `## User-Provided Business Context` augmentation are ported verbatim.
 */
import { Agent, type Model } from '@strands-agents/sdk';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { config } from '../config.js';
import { createModel } from '../providers.js';
import { makeSandboxedFileRead, makeSandboxedFileWrite } from '../tools/sandboxed-file.js';
import { makeStructuralAnalyzer } from '../tools/structural-analyzer.js';
import { traceAttrs } from '../tracing.js';
import { SCANNER_SYSTEM_PROMPT } from './scanner.prompt.js';

/** Legacy default state dir, overridden by run_dir (mirrors Python STATE_DIR). */
export const STATE_DIR = '.threatforest/state';
export const STATE_FILE = 'scanner_context.json';

/**
 * Return the state directory — uses `runDir/state` if provided, else the legacy
 * `<repo>/.threatforest/state` path. Only creates the directory when `runDir` is
 * given (centralized runs); the legacy fallback returns the path without creating
 * it so scanned projects are never polluted with a `.threatforest/` folder.
 */
export function resolveStateDir(repoPath: string, runDir?: string): string {
  if (runDir) {
    const sd = join(runDir, 'state');
    mkdirSync(sd, { recursive: true });
    return sd;
  }
  return join(repoPath, STATE_DIR);
}

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '__pycache__',
  '.venv',
  'venv',
  'dist',
  'build',
  'target',
]);

const SKIP_EXTS = new Set([
  // Compiled / binary artifacts
  '.pyc',
  '.pyo',
  '.class',
  '.o',
  '.so',
  '.dylib',
  '.dll',
  '.exe',
  '.whl',
  '.egg',
  '.jar',
  '.war',
  // Package archives
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.xz',
  '.7z',
  '.rar',
  // OS junk
  '.ds_store',
]);

/**
 * Quick count of analyzable files to determine repo size category.
 *
 * Exclusion-based, like the Python `_count_source_files`: any file that isn't a
 * known binary artifact or hidden file counts. Walks top-down, prunes SKIP_DIRS,
 * and returns early once `count >= 50` is reached (checked after each directory's
 * files, matching the Python os.walk loop).
 */
export function countSourceFiles(repoPath: string): number {
  let count = 0;

  // Iterative top-down walk to mirror os.walk's dir-pruning + per-dir check.
  const stack: string[] = [repoPath];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let dirents;
    try {
      dirents = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    const subDirs: string[] = [];
    for (const ent of dirents) {
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) subDirs.push(join(dir, ent.name));
        continue;
      }
      // File
      const f = ent.name;
      if (f.startsWith('.')) continue;
      if (!SKIP_EXTS.has(extname(f).toLowerCase())) count += 1;
    }
    if (count >= 50) return count;
    // Push subdirs to continue the walk.
    for (const sd of subDirs) stack.push(sd);
  }
  return count;
}

interface SeededContext {
  business_context?: unknown;
  [k: string]: unknown;
}

/**
 * Return a pre-seeded `business_context` block if the state file exists and the
 * block is a non-empty object. Mirrors `_load_seeded_business_context`.
 */
export function loadSeededBusinessContext(stateFile: string): Record<string, unknown> | null {
  if (!existsSync(stateFile) || !statSync(stateFile).isFile()) return null;
  let data: SeededContext;
  try {
    data = JSON.parse(readFileSync(stateFile, 'utf8')) as SeededContext;
  } catch {
    return null;
  }
  const bc = data.business_context;
  if (bc && typeof bc === 'object' && !Array.isArray(bc) && Object.keys(bc as object).length > 0) {
    return bc as Record<string, unknown>;
  }
  return null;
}

/** Create a Scanner Agent scoped to the given repository. */
export async function createScannerAgent(repoPath: string, runDir?: string): Promise<Agent> {
  const stateDir = resolveStateDir(repoPath, runDir);
  const stateFile = join(stateDir, STATE_FILE);

  const tools = [
    makeStructuralAnalyzer(repoPath),
    // Allow the agent to read repo files *and* its own seeded state file so it
    // can merge business context into the output rather than overwriting it.
    makeSandboxedFileRead([repoPath, stateFile]),
    makeSandboxedFileWrite([stateFile]),
  ];

  const fileCount = countSourceFiles(repoPath);
  const sizeHint = fileCount < 50 ? 'small' : 'large';

  let systemPrompt = SCANNER_SYSTEM_PROMPT;
  systemPrompt += `\n\n## Repo Info\n- Path: \`${repoPath}\`\n- Source files: ~${fileCount}\n- Size category: **${sizeHint}**\n- Write output to: \`${stateFile}\`\n`;

  // When the run is linked to a persistent Application, the executor has seeded
  // `state_file` with a `business_context` block (plus top-level
  // compliance_requirements / data_sensitivity). Surface it in-prompt so the
  // agent treats it as authoritative and preserves (not overwrites) those fields.
  const seededBc = loadSeededBusinessContext(stateFile);
  if (seededBc !== null) {
    systemPrompt +=
      '\n\n## User-Provided Business Context (authoritative)\n' +
      'The state file has been pre-populated with the following\n' +
      'user-provided business context. Treat these fields as the\n' +
      'source of truth. Do not overwrite them; preserve them when\n' +
      'you write your output, and let them shape which parts of the\n' +
      'repo you prioritise.\n\n' +
      `\`\`\`json\n${JSON.stringify(seededBc, null, 2)}\n\`\`\`\n`;
  }

  const model: Model = await createModel(config, { temperature: 0 });

  return new Agent({
    // Distinct id so AgentNode-wrapped agents don't collide on the default
    // 'agent' id when assembled into the graph (Graph rejects duplicate node ids).
    id: 'scanner',
    name: 'Scanner',
    model,
    systemPrompt,
    tools,
    printer: false,
    traceAttributes: traceAttrs('scanner'),
  });
}

/** Run the Scanner Agent and return the state file path. */
export async function runScanner(repoPath: string, runDir?: string): Promise<string> {
  const agent = await createScannerAgent(repoPath, runDir);
  await agent.invoke('Analyze this repository and write the project context to the state file.');
  const stateDir = resolveStateDir(repoPath, runDir);
  return join(stateDir, STATE_FILE);
}
