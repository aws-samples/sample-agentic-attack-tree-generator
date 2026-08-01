/**
 * Mitigation Agent — LLM agent that synthesizes actionable mitigations.
 *
 * Port of:
 *   - src/threatforest/agents/mitigation/agent.py      (the agent + tools wiring)
 *   - src/threatforest/agents/mitigation/embedding.py  (control-candidate step)
 *   - src/threatforest/agents/mitigation/verifier.py   (deterministic checks)
 *   - src/threatforest/tools/sandboxed_file.py         (the two tools this agent uses:
 *                                                       make_sandboxed_file_read +
 *                                                       make_store_mitigations)
 *
 * State filenames are EXACTLY as on the Python side so on-disk JSON round-trips:
 *   reads:  ttp_mappings.json, scanner_context.json, attack_trees.json,
 *           control_candidates.json (conditional, AWS-only)
 *   writes: mitigations.json, control_candidates.json
 *
 * Strands TS SDK shapes used (verified against the .d.ts):
 *   new Agent({ model, systemPrompt, tools, printer:false, traceAttributes })
 *   tool({ name, description, inputSchema: z.object({...}), callback })
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, readdirSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';

import { Agent, tool, type JSONValue } from '@strands-agents/sdk';
import { z } from 'zod';

import { config } from '../config.js';
import { createModel } from '../providers.js';
import { makeRetryStrategy } from '../retry.js';
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';
import { MITIGATION_SYSTEM_PROMPT } from './mitigation.prompt.js';

export const STATE_FILE = 'mitigations.json';
const CONTROLS_STATE_FILE = 'control_candidates.json';

// ---------------------------------------------------------------------------
// tracing — port of agents/tracing_session.py trace_attrs(). The TS session id
// is process-global like the Python module-level `_session_id`; an orchestrator
// may set TF_TRACE_SESSION_ID before constructing agents. When unset, returns
// {} exactly like the Python (which returns {} until init_session() is called).
// ---------------------------------------------------------------------------
function traceAttrs(agentName: string): Record<string, string | string[]> {
  const sessionId = process.env.TF_TRACE_SESSION_ID;
  if (!sessionId) return {};
  return {
    'session.id': sessionId,
    'langfuse.tags': ['threatforest', agentName],
  };
}

// ===========================================================================
// sandboxed_file tools — port of src/threatforest/tools/sandboxed_file.py
// ===========================================================================

const DOCUMENT_EXTENSIONS = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv']);
const MAX_FILE_SIZE = 200_000; // ~200KB / ~50K tokens

/** Resolve a path and assert it falls within one of the allowed prefixes. Port of `_validate_path`. */
function validatePath(path: string, allowedPrefixes: string[]): string {
  let p = path;
  if (!isAbsolutePath(p)) {
    // Resolve relative paths against each allowed prefix until one exists.
    let matched = false;
    for (const prefix of allowedPrefixes) {
      const candidate = join(resolve(prefix), p);
      if (existsSync(candidate)) {
        p = candidate;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // No match — use the first directory prefix as the default base.
      for (const prefix of allowedPrefixes) {
        const rp = resolve(prefix);
        if (existsSync(rp) && statSync(rp).isDirectory()) {
          p = join(rp, p);
          break;
        }
      }
    }
  }
  const resolved = resolve(p);
  for (const prefix of allowedPrefixes) {
    if (isWithin(resolve(prefix), resolved)) return resolved;
  }
  throw new Error(`Access denied: ${resolved} is outside allowed paths`);
}

function isAbsolutePath(p: string): boolean {
  // node:path.isAbsolute, but kept explicit for parity with Path.is_absolute().
  return p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p);
}

/** True if `child` is `parent` or nested beneath it (port of Path.is_relative_to). */
function isWithin(parent: string, child: string): boolean {
  if (child === parent) return true;
  const withSep = parent.endsWith(sep) ? parent : parent + sep;
  return child.startsWith(withSep);
}

/**
 * Build a `sandboxed_file_read` tool restricted to specific paths. Port of
 * `make_sandboxed_file_read`. The in-process `_cache` and offset/limit ranged
 * reads are preserved; binary document extensions are surfaced as a structured
 * Bedrock document content block exactly as the Python does.
 */
export function makeSandboxedFileRead(allowedReadPaths: string[]) {
  const cache = new Map<string, JSONValue>();

  return tool({
    name: 'sandboxed_file_read',
    description:
      'Read file content — restricted to allowed paths for this agent. For large files, ' +
      'only the first portion is returned. Use offset/limit to read specific sections.',
    inputSchema: z.object({
      path: z.string().describe('Path to the file to read (can be relative to the project root).'),
      offset: z
        .number()
        .int()
        .default(0)
        .describe('Line number to start reading from (0-based, default: start of file).'),
      limit: z
        .number()
        .int()
        .default(0)
        .describe('Maximum number of lines to return (default: 0 = up to the size cap).'),
    }),
    callback: ({ path, offset, limit }): JSONValue => {
      const resolved = validatePath(path, allowedReadPaths);
      const cacheKey = `${resolved}:${offset}:${limit}`;
      if (cache.has(cacheKey)) {
        const cached = cache.get(cacheKey);
        if (cached !== null && typeof cached === 'object') return cached;
        return `[CACHED — already read this range]\n${String(cached)}`;
      }

      const st = statSync(resolved);
      if (st.isDirectory()) {
        const entries = readdirSync(resolved).sort();
        const result = entries.join('\n');
        cache.set(cacheKey, result);
        return result;
      }

      const suffix = extLower(resolved);
      if (DOCUMENT_EXTENSIONS.has(suffix)) {
        // CAVEAT: binary document ingestion is not ported in v1 (parity with
        // tools/sandboxed-file.ts). The Python path returns a Bedrock
        // {document:{...bytes}} content block; here we return a clear placeholder
        // string. Use the Python pipeline for PDF/Office document extraction.
        const result =
          `[binary document read not yet supported in TS port] ${baseName(resolved)} ` +
          `(${suffix.replace(/^\./, '')}). Use the Python pipeline for PDF/Office document extraction.`;
        cache.set(cacheKey, result);
        return result;
      }

      const content = readFileSync(resolved, 'utf8');
      const lines = splitKeepEnds(content);
      const totalLines = lines.length;
      const fileSize = st.size;

      // Ranged read — drilling into a specific section.
      if (offset > 0 || limit > 0) {
        let sliced = lines.slice(offset);
        if (limit > 0) sliced = sliced.slice(0, limit);
        let result = sliced.join('');
        if (result.length > MAX_FILE_SIZE) {
          result = result.slice(0, MAX_FILE_SIZE);
          const shown = countNewlines(result);
          result +=
            `\n\n[TRUNCATED at ${Math.trunc(MAX_FILE_SIZE / 1000)}KB — showing ~${shown} lines ` +
            `starting at line ${offset}. Use offset=${offset + shown} to continue.]`;
        } else {
          result += `\n\n[Lines ${offset}-${offset + sliced.length} of ${totalLines}]`;
        }
        cache.set(cacheKey, result);
        return result;
      }

      // Full read — small files return as-is.
      if (fileSize <= MAX_FILE_SIZE) {
        cache.set(cacheKey, content);
        return content;
      }

      // Large file — head + tail + metadata preview.
      const HEAD_LINES = 100;
      const TAIL_LINES = 20;
      const head = lines.slice(0, HEAD_LINES).join('');
      const tail = lines.slice(-TAIL_LINES).join('');
      const result =
        `[LARGE FILE: ${formatThousands(fileSize)} bytes, ${totalLines} lines — showing preview]\n` +
        `--- First ${HEAD_LINES} lines ---\n` +
        `${head}\n` +
        `--- Last ${TAIL_LINES} lines ---\n` +
        `${tail}\n` +
        `[Use offset and limit to read specific sections, e.g. offset=100 limit=200]`;
      cache.set(cacheKey, result);
      return result;
    },
  });
}

// --- store_mitigations tool ------------------------------------------------
//
// PARITY NOTE: this tool's input schema mirrors the Pydantic `Mitigation`
// model in sandboxed_file.py (make_store_mitigations) — which is what actually
// shapes mitigations.json on disk. It deliberately includes `remediation_type`
// and `also_applies_to`, which the shared `@threatforest/types` MitigationSchema
// OMITS. The verifier reads those fields, so the tool's output must carry them.
// We do NOT reuse MitigationSchema here for that reason. Field order in the
// written JSON matches the Pydantic field declaration order.
const EvidenceInput = z.object({
  source_type: z.string(),
  source_ref: z.string(),
  excerpt: z.string(),
  relevance: z.string(),
});

const MitigationInput = z.object({
  attack_step_id: z.string(),
  technique_id: z.string(),
  mitigation_text: z.string(),
  implementation_guidance: z.string(),
  remediation_type: z.enum(['quick_win', 'short_term', 'medium_term', 'long_term', 'monitoring']),
  control_candidates: z.array(z.record(z.string(), z.unknown())).default([]),
  selected_control_id: z.string().default(''),
  priority: z.number().int(),
  evidence: z.array(EvidenceInput),
  also_applies_to: z.array(z.string()).default([]),
});

/**
 * Build a `store_mitigations` tool that validates and writes mitigations. Port
 * of `make_store_mitigations`. Writes `{"mitigations": [...]}` with 2-space
 * indent (matches `json.dumps(data, indent=2)`).
 */
export function makeStoreMitigations(outputPath: string) {
  return tool({
    name: 'store_mitigations',
    description:
      'Store all mitigations at once. Each mitigation is validated against a schema before ' +
      'writing. Every field is required and validated.',
    inputSchema: z.object({
      mitigations: z.array(MitigationInput).describe('List of mitigation objects.'),
    }),
    callback: ({ mitigations }): string => {
      mkdirSync(dirname(outputPath), { recursive: true });
      const data = { mitigations };
      writeFileSync(outputPath, JSON.stringify(data, null, 2), 'utf8');
      return `Stored ${mitigations.length} mitigations to ${outputPath}`;
    },
  });
}

// ===========================================================================
// Mitigation agent — port of agents/mitigation/agent.py
// ===========================================================================

/**
 * Create a Mitigation Agent. Reads ttp_mappings / scanner_context / attack_trees
 * (plus control_candidates.json when present) and writes mitigations.json via
 * the preconfigured `store_mitigations` tool.
 */
export async function createMitigationAgent(repoPath: string, runDir?: string | null): Promise<Agent> {
  const stateDir = resolveStateDir(repoPath, runDir ?? undefined);

  const readFiles = [
    join(stateDir, 'ttp_mappings.json'),
    join(stateDir, 'scanner_context.json'),
    join(stateDir, 'attack_trees.json'),
  ];

  // Control candidates may or may not exist (AWS conditional).
  const controlsFile = join(stateDir, CONTROLS_STATE_FILE);
  if (existsSync(controlsFile)) {
    readFiles.push(controlsFile);
  }

  const outFile = join(stateDir, STATE_FILE);

  const tools = [makeSandboxedFileRead(readFiles), makeStoreMitigations(outFile)];

  let systemPrompt = MITIGATION_SYSTEM_PROMPT;
  systemPrompt +=
    `\n\n## Paths\n` +
    `- TTP mappings: \`${join(stateDir, 'ttp_mappings.json')}\`\n` +
    `- Scanner context: \`${join(stateDir, 'scanner_context.json')}\`\n` +
    `- Attack trees: \`${join(stateDir, 'attack_trees.json')}\`\n` +
    `- Control candidates (if exists): \`${controlsFile}\`\n` +
    `- Output: call \`store_mitigations\` (path is preconfigured)\n`;

  const model = await createModel(config, { temperature: 0 });

  return new Agent({
    id: 'mitigation',
    name: 'Mitigation',
    model,
    systemPrompt,
    tools,
    printer: false,
    retryStrategy: makeRetryStrategy(),
    traceAttributes: traceAttrs('mitigation'),
  });
}

/**
 * Run the Mitigation Agent and return the state file path. Port of
 * `run_mitigation_agent`.
 */
export async function runMitigationAgent(repoPath: string, runDir?: string | null): Promise<string> {
  const agent = await createMitigationAgent(repoPath, runDir);
  await agent.invoke(
    'Read all state files. For each unique technique, synthesize an actionable mitigation with ' +
      'evidence. Call store_mitigations with the complete list.',
  );
  const stateDir = resolveStateDir(repoPath, runDir ?? undefined);
  return join(stateDir, STATE_FILE);
}

// ===========================================================================
// Control-candidate embedding step — port of agents/mitigation/embedding.py
// ===========================================================================
//
// CAVEAT (dependency flagged, no endpoint invented): the Python embedding.py is
// a PLACEHOLDER. It does NOT call the ML/MITRE service — there is no AWS Control
// Catalog embedding endpoint yet. It only emits the correct schema with EMPTY
// `top_k` lists ("populated when catalog embeddings exist"). The MlServiceClient
// (WS-1) exposes /embed and /match_steps for MITRE techniques, NOT a control
// catalog, so routing through it would be wrong. We therefore port the
// placeholder faithfully: write the correct shape with empty candidates, and
// leave a clear TODO for when the catalog embeddings are built.

export const CONTROL_STATE_FILE = CONTROLS_STATE_FILE;

interface AttackTreesFile {
  attack_trees?: Array<{ steps?: Array<{ id?: string; description?: string }> }>;
}
interface ScannerContextFile {
  cloud_provider?: string;
}

/** Check scanner context for AWS cloud provider. Port of `_is_aws_project`. */
function isAwsProject(repoPath: string, runDir?: string | null): boolean {
  const workspace = new LocalFilesystemWorkspace(resolveStateDir(repoPath, runDir ?? undefined));
  if (!workspace.exists('scanner_context.json')) return false;
  try {
    const data = workspace.readJson<ScannerContextFile>('scanner_context.json');
    return (data.cloud_provider ?? '').toLowerCase() === 'aws';
  } catch {
    return false;
  }
}

/**
 * Run control-embedding search. Returns the state file path, or `null` if
 * skipped (non-AWS projects — architecture: conditional edge). Port of
 * `run_control_embedding`.
 *
 * NOTE: `topK` is accepted for signature parity but unused while the catalog
 * embeddings do not exist (matches the Python placeholder, which also ignores
 * its `top_k` argument).
 */
export function runControlEmbedding(
  repoPath: string,
  topK = 5,
  runDir?: string | null,
): string | null {
  void topK; // unused until AWS Control Catalog embeddings are built (see CAVEAT).
  const stateDir = resolveStateDir(repoPath, runDir ?? undefined);
  const workspace = new LocalFilesystemWorkspace(stateDir);
  const outFile = join(stateDir, CONTROLS_STATE_FILE);

  if (!isAwsProject(repoPath, runDir)) return null;

  // Load attack steps from trees.
  const treesData = workspace.readJson<AttackTreesFile>('attack_trees.json');

  const steps: Array<{ id: string; description: string }> = [];
  for (const tree of treesData.attack_trees ?? []) {
    for (const step of tree.steps ?? []) {
      steps.push({ id: step.id ?? '', description: step.description ?? '' });
    }
  }

  if (steps.length === 0) {
    workspace.writeJson(CONTROLS_STATE_FILE, { control_candidates: [] });
    return outFile;
  }

  // TODO: Replace with actual AWS Control Catalog embedding search when the
  // catalog embeddings are built. For now this is a placeholder producing the
  // correct schema (empty top_k) so downstream agents work.
  const candidates = steps.map((step) => ({
    attack_step_id: step.id,
    top_k: [] as unknown[], // populated when catalog embeddings exist
  }));

  workspace.writeJson(CONTROLS_STATE_FILE, { control_candidates: candidates });
  return outFile;
}

// ===========================================================================
// Mitigation verifier — port of agents/mitigation/verifier.py
// ===========================================================================

const BOILERPLATE = new Set([
  'implement proper access controls',
  'follow security best practices',
  'use encryption',
  'apply the principle of least privilege',
  'implement input validation',
  'use secure coding practices',
  'implement monitoring and logging',
]);

const VALID_REMEDIATION_TYPES = new Set([
  'quick_win',
  'short_term',
  'medium_term',
  'long_term',
  'monitoring',
]);

interface MitigationsFile {
  mitigations?: Array<{
    attack_step_id?: string;
    also_applies_to?: string[];
    mitigation_text?: string;
    evidence?: unknown[];
    priority?: unknown;
    remediation_type?: string;
  }>;
}
interface TtpMappingsFile {
  ttp_mappings?: Array<{ attack_step_id?: string }>;
}

/**
 * Verify mitigations are actionable, specific, and evidenced. Returns
 * `[passed, feedback]`. Faithful port of `verify_mitigation_output`.
 *
 * Parity note: Python manually scrubs trailing commas in mitigations.json
 * (`,\n]`→`\n]`, `,]`→`]`) before json.loads. The TS workspace.readJson applies
 * the same scrub to every read, so reading via readJson is a strict superset of
 * the Python behaviour and stays in parity.
 */
export function verifyMitigationOutput(repoPath: string, runDir?: string | null): [boolean, string] {
  const workspace = new LocalFilesystemWorkspace(resolveStateDir(repoPath, runDir ?? undefined));

  if (!workspace.exists('mitigations.json')) {
    return [false, 'mitigations.json does not exist'];
  }
  if (!workspace.exists('attack_trees.json')) {
    return [false, 'attack_trees.json does not exist'];
  }

  let mitData: MitigationsFile;
  let treesData: AttackTreesFile;
  try {
    mitData = workspace.readJson<MitigationsFile>('mitigations.json');
    treesData = workspace.readJson<AttackTreesFile>('attack_trees.json');
  } catch (e) {
    return [false, `Failed to read state files: ${e instanceof Error ? e.message : String(e)}`];
  }

  const mitigations = mitData.mitigations ?? [];

  // Collect step IDs that have TTP mappings (only these can have mitigations).
  const allStepIds = new Set<string>();
  if (workspace.exists('ttp_mappings.json')) {
    try {
      const mappingsData = workspace.readJson<TtpMappingsFile>('ttp_mappings.json');
      for (const m of mappingsData.ttp_mappings ?? []) {
        const sid = m.attack_step_id ?? '';
        if (sid) allStepIds.add(sid);
      }
    } catch {
      // Fall back to tree step IDs if mappings unreadable.
      for (const tree of treesData.attack_trees ?? []) {
        for (const step of tree.steps ?? []) {
          allStepIds.add(step.id ?? '');
        }
      }
    }
  } else {
    for (const tree of treesData.attack_trees ?? []) {
      for (const step of tree.steps ?? []) {
        allStepIds.add(step.id ?? '');
      }
    }
  }

  if (mitigations.length === 0 && allStepIds.size > 0) {
    return [false, 'No mitigations produced but attack steps exist'];
  }

  // Hard failures warrant a retry; soft warnings are logged but don't.
  const hardIssues: string[] = [];
  const warnings: string[] = [];
  const coveredIds = new Set<string>();

  for (let i = 0; i < mitigations.length; i++) {
    const m = mitigations[i]!;
    const sid = m.attack_step_id ?? '';
    if (!sid) {
      hardIssues.push(`Mitigation ${i}: missing attack_step_id`);
      continue;
    }
    coveredIds.add(sid);
    for (const also of m.also_applies_to ?? []) {
      coveredIds.add(also);
    }

    const text = m.mitigation_text ?? '';
    if (!text) {
      hardIssues.push(`${sid}: empty mitigation_text`);
    } else if (BOILERPLATE.has(stripTrailingDots(text.toLowerCase().trim()))) {
      warnings.push(`${sid}: boilerplate mitigation — '${text}'`);
    }

    const evidence = m.evidence ?? [];
    if (evidence.length === 0) {
      warnings.push(`${sid}: no evidence provided`);
    }

    if (!m.priority) {
      warnings.push(`${sid}: missing priority`);
    }

    const rtype = m.remediation_type ?? '';
    if (!rtype) {
      hardIssues.push(`${sid}: missing remediation_type`);
    } else if (!VALID_REMEDIATION_TYPES.has(rtype)) {
      hardIssues.push(
        `${sid}: invalid remediation_type '${rtype}' — must be one of ${formatSet(VALID_REMEDIATION_TYPES)}`,
      );
    }
  }

  const missing = [...allStepIds].filter((id) => !coveredIds.has(id));
  if (missing.length > 0) {
    // Coverage gaps are warnings, not hard failures — per-threat verification
    // inside the parallel pipeline handles retries at the individual threat level.
    warnings.push(`${missing.length} steps without mitigations`);
  }

  if (hardIssues.length > 0) {
    return [false, hardIssues.join('; ')];
  }

  let feedback = 'All mitigations are actionable and evidenced';
  if (warnings.length > 0) {
    feedback += ` (${warnings.length} warnings)`;
  }
  return [true, feedback];
}

// ---------------------------------------------------------------------------
// small string/byte helpers (kept local; no deps)
// ---------------------------------------------------------------------------

/** Python str.rstrip(".") — strip trailing '.' characters only. */
function stripTrailingDots(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === '.') end--;
  return s.slice(0, end);
}

/** Render a JS Set the way Python renders a set literal: `{'a', 'b'}` (insertion order). */
function formatSet(s: Set<string>): string {
  return `{${[...s].map((v) => `'${v}'`).join(', ')}}`;
}

/** splitlines(keepends=True): keep the trailing newline on each line. */
function splitKeepEnds(content: string): string[] {
  if (content === '') return [];
  const lines = content.split(/(?<=\n)/);
  // A trailing split after a final newline produces a spurious '' — drop it.
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function countNewlines(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s[i] === '\n') n++;
  return n;
}

/** Python f"{n:,}" — thousands-separated integer. */
function formatThousands(n: number): string {
  return n.toLocaleString('en-US');
}

function extLower(p: string): string {
  const base = baseName(p);
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

function baseName(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx < 0 ? p : p.slice(idx + 1);
}
