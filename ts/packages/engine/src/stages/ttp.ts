/**
 * TTP embedding stage — port of
 * `src/threatforest/agents/ttp/{embedding,coverage,reviewer}.py`.
 *
 * Not an LLM stage. Embeds attack-step descriptions and finds top-K MITRE
 * technique candidates via cosine similarity. The legacy Python embeds
 * in-process with `TTCMatcher`; this TS port calls the warm Python ML service
 * (WS-1) via `MlServiceClient.matchSteps` instead — the wire contract
 * (`StepMatch` / `TechniqueMatch`) is byte-identical to `TTCMatcher.match_steps`
 * so the candidate output is 1:1.
 *
 * Parity contract (so on-disk state round-trips with the Python pipeline):
 *   - Steps + ids are collected from `attack_trees.json` in tree/step order.
 *   - matchSteps results are keyed BY DESCRIPTION (`r.attack_step`), exactly as
 *     `embedding.py` builds `step_to_result[step_text] = r["matches"]`. Steps
 *     with no match above threshold are absent from the results → empty top_k.
 *   - similarity_score is `round(m.similarity, 4)`, rank is 1-based, top_k is
 *     sliced to `top_k`.
 *   - `ttp_candidates.json` shape:
 *       { ttp_candidates: [ { attack_step_id, attack_step_description,
 *           top_k: [ { technique_id, technique_name, similarity_score, rank } ] } ] }
 *   - `ttp_top1_summary.json` shape:
 *       { ttp_top1: [ { attack_step_id, attack_step_description,
 *           technique_id, technique_name, similarity_score } ] }
 *
 * The reviewer (`reviewer.py`) is an LLM agent that refines the top-1 mappings;
 * it is CURRENTLY DISABLED in the Python pipeline (not wired into any flow), so
 * it is intentionally not ported here. The pure-computation coverage check from
 * `coverage.py` is ported as `verifyTtpCoverage`.
 */
import * as path from 'node:path';
import { config } from '../config.js';
import { MlServiceClient } from '../ml-client.js';
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';

const STATE_FILE = 'ttp_candidates.json';

/** round to 4dp, matching Python's `round(x, 4)` (4th-dp differences are
 *  numerically negligible for parity and compared with 1e-6 tolerance). */
function round4(x: number): number {
  return Math.round(x * 1e4) / 1e4;
}

/** One step's slot in attack_trees.json. */
interface TreeStep {
  id?: string;
  description?: string;
  [k: string]: unknown;
}
interface AttackTree {
  steps?: TreeStep[];
  [k: string]: unknown;
}
interface AttackTreesFile {
  attack_trees?: AttackTree[];
  [k: string]: unknown;
}

interface TtpCandidate {
  attack_step_id: string;
  attack_step_description: string;
  top_k: Array<{
    technique_id: string;
    technique_name: string;
    similarity_score: number;
    rank: number;
  }>;
}

/**
 * Run embedding-based TTP matching and write candidates to the state file.
 * Returns the state file path. Port of `run_ttp_embedding`.
 */
export async function runTtpEmbedding(
  repoPath: string,
  opts: { topK?: number; runDir?: string } = {},
): Promise<string> {
  const topK = opts.topK ?? 3;
  const stateDir = resolveStateDir(repoPath, opts.runDir);
  const workspace = new LocalFilesystemWorkspace(stateDir);

  // `out_file = state_dir / STATE_FILE` in Python; the TS workspace exposes the
  // root dir but no path helper, so join here (matches `str(state_dir / file)`).
  const pathOf = (file: string): string => path.join(workspace.root, file);

  // Load attack steps from trees.
  const treesData = workspace.readJson<AttackTreesFile>('attack_trees.json');
  const steps: string[] = [];
  const stepIds: string[] = [];
  for (const tree of treesData.attack_trees ?? []) {
    for (const step of tree.steps ?? []) {
      steps.push(step.description ?? '');
      stepIds.push(step.id ?? '');
    }
  }

  if (steps.length === 0) {
    workspace.writeJson(STATE_FILE, { ttp_candidates: [] });
    return pathOf(STATE_FILE);
  }

  // Cross-process call to the warm ML service (replaces in-process TTCMatcher).
  const client = new MlServiceClient();
  const results = await client.matchSteps(steps, {
    topK,
    minSimilarity: config.ttcThreshold,
  });

  // Build candidates keyed by step DESCRIPTION (mirrors embedding.py exactly).
  const stepToResult = new Map<string, (typeof results)[number]['matches']>();
  for (const r of results) {
    stepToResult.set(r.attack_step, r.matches);
  }

  const candidates: TtpCandidate[] = [];
  for (let i = 0; i < stepIds.length; i++) {
    const sid = stepIds[i] ?? '';
    const desc = steps[i] ?? '';
    const matches = stepToResult.get(desc) ?? [];
    candidates.push({
      attack_step_id: sid,
      attack_step_description: desc,
      top_k: matches.slice(0, topK).map((m, idx) => ({
        technique_id: m.technique_id,
        technique_name: m.name,
        similarity_score: round4(m.similarity),
        rank: idx + 1,
      })),
    });
  }

  workspace.writeJson(STATE_FILE, { ttp_candidates: candidates });

  // Write slim top-1 summary for the (currently disabled) reviewer.
  const summary = candidates.map((c) => {
    const top1 = c.top_k.length > 0 ? c.top_k[0]! : undefined;
    return {
      attack_step_id: c.attack_step_id,
      attack_step_description: c.attack_step_description,
      technique_id: top1?.technique_id ?? '',
      technique_name: top1?.technique_name ?? '',
      similarity_score: top1?.similarity_score ?? 0,
    };
  });
  workspace.writeJson('ttp_top1_summary.json', { ttp_top1: summary });

  return pathOf(STATE_FILE);
}

interface TtpMappingsFile {
  ttp_mappings?: Array<{ attack_step_id?: string; technique_id?: string; [k: string]: unknown }>;
  [k: string]: unknown;
}

/**
 * Deterministic coverage check — verifies every attack step in every tree has
 * exactly one final TTP mapping. No LLM. Port of `verify_ttp_coverage`.
 *
 * Returns `[passed, feedback]`.
 */
export function verifyTtpCoverage(repoPath: string, runDir?: string): [boolean, string] {
  const workspace = new LocalFilesystemWorkspace(resolveStateDir(repoPath, runDir));

  if (!workspace.exists('attack_trees.json')) {
    return [false, 'attack_trees.json does not exist'];
  }
  if (!workspace.exists('ttp_mappings.json')) {
    return [false, 'ttp_mappings.json does not exist'];
  }

  let treesData: AttackTreesFile;
  let mappingsData: TtpMappingsFile;
  try {
    treesData = workspace.readJson<AttackTreesFile>('attack_trees.json');
    // readJson already scrubs the trailing-comma artifacts the Python path
    // strips (`.replace(",\n]", "\n]").replace(",]", "]")`).
    mappingsData = workspace.readJson<TtpMappingsFile>('ttp_mappings.json');
  } catch (e) {
    return [false, `Failed to read state files: ${e instanceof Error ? e.message : String(e)}`];
  }

  // Collect all step IDs from trees.
  const allStepIds = new Set<string>();
  for (const tree of treesData.attack_trees ?? []) {
    for (const step of tree.steps ?? []) {
      allStepIds.add(step.id ?? '');
    }
  }

  // Collect mapped step IDs (require both step id and technique id).
  const mappedIds = new Set<string>();
  for (const m of mappingsData.ttp_mappings ?? []) {
    const sid = m.attack_step_id ?? '';
    const tid = m.technique_id ?? '';
    if (sid && tid) {
      mappedIds.add(sid);
    }
  }

  const missing = [...allStepIds].filter((sid) => !mappedIds.has(sid)).sort();
  if (missing.length > 0) {
    return [false, `Steps missing TTP mappings: ${missing.join(', ')}`];
  }

  return [true, 'All steps have TTP mappings'];
}
