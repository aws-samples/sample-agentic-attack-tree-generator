/**
 * Parallel per-threat pipeline — port of `src/threatforest/agents/parallel.py`.
 *
 * Fans out tree → ttp(embed via ML service) → mitigation across all threats
 * concurrently (Promise.all instead of asyncio.gather), then merges with the
 * exact renumber → remap → consolidate logic the Python uses, with the same
 * retry-failed-threats-at-the-merge-point behaviour.
 *
 * Per-threat state files use the `t{idx}_` prefix and the same skip-if-exists
 * resume semantics, so a paused/resumed run reuses completed threads' output.
 */
import { config } from '../config.js';
import { createModel } from '../providers.js';
import { matchSteps } from '../ml/index.js';
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';
import { makeSandboxedFileRead, makeSandboxedFileWrite, makeStoreMitigations } from '../tools/sandboxed-file.js';
import { TREE_SYSTEM_PROMPT } from '../agents/tree.prompt.js';
import { MITIGATION_SYSTEM_PROMPT } from '../agents/mitigation.prompt.js';
import { traceAttrs } from '../tracing.js';
import { Agent } from '@strands-agents/sdk';
import { join } from 'node:path';

type Json = Record<string, unknown>;

interface ThreatResult {
  attack_trees: Json[];
  ttp_candidates: Json[];
  ttp_mappings: Json[];
  mitigations: Json[];
}

const EMPTY_RESULT: ThreatResult = {
  attack_trees: [],
  ttp_candidates: [],
  ttp_mappings: [],
  mitigations: [],
};

// Techniques known to be irrelevant for cloud/serverless workloads (port of
// _CLOUD_TTP_BLOCKLIST).
const CLOUD_TTP_BLOCKLIST = new Set(['T1014', 'T1548.002', 'T1088', 'T1553.001']);

function round4(x: number): number {
  return Math.round(x * 1e4) / 1e4;
}

function readJsonSafe(ws: LocalFilesystemWorkspace, key: string): Json {
  if (!ws.exists(key)) return {};
  try {
    return ws.readJson<Json>(key);
  } catch {
    return {};
  }
}

/** Run tree → ttp_embed → mitigation for one threat. Port of _process_single_threat_inner. */
async function processSingleThreat(
  threat: Json,
  threatIdx: number,
  repoPath: string,
  runDir: string | undefined,
  frameworks: string[] | null,
): Promise<ThreatResult> {
  try {
    const stateDir = resolveStateDir(repoPath, runDir);
    const ws = new LocalFilesystemWorkspace(stateDir);
    const prefix = `t${threatIdx}`;

    const scannerFile = join(stateDir, 'scanner_context.json');
    const singleThreatsKey = `${prefix}_threats.json`;
    const singleThreatsFile = join(stateDir, singleThreatsKey);
    const treeOutKey = `${prefix}_attack_trees.json`;
    const treeOut = join(stateDir, treeOutKey);

    // --- Tree generation (skip if output already exists from a prior run) ---
    let trees: Json[] = [];
    if (ws.exists(treeOutKey)) {
      trees = (readJsonSafe(ws, treeOutKey)['attack_trees'] as Json[]) ?? [];
    }

    if (trees.length === 0) {
      ws.writeJson(singleThreatsKey, { threats: [threat] });

      const treePrompt =
        TREE_SYSTEM_PROMPT +
        `\n\n## Paths\n- Scanner context: \`${scannerFile}\`\n- Threats: \`${singleThreatsFile}\`\n` +
        `- Write output to: \`${treeOut}\`\n`;

      const treeAgent = new Agent({
        model: await createModel(config, { temperature: 0 }),
        systemPrompt: treePrompt,
        tools: [
          makeSandboxedFileRead([scannerFile, singleThreatsFile, repoPath]),
          makeSandboxedFileWrite([treeOut]),
        ],
        printer: false,
        traceAttributes: traceAttrs(`tree-T${String(threatIdx).padStart(3, '0')}`),
      });
      await treeAgent.invoke(
        'Read the threat and scanner context. Generate an attack tree. Write to the output file.',
      );

      if (ws.exists(treeOutKey)) {
        trees = (readJsonSafe(ws, treeOutKey)['attack_trees'] as Json[]) ?? [];
      }
    }

    if (trees.length === 0) return { ...EMPTY_RESULT };

    // --- TTP embedding (no LLM, via the Python ML service) ---
    const steps: string[] = [];
    const stepIds: string[] = [];
    for (const tree of trees) {
      for (const step of (tree['steps'] as Json[]) ?? []) {
        steps.push((step['description'] as string) ?? '');
        stepIds.push((step['id'] as string) ?? '');
      }
    }

    const ttpCandidates: Json[] = [];
    if (steps.length > 0) {
      const results = await matchSteps(steps, {
        topK: 3,
        minSimilarity: config.ttcThreshold,
        frameworks,
      });
      const stepToMatches = new Map(results.map((r) => [r.attack_step, r.matches]));
      for (let i = 0; i < stepIds.length; i++) {
        const desc = steps[i]!;
        const matches = stepToMatches.get(desc) ?? [];
        const topK = matches.slice(0, 3).map((m, idx) => ({
          technique_id: m.technique_id,
          technique_name: m.name,
          similarity_score: round4(m.similarity),
          rank: idx + 1,
          framework: m.framework ?? 'attack',
        }));
        ttpCandidates.push({
          attack_step_id: stepIds[i]!,
          attack_step_description: desc,
          top_k: topK,
        });
      }
    }

    // Promote embedding top-1 directly (no LLM review — reviewer is disabled).
    let ttpMappings: Json[] = [];
    for (const c of ttpCandidates) {
      const topk = (c['top_k'] as Json[]) ?? [];
      const top1 = topk[0] ?? {};
      if (top1['technique_id']) {
        ttpMappings.push({
          attack_step_id: c['attack_step_id'],
          technique_id: top1['technique_id'],
          technique_name: top1['technique_name'] ?? '',
          similarity_score: top1['similarity_score'] ?? 0,
          framework: top1['framework'] ?? 'attack',
          reviewer_overrode_top1: false,
          reviewer_reasoning: '',
        });
      }
    }
    ttpMappings = ttpMappings.filter((m) => !CLOUD_TTP_BLOCKLIST.has(m['technique_id'] as string));

    // --- Mitigation (skip if output already exists from a prior run) ---
    const mitOutKey = `${prefix}_mitigations.json`;
    const mitOut = join(stateDir, mitOutKey);
    let mitigations: Json[] = [];
    if (ws.exists(mitOutKey)) {
      mitigations = (readJsonSafe(ws, mitOutKey)['mitigations'] as Json[]) ?? [];
    }

    if (mitigations.length === 0) {
      const mitMappingsKey = `${prefix}_mitigations_input.json`;
      const mitMappingsFile = join(stateDir, mitMappingsKey);
      ws.writeJson(mitMappingsKey, { ttp_mappings: ttpMappings });

      const mitPrompt =
        MITIGATION_SYSTEM_PROMPT +
        `\n\n## Paths\n- TTP mappings: \`${mitMappingsFile}\`\n- Scanner context: \`${scannerFile}\`\n` +
        `- Attack trees: \`${treeOut}\`\n- Output: call \`store_mitigations\` (path is preconfigured)\n`;

      const mappedStepIds = new Set(
        ttpMappings.map((m) => m['attack_step_id'] as string).filter(Boolean),
      );
      const maxMitAttempts = 2;

      for (let attempt = 0; attempt < maxMitAttempts; attempt++) {
        ws.delete(mitOutKey);
        const mitAgent = new Agent({
          id: 'mitigation',
          name: 'Mitigation',
          model: await createModel(config, { temperature: 0 }),
          systemPrompt: mitPrompt,
          tools: [
            makeSandboxedFileRead([mitMappingsFile, scannerFile, treeOut, repoPath]),
            makeStoreMitigations(mitOut),
          ],
          printer: false,
          traceAttributes: traceAttrs(`mitigation-T${String(threatIdx).padStart(3, '0')}`),
        });
        const feedback =
          attempt === 0
            ? ''
            : ' IMPORTANT: Your previous attempt was missing mitigations for some attack steps. ' +
              'Make sure every technique in the TTP mappings file has a mitigation.';
        try {
          await mitAgent.invoke(
            'Read the TTP mappings and scanner context. For each unique technique, synthesize an ' +
              'actionable mitigation with evidence. Call store_mitigations with the complete list.' +
              feedback,
          );
        } catch (err) {
          // A mitigation-agent failure (e.g. the SDK throwing ModelError when the
          // model's streamed store_mitigations tool-input JSON fails to parse)
          // must NOT discard this threat's tree + TTP work. Log and retry; if the
          // budget is exhausted the threat keeps its tree with empty mitigations.
          // eslint-disable-next-line no-console
          console.error(
            `[parallel] mitigation agent failed for t${threatIdx} (attempt ${attempt + 1}/${maxMitAttempts}):`,
            (err as Error).message,
          );
          continue;
        }

        mitigations = ws.exists(mitOutKey)
          ? ((readJsonSafe(ws, mitOutKey)['mitigations'] as Json[]) ?? [])
          : [];

        const covered = new Set<string>();
        for (const m of mitigations) {
          const sid = m['attack_step_id'] as string;
          if (sid) covered.add(sid);
          for (const a of (m['also_applies_to'] as string[]) ?? []) covered.add(a);
        }
        const missing = [...mappedStepIds].filter((s) => !covered.has(s));
        if (missing.length === 0 || mitigations.length === 0) break;
      }

      ws.delete(singleThreatsKey);
      ws.delete(mitMappingsKey);
    }

    return {
      attack_trees: trees,
      ttp_candidates: ttpCandidates,
      ttp_mappings: ttpMappings,
      mitigations,
    };
  } catch {
    return { ...EMPTY_RESULT };
  }
}

/** Renumber attack tree IDs from startIdx. Port of _renumber_trees. */
function renumberTrees(trees: Json[], startIdx = 1): [Json[], Record<string, string>] {
  const renumbered: Json[] = [];
  const idMap: Record<string, string> = {};
  let globalIdx = startIdx;
  for (const tree of trees) {
    const oldTreeId = (tree['id'] as string) || `AT${String(globalIdx).padStart(3, '0')}`;
    const newTreeId = `AT${String(globalIdx).padStart(3, '0')}`;
    const oldPrefix = oldTreeId + '-';
    const newPrefix = newTreeId + '-';

    const newSteps: Json[] = [];
    for (const step of (tree['steps'] as Json[]) ?? []) {
      const oldSid = (step['id'] as string) ?? '';
      const newSid = oldSid.startsWith(oldPrefix) ? newPrefix + oldSid.slice(oldPrefix.length) : oldSid;
      idMap[oldSid] = newSid;
      const newStep: Json = { ...step, id: newSid };
      const oldParent = (step['parent_id'] as string) ?? '';
      if (oldParent && oldParent.startsWith(oldPrefix)) {
        newStep['parent_id'] = newPrefix + oldParent.slice(oldPrefix.length);
      }
      newSteps.push(newStep);
    }
    renumbered.push({ ...tree, id: newTreeId, steps: newSteps });
    globalIdx += 1;
  }
  return [renumbered, idMap];
}

/** Remap attack_step_id + also_applies_to via idMap. Port of _remap_step_ids. */
function remapStepIds(items: Json[], idMap: Record<string, string>): Json[] {
  return items.map((item) => {
    const newItem: Json = { ...item };
    const oldId = (item['attack_step_id'] as string) ?? '';
    if (oldId in idMap) newItem['attack_step_id'] = idMap[oldId];
    const also = (item['also_applies_to'] as string[]) ?? [];
    if (also.length) newItem['also_applies_to'] = also.map((s) => idMap[s] ?? s);
    return newItem;
  });
}

/** Merge per-technique duplicate mitigations across threats. Port of _consolidate_mitigations. */
function consolidateMitigations(mitigations: Json[], ttpMappings: Json[]): Json[] {
  const techniqueToSteps = new Map<string, Set<string>>();
  for (const m of ttpMappings) {
    const tid = m['technique_id'] as string;
    const sid = m['attack_step_id'] as string;
    if (tid && sid) {
      if (!techniqueToSteps.has(tid)) techniqueToSteps.set(tid, new Set());
      techniqueToSteps.get(tid)!.add(sid);
    }
  }

  const byTechnique = new Map<string, Json[]>();
  const noTechnique: Json[] = [];
  for (const m of mitigations) {
    const tid = m['technique_id'] as string;
    if (tid) {
      if (!byTechnique.has(tid)) byTechnique.set(tid, []);
      byTechnique.get(tid)!.push(m);
    } else {
      noTechnique.push(m);
    }
  }

  const consolidated: Json[] = [];
  for (const [tid, group] of byTechnique) {
    // min by priority (default 99) — keep insertion order for ties (mirrors Python min()).
    let rep = group[0]!;
    let repPriority = (rep['priority'] as number) ?? 99;
    for (const m of group) {
      const p = (m['priority'] as number) ?? 99;
      if (p < repPriority) {
        rep = m;
        repPriority = p;
      }
    }

    const allStepIds = new Set<string>();
    for (const m of group) {
      const sid = m['attack_step_id'] as string;
      if (sid) allStepIds.add(sid);
      for (const a of (m['also_applies_to'] as string[]) ?? []) allStepIds.add(a);
    }
    for (const s of techniqueToSteps.get(tid) ?? []) allStepIds.add(s);
    allStepIds.delete((rep['attack_step_id'] as string) ?? '');
    allStepIds.delete('');

    consolidated.push({ ...rep, also_applies_to: [...allStepIds].sort() });
  }
  consolidated.push(...noTechnique);
  return consolidated;
}

function isEmptyResult(r: ThreatResult | null | undefined): boolean {
  if (!r) return true;
  return (r.attack_trees?.length ?? 0) === 0 && (r.mitigations?.length ?? 0) === 0;
}

/**
 * Fan out tree/ttp/mitigation across threats, merge results, write consolidated
 * state. Returns the mitigations.json path. Port of run_parallel_pipeline.
 */
export async function runParallelPipeline(
  repoPath: string,
  runDir?: string,
  frameworks: string[] | null = null,
): Promise<string> {
  const maxRetries = config.parallelMaxRetries;
  const stateDir = resolveStateDir(repoPath, runDir);
  const ws = new LocalFilesystemWorkspace(stateDir);

  const threats = (readJsonSafe(ws, 'threats.json')['threats'] as Json[]) ?? [];

  if (threats.length === 0) {
    for (const name of ['attack_trees', 'ttp_candidates', 'ttp_mappings', 'mitigations']) {
      ws.writeJson(`${name}.json`, { [name]: [] });
    }
    return join(stateDir, 'mitigations.json');
  }

  const runThreats = async (): Promise<ThreatResult[]> =>
    Promise.all(
      threats.map((threat, idx) => processSingleThreat(threat, idx, repoPath, runDir, frameworks)),
    );

  // Initial run — all threats.
  const resultsByIdx: (ThreatResult | null)[] = await runThreats();

  // Retry failed threats at the merge point (re-run all; completed threads
  // skip-if-exists and return immediately).
  for (let round = 0; round < maxRetries; round++) {
    if (!resultsByIdx.some((r) => isEmptyResult(r))) break;
    const retry = await runThreats();
    for (let i = 0; i < retry.length; i++) {
      if (!isEmptyResult(retry[i])) resultsByIdx[i] = retry[i]!;
    }
  }

  // Merge with per-result renumbering.
  const allTrees: Json[] = [];
  const allCandidates: Json[] = [];
  const allMappings: Json[] = [];
  let allMitigations: Json[] = [];
  let globalTreeIdx = 0;

  for (const r of resultsByIdx) {
    if (!r) continue;
    const [renumbered, idMap] = renumberTrees(r.attack_trees, globalTreeIdx + 1);
    globalTreeIdx += renumbered.length;
    allTrees.push(...renumbered);
    allCandidates.push(...remapStepIds(r.ttp_candidates, idMap));
    allMappings.push(...remapStepIds(r.ttp_mappings, idMap));
    allMitigations.push(...remapStepIds(r.mitigations, idMap));
  }

  allMitigations = consolidateMitigations(allMitigations, allMappings);

  ws.writeJson('attack_trees.json', { attack_trees: allTrees });
  ws.writeJson('ttp_candidates.json', { ttp_candidates: allCandidates });

  const summary = allCandidates.map((c) => {
    const top1 = ((c['top_k'] as Json[]) ?? [])[0] ?? {};
    return {
      attack_step_id: c['attack_step_id'],
      technique_id: top1['technique_id'] ?? '',
      technique_name: top1['technique_name'] ?? '',
      similarity_score: top1['similarity_score'] ?? 0,
    };
  });
  ws.writeJson('ttp_top1_summary.json', { ttp_top1: summary });
  ws.writeJson('ttp_mappings.json', { ttp_mappings: allMappings });
  ws.writeJson('mitigations.json', { mitigations: allMitigations });

  // Clean up per-threat output files (no scan_control/interrupt in this port path).
  for (let i = 0; i < threats.length; i++) {
    for (const suffix of ['attack_trees', 'mitigations', 'threats', 'mitigations_input']) {
      ws.delete(`t${i}_${suffix}.json`);
    }
  }

  return join(stateDir, 'mitigations.json');
}
