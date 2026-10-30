/**
 * Parallel per-threat pipeline — port of `src/threatforest/agents/parallel.py`.
 *
 * Fans out tree → ttp(embed via ML service) → mitigation across all threats
 * with bounded concurrency, then merges with the
 * exact renumber → remap → consolidate logic the Python uses, with the same
 * bounded per-threat retry behavior. Exhausted work fails the stage before
 * merge so a completed report cannot silently omit a threat.
 *
 * Per-threat state files use the `t{idx}_` prefix and the same skip-if-exists
 * resume semantics, so a paused/resumed run reuses completed threads' output.
 */
import { config, type EngineConfigSource } from '../config.js';
import { createModel } from '../providers.js';
import { makeRetryStrategy } from '../retry.js';
import { matchSteps } from '../ml/index.js';
import { findAttackTreeQualityIssues, findMitigationQualityIssues } from '../quality/domain-quality.js';
import { createSourceEvidenceResolver } from '../quality/evidence.js';
import { selectTtpDecision, CLOUD_TTP_BLOCKLIST } from '../quality/ttp-confidence.js';
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';
import { makeSandboxedFileRead, makeStoreMitigations } from '../tools/sandboxed-file.js';
import { makeStoreAttackTrees } from '../tools/store-attack-trees.js';
import { renumberAttackTrees, OUTPUT_CONTRACT_VERSION } from '../output-contract.js';
import { TREE_SYSTEM_PROMPT } from '../agents/tree.prompt.js';
import { MITIGATION_SYSTEM_PROMPT } from '../agents/mitigation.prompt.js';
import { traceAttrs } from '../tracing.js';
import { Agent } from '@strands-agents/sdk';
import { observeAgent, observeOperation } from '../execution-observability.js';
import { join } from 'node:path';

type Json = Record<string, unknown>;

interface ThreatResult {
  attack_trees: Json[];
  ttp_candidates: Json[];
  ttp_mappings: Json[];
  mitigations: Json[];
}

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
export async function processSingleThreat(
  threat: Json,
  threatIdx: number,
  repoPath: string,
  runDir: string | undefined,
  frameworks: string[] | null,
  engineConfig: EngineConfigSource,
  onStep?: () => void,
  cancelSignal?: AbortSignal,
): Promise<ThreatResult> {
  try {
    cancelSignal?.throwIfAborted();
    const stateDir = resolveStateDir(repoPath, runDir);
    const ws = new LocalFilesystemWorkspace(stateDir);
    const prefix = `t${threatIdx}`;
    const threatId = String(threat['id'] ?? prefix);

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

      const treeAgent = observeAgent(new Agent({
        id: `tree-${prefix}`,
        name: 'Attack tree',
        model: await createModel(engineConfig, { temperature: 0 }),
        systemPrompt: treePrompt,
        tools: [
          makeSandboxedFileRead([scannerFile, singleThreatsFile, repoPath]),
          makeStoreAttackTrees(treeOut, () => [threat]),
        ],
        printer: false,
        // Fresh instance per agent: strategies hold per-turn state and the SDK
        // rejects one that is already attached elsewhere.
        retryStrategy: makeRetryStrategy(),
        traceAttributes: traceAttrs(`tree-T${String(threatIdx).padStart(3, '0')}`),
      }), `tree-${prefix}`, `Attack tree · ${threatId}`);
      await treeAgent.invoke(
        'Read the threat and scanner context. Generate an attack tree. Write to the output file.',
        { cancelSignal, limits: { turns: 32, totalTokens: 250_000 } },
      );
      cancelSignal?.throwIfAborted();

      if (ws.exists(treeOutKey)) {
        trees = (readJsonSafe(ws, treeOutKey)['attack_trees'] as Json[]) ?? [];
      }
    }

    if (trees.length === 0) {
      throw new Error('attack-tree generation produced no trees');
    }
    const treeIssues = findAttackTreeQualityIssues(trees, [threat]);
    if (treeIssues.length > 0) {
      ws.delete(treeOutKey);
      ws.delete(`${prefix}_mitigations.json`);
      throw new Error(`invalid attack tree: ${treeIssues.join('; ')}`);
    }
    onStep?.(); // attack tree done for this threat

    // --- TTP embedding (no LLM, via the Python ML service) ---
    const steps: string[] = [];
    const stepIds: string[] = [];
    for (const tree of trees) {
      for (const step of (tree['steps'] as Json[]) ?? []) {
        steps.push((step['description'] as string) ?? '');
        stepIds.push((step['id'] as string) ?? '');
      }
    }
    if (steps.length === 0) {
      throw new Error('attack-tree generation produced no attack steps');
    }
    if (
      stepIds.some((stepId) => stepId.trim().length === 0) ||
      new Set(stepIds).size !== stepIds.length
    ) {
      throw new Error('attack-tree generation produced missing or duplicate step IDs');
    }

    const ttpCandidates: Json[] = [];
    cancelSignal?.throwIfAborted();
    if (steps.length > 0) {
      const matchOptions = {
        topK: 3,
        minSimilarity: engineConfig.ttcThreshold,
        frameworks,
        embeddingsModel: engineConfig.embeddingsModel,
      };
      const results = await observeOperation(
        `ttp-${prefix}`, `TTP mapping · ${threatId}`,
        { steps, ...matchOptions },
        () => matchSteps(steps, matchOptions),
      );
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

    // Candidate retrieval uses the configurable recall floor. Report promotion
    // uses a separate precision-oriented policy and emits an explicit
    // abstention when no candidate is sufficiently strong and unambiguous.
    const ttpMappings = ttpCandidates.map(
      (candidate) =>
        selectTtpDecision(candidate, CLOUD_TTP_BLOCKLIST) as unknown as Json,
    );
    onStep?.(); // TTP mapping done for this threat

    // --- Mitigation (skip if output already exists from a prior run) ---
    const mitOutKey = `${prefix}_mitigations.json`;
    const mitOut = join(stateDir, mitOutKey);
    let mitigations: Json[] = [];
    if (ws.exists(mitOutKey)) {
      mitigations = (readJsonSafe(ws, mitOutKey)['mitigations'] as Json[]) ?? [];
    }
    const qualityOptions = { attackTrees: trees, resolveEvidence: createSourceEvidenceResolver(repoPath, [stateDir]) };
    let mitigationIssues = findMitigationQualityIssues(
      ttpMappings,
      mitigations,
      qualityOptions,
    );

    if (mitigations.length === 0 || mitigationIssues.length > 0) {
      const mitMappingsKey = `${prefix}_mitigations_input.json`;
      const mitMappingsFile = join(stateDir, mitMappingsKey);
      ws.writeJson(mitMappingsKey, { ttp_mappings: ttpMappings });

      const mitPrompt =
        MITIGATION_SYSTEM_PROMPT +
        `\n\n## Paths\n- TTP mappings: \`${mitMappingsFile}\`\n- Scanner context: \`${scannerFile}\`\n` +
        `- Attack trees: \`${treeOut}\`\n- Output: call \`store_mitigations\` (path is preconfigured)\n`;

      const maxMitAttempts = 2;

      for (let attempt = 0; attempt < maxMitAttempts; attempt++) {
        cancelSignal?.throwIfAborted();
        ws.delete(mitOutKey);
        const mitAgent = observeAgent(new Agent({
          id: 'mitigation',
          name: 'Mitigation',
          model: await createModel(engineConfig, { temperature: 0 }),
          systemPrompt: mitPrompt,
          tools: [
            makeSandboxedFileRead([mitMappingsFile, scannerFile, treeOut, repoPath]),
            makeStoreMitigations(mitOut, qualityOptions.resolveEvidence),
          ],
          printer: false,
          // Fresh instance per attempt, for the same reason as the tree agent
          // above. Model-level retry nests inside this maxMitAttempts loop.
          retryStrategy: makeRetryStrategy(),
          traceAttributes: traceAttrs(`mitigation-T${String(threatIdx).padStart(3, '0')}`),
        }), `mitigation-${prefix}`, `Mitigation · ${threatId}`);
        const feedback =
          mitigationIssues.length === 0
            ? ''
            : ` Repair these validation issues: ${mitigationIssues.join('; ')}.`;
        try {
          await mitAgent.invoke(
            'Read the attack trees, TTP decisions, scanner context, and relevant source files. ' +
              'Cover every attack step with an actionable mitigation and exact source evidence, ' +
              'including abstained decisions (use an empty technique_id). Call store_mitigations with the complete list.' +
              feedback,
            { cancelSignal, limits: { turns: 32, totalTokens: 250_000 } },
          );
          cancelSignal?.throwIfAborted();
        } catch (err) {
          cancelSignal?.throwIfAborted();
          // A mitigation-agent failure (e.g. the SDK throwing ModelError when the
          // model's streamed store_mitigations tool-input JSON fails to parse)
          // does not discard this threat's tree + TTP work. Log and retry; an
          // exhausted budget fails this threat and prevents a partial merge.
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
        mitigationIssues = findMitigationQualityIssues(
          ttpMappings,
          mitigations,
          qualityOptions,
        );
        if (mitigationIssues.length === 0) break;
      }

      ws.delete(singleThreatsKey);
      ws.delete(mitMappingsKey);
    }
    mitigationIssues = findMitigationQualityIssues(
      ttpMappings,
      mitigations,
      qualityOptions,
    );
    if (mitigationIssues.length > 0) {
      throw new Error(
        `mitigation output remained incomplete after retries: ${mitigationIssues.join('; ')}`,
      );
    }
    onStep?.(); // mitigations done for this threat

    return {
      attack_trees: trees,
      ttp_candidates: ttpCandidates,
      ttp_mappings: ttpMappings,
      mitigations,
    };
  } catch (err) {
    throw new Error(
      `threat t${threatIdx} failed: ${(err as Error)?.message ?? String(err)}`,
      { cause: err },
    );
  }
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

export class ParallelThreatProcessingError extends Error {
  readonly failedThreatIndexes: readonly number[];

  constructor(failedThreatIndexes: readonly number[]) {
    super(
      `Threat processing failed after bounded retries for indexes: ${failedThreatIndexes.join(', ')}`,
    );
    this.name = 'ParallelThreatProcessingError';
    this.failedThreatIndexes = [...failedThreatIndexes];
  }
}

/**
 * Run independent threat work with bounded, targeted retries. Successful work
 * is retained; unresolved failures reject the stage before any merged report is
 * written.
 */
export async function collectThreatResults<T>(
  threatCount: number,
  maxRetries: number,
  processor: (threatIndex: number) => Promise<T>,
  onFailure: (threatIndex: number, error: unknown, attempt: number) => void = () => {},
  options: { concurrency?: number; cancelSignal?: AbortSignal } = {},
): Promise<T[]> {
  const concurrency = options.concurrency ?? 3;
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
    throw new Error('Threat concurrency must be an integer from 1 to 16');
  }
  const results: Array<T | undefined> = Array.from({ length: threatCount });
  let pending = Array.from({ length: threatCount }, (_, index) => index);
  for (let attempt = 1; pending.length > 0 && attempt <= maxRetries + 1; attempt += 1) {
    options.cancelSignal?.throwIfAborted();
    let cursor = 0;
    const failed: number[] = [];
    await Promise.all(Array.from({ length: Math.min(concurrency, pending.length) }, async () => {
      while (!options.cancelSignal?.aborted && cursor < pending.length) {
        const index = pending[cursor++]!;
        try {
          results[index] = await processor(index);
        } catch (error) {
          failed.push(index);
          onFailure(index, error, attempt);
        }
      }
    }));
    options.cancelSignal?.throwIfAborted();
    pending = failed.sort((a, b) => a - b);
  }
  if (pending.length > 0) {
    throw new ParallelThreatProcessingError(pending);
  }
  return results as T[];
}

/**
 * Fan out tree/ttp/mitigation across threats, merge results, write consolidated
 * state. Returns the mitigations.json path. Port of run_parallel_pipeline.
 */
/** Optional per-threat progress signal, fired as each threat finishes. */
export type ThreatProgressFn = (done: number, total: number) => void;

export async function runParallelPipeline(
  repoPath: string,
  runDir?: string,
  frameworks: string[] | null = null,
  onThreatProgress?: ThreatProgressFn | null,
  engineConfig: EngineConfigSource = config,
  cancelSignal?: AbortSignal,
): Promise<string> {
  const maxRetries = engineConfig.parallelMaxRetries;
  const stateDir = resolveStateDir(repoPath, runDir);
  const ws = new LocalFilesystemWorkspace(stateDir);

  const threats = (readJsonSafe(ws, 'threats.json')['threats'] as Json[]) ?? [];

  if (threats.length === 0) {
    for (const name of ['attack_trees', 'ttp_candidates', 'ttp_mappings', 'mitigations']) {
      ws.writeJson(`${name}.json`, { [name]: [] });
    }
    return join(stateDir, 'mitigations.json');
  }

  // Report fractional progress for this — the longest — stage. The 12 threats
  // run concurrently (Promise.all), so counting only completions would leave
  // the bar flat then jump at the end. Instead count SUB-STEPS (tree → TTP →
  // mitigation = 3 per threat) as they finish across all threats, giving a
  // steady stream of ticks. Retries are clamped to the same total.
  const STEPS_PER_THREAT = 3;
  const total = threats.length * STEPS_PER_THREAT;
  let done = 0;
  const onStep = (): void => {
    done += 1;
    onThreatProgress?.(Math.min(done, total), total);
  };

  const resultsByIdx = await collectThreatResults(
    threats.length,
    maxRetries,
    (idx) =>
      processSingleThreat(
        threats[idx]!,
        idx,
        repoPath,
        runDir,
        frameworks,
        engineConfig,
        onStep,
        cancelSignal,
      ),
    (idx, error, attempt) => {
      // eslint-disable-next-line no-console
      console.error(
        `[parallel] threat t${idx} failed on attempt ${attempt}/${maxRetries + 1}:`,
        error instanceof Error ? error.message : String(error),
      );
    },
    { concurrency: engineConfig.parallelConcurrency ?? 3, cancelSignal },
  );

  // Merge with per-result renumbering.
  const allTrees: Json[] = [];
  const allCandidates: Json[] = [];
  const allMappings: Json[] = [];
  let allMitigations: Json[] = [];
  let globalTreeIdx = 0;

  for (const r of resultsByIdx) {
    const [renumbered, idMap] = renumberAttackTrees(r.attack_trees, globalTreeIdx + 1);
    globalTreeIdx += renumbered.length;
    allTrees.push(...renumbered);
    allCandidates.push(...remapStepIds(r.ttp_candidates, idMap));
    allMappings.push(...remapStepIds(r.ttp_mappings, idMap));
    allMitigations.push(...remapStepIds(r.mitigations, idMap));
  }

  // Preserve component-specific controls, evidence, and explicit applicability.
  // Sharing a technique alone does not make a mitigation apply to another step.

  ws.writeJson('attack_trees.json', { output_contract_version: OUTPUT_CONTRACT_VERSION, attack_trees: allTrees });
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
