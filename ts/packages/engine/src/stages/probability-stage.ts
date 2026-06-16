/**
 * Probability stage GraphNode entry — port of `run_probability_stage` in
 * `src/threatforest/agents/probability/stage.py`.
 *
 * Loads attack_trees.json + ttp_mappings.json + mitigations.json +
 * scanner_context.json from the run's state dir, applies the pure-function
 * `computeProbabilities` (probability.ts), and writes the augmented trees back
 * to attack_trees.json in place. Idempotent.
 */
import { LocalFilesystemWorkspace, resolveStateDir } from '../workspace.js';
import { computeProbabilities, indexByStep, type TreeLike } from './probability.js';

type Json = Record<string, unknown>;

function loadJson(ws: LocalFilesystemWorkspace, key: string): Json {
  if (!ws.exists(key)) return {};
  try {
    return ws.readJson<Json>(key);
  } catch {
    return {};
  }
}

export async function runProbabilityStage(repoPath: string, runDir?: string): Promise<string> {
  const stateDir = resolveStateDir(repoPath, runDir);
  const ws = new LocalFilesystemWorkspace(stateDir);

  if (!ws.exists('attack_trees.json')) {
    return 'probability: no attack_trees.json to process';
  }

  const treeBlob = loadJson(ws, 'attack_trees.json');
  const trees = (treeBlob['attack_trees'] as TreeLike[]) ?? [];
  if (trees.length === 0) return 'probability: no trees to process';

  const ttpBlob = loadJson(ws, 'ttp_mappings.json');
  const mitBlob = loadJson(ws, 'mitigations.json');
  const scannerBlob = loadJson(ws, 'scanner_context.json');

  const ttpByStep = indexByStep((ttpBlob['ttp_mappings'] as Json[]) ?? [], 'attack_step_id');
  const mitigationsByStep = indexByStep((mitBlob['mitigations'] as Json[]) ?? [], 'attack_step_id');
  const techStack = (scannerBlob['tech_stack'] as string) ?? '';

  computeProbabilities(trees, ttpByStep, mitigationsByStep, techStack);

  treeBlob['attack_trees'] = trees;
  ws.writeJson('attack_trees.json', treeBlob);

  const totalSteps = trees.reduce((n, t) => n + ((t.steps as unknown[])?.length ?? 0), 0);
  return `probability: scored ${totalSteps} steps across ${trees.length} trees`;
}
