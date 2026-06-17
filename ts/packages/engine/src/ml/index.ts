/**
 * Unified TTP-matching entry point.
 *
 * Selects between in-process TS embedding (transformers.js + converted
 * ATTACK-BERT ONNX) and the Python ML service (WS-1, kept as a fallback), so the
 * pipeline stages don't care which backend runs. Selection:
 *
 *   1. TF_USE_PYTHON_ML=1            → force the Python service (MlServiceClient).
 *   2. TF_ML_URL set (and not =1 off) → use the Python service if a local model
 *                                       isn't available.
 *   3. local converted model present → in-process TS (default, no service needed).
 *   4. otherwise                     → in-process TS, which will try a remote HF
 *                                       load and otherwise instruct the user to
 *                                       run `npm run convert-model`.
 *
 * The default (no env) is pure-TS in-process, so `npm run dev` needs no Python.
 */
import type { StepMatch } from '@threatforest/types';
import { matchStepsInProcess } from './matcher.js';
import { localModelAvailable } from './embedder.js';
import { MlServiceClient } from '../ml-client.js';

export interface MatchOptions {
  topK?: number;
  minSimilarity?: number | null;
  frameworks?: string[] | null;
}

function usePythonService(): boolean {
  if (process.env.TF_USE_PYTHON_ML === '1') return true;
  if (process.env.TF_USE_PYTHON_ML === '0') return false;
  // Auto: prefer in-process TS when a local model exists; else fall back to the
  // Python service only if its URL was explicitly configured.
  if (localModelAvailable()) return false;
  return Boolean(process.env.TF_ML_URL);
}

/**
 * Match attack-step descriptions to MITRE techniques. Returns StepMatch[] —
 * identical shape from either backend, so callers are backend-agnostic.
 */
export async function matchSteps(steps: string[], opts: MatchOptions = {}): Promise<StepMatch[]> {
  if (usePythonService()) {
    return new MlServiceClient().matchSteps(steps, opts);
  }
  return matchStepsInProcess(steps, opts);
}

export { matchStepsInProcess } from './matcher.js';
export { getEmbedding, getBatchEmbeddings, localModelAvailable } from './embedder.js';
export { getOrBuildGraph, VectorSearch } from './graph.js';
