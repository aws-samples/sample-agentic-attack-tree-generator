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
import { MlServiceClient } from '../ml-client.js';

export interface MatchOptions {
  topK?: number;
  minSimilarity?: number | null;
  frameworks?: string[] | null;
}

function usePythonService(): boolean {
  // Default: use the Python ML service for embeddings. The in-process TS
  // embedder (transformers.js + ATTACK-BERT ONNX) is proven at parity but kept
  // opt-in for now — set TF_USE_PYTHON_ML=0 to switch to it (requires the
  // converted model, see `npm run convert-model`).
  if (process.env.TF_USE_PYTHON_ML === '0') return false;
  return true;
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
