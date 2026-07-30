/**
 * Unified TTP-matching entry point.
 *
 * Selects between the Python ML service (src/ml_service) and the in-process TS
 * embedder (transformers.js + a converted ATTACK-BERT ONNX), so the pipeline
 * stages don't care which backend runs. Selection is a single switch:
 *
 *   TF_USE_PYTHON_ML=0  → in-process TS embedder.
 *   anything else/unset → the Python ML service  (THE DEFAULT).
 *
 * The Python service is the supported backend and is deliberately kept: it is
 * the only one that honours `embeddings.model`, so alternative embedders (e.g.
 * ThreatBERT) work there. The TS embedder ignores that setting and only ever
 * loads an ATTACK-BERT conversion — configuring any other model while it is
 * active is refused up front (see ml/embedder.ts embedderSupportsModel and the
 * pre-flight in pipeline/graph.ts) because the mismatch would otherwise produce
 * wrong TTP mappings silently.
 *
 * Consequence: `npm run dev` and the MCP server DO need `python -m ml_service`
 * running unless TF_USE_PYTHON_ML=0 is set explicitly.
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

/** Whether the run relies on the external Python ML service (vs the in-process embedder). */
export function mlServiceRequired(): boolean {
  return usePythonService();
}

/**
 * Pre-flight: confirm the Python ML service is reachable when it's the active
 * backend. Returns true if not required (in-process embedder) or if healthy.
 * Lets the pipeline fail fast with a clear message instead of silently
 * producing an incomplete threat model when the service is down — every
 * per-threat TTP match would otherwise throw and be swallowed into an empty
 * result, yielding a "complete" run with missing attack paths.
 */
export async function mlHealthCheck(): Promise<boolean> {
  if (!usePythonService()) return true;
  return new MlServiceClient().health();
}

export { matchStepsInProcess } from './matcher.js';
export { getEmbedding, getBatchEmbeddings, localModelAvailable } from './embedder.js';
export { getOrBuildGraph, VectorSearch } from './graph.js';
