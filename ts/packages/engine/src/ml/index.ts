/**
 * TTP-matching entry point.
 *
 * Embeddings and MITRE technique matching run in the Python ML service
 * (`src/ml_service`, `python -m ml_service`). That service is the ONLY backend —
 * there is no in-process alternative and no switch to select one.
 *
 * Why the service rather than an in-process TS embedder: it is the only
 * implementation that honours `embeddings.model`, so alternative embedders (e.g.
 * ThreatBERT, which outperforms ATTACK-BERT on TTP mapping) can be configured
 * and used. A transformers.js embedder was tried and is kept out deliberately —
 * it ignored that setting and could only load an ATTACK-BERT ONNX conversion, so
 * configuring any other model silently produced wrong TTP mappings.
 *
 * Consequence: `npm run dev` and the MCP server require the service to be
 * running. `runGraph` pre-flights it (see pipeline/graph.ts) and refuses to
 * start rather than emitting a "complete" threat model with silently missing
 * attack paths.
 */
import type { StepMatch } from '@threatforest/types';
import { MlServiceClient } from '../ml-client.js';

export interface MatchOptions {
  topK?: number;
  minSimilarity?: number | null;
  frameworks?: string[] | null;
}

/** Match attack-step descriptions to MITRE techniques via the Python ML service. */
export async function matchSteps(steps: string[], opts: MatchOptions = {}): Promise<StepMatch[]> {
  return new MlServiceClient().matchSteps(steps, opts);
}

/**
 * Pre-flight: confirm the Python ML service is reachable. Lets the pipeline fail
 * fast with a clear message instead of silently producing an incomplete threat
 * model when the service is down — every per-threat TTP match would otherwise
 * throw and be swallowed into an empty result (see stages/parallel.ts), yielding
 * a "complete" run with missing attack paths.
 */
export async function mlHealthCheck(): Promise<boolean> {
  return new MlServiceClient().health();
}

