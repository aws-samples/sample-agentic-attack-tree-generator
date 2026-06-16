/**
 * Client for the Python ML/MITRE service (WS-1, src/ml_service/app.py).
 *
 * The TTP stage uses this instead of the old in-process TTCMatcher call. The
 * service holds the embedding model + STIX graphs warm, so calls are cheap;
 * we batch one `matchSteps` request per threat (all its steps at once) to keep
 * the cross-process hop count low.
 */
import {
  MatchStepsResponseSchema,
  EmbedResponseSchema,
  type StepMatch,
} from '@threatforest/types';

export interface MlClientOptions {
  /** Base URL of the ML service. Defaults to TF_ML_URL or http://127.0.0.1:8770. */
  baseUrl?: string;
  /** Per-request timeout (ms). Embedding a batch is fast once warm; default 120s. */
  timeoutMs?: number;
}

export class MlServiceClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(opts: MlClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? process.env.TF_ML_URL ?? 'http://127.0.0.1:8770').replace(
      /\/$/,
      '',
    );
    this.timeoutMs = opts.timeoutMs ?? 120_000;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        throw new Error(`ML service ${path} -> HTTP ${res.status}: ${await res.text()}`);
      }
      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Health probe — returns true when the service is reachable and OK. */
  async health(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/health`, { method: 'GET' });
      if (!res.ok) return false;
      const j = (await res.json()) as { status?: string };
      return j.status === 'ok';
    } catch {
      return false;
    }
  }

  /** Batch ATTACK-BERT embeddings. */
  async embed(texts: string[]): Promise<number[][]> {
    const raw = await this.post('/embed', { texts });
    return EmbedResponseSchema.parse(raw).vectors;
  }

  /**
   * Match attack-step descriptions to MITRE techniques. Mirrors
   * TTCMatcher.match_steps: returns one entry per *matched* step (steps with no
   * match above threshold are omitted), each with up to `topK` ranked matches
   * merged across frameworks, AWS-term boost applied server-side.
   */
  async matchSteps(
    steps: string[],
    opts: { topK?: number; minSimilarity?: number | null; frameworks?: string[] | null } = {},
  ): Promise<StepMatch[]> {
    const raw = await this.post('/match_steps', {
      steps,
      top_k: opts.topK ?? 3,
      min_similarity: opts.minSimilarity ?? null,
      frameworks: opts.frameworks ?? null,
    });
    return MatchStepsResponseSchema.parse(raw).results;
  }
}
