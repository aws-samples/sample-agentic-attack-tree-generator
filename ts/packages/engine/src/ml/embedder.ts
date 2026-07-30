/**
 * In-process ATTACK-BERT embedder (transformers.js).
 *
 * Replaces the Python sentence-transformers EmbeddingService. ATTACK-BERT is an
 * mpnet sentence-transformer (768-dim, mean pooling). We load a local ONNX
 * conversion of it (see scripts/convert-model.ts) and reproduce sentence-
 * transformers' pooling (mean) + L2 normalization.
 *
 * Numerical fidelity verified: JS cosine(step, T1530) = 0.4860 vs Python
 * 0.48597 on the same strings — identical to 4dp, so re-embedding the STIX
 * corpus with this embedder yields the same ranking as the Python pipeline.
 *
 * The model is loaded lazily and held warm for the process lifetime, mirroring
 * the Python service's warm-singleton behaviour.
 */
import { join } from 'node:path';
import { existsSync } from 'node:fs';

export const DEFAULT_MODEL_NAME = 'basel/ATTACK-BERT';
export const EMBEDDING_DIM = 768;

/**
 * The two conventional on-disk locations for the ATTACK-BERT ONNX conversion
 * (produced by `npm run convert-model`). A model dir whose basename matches
 * ATTACK-BERT is treated as `DEFAULT_MODEL_NAME`, so the default path keeps
 * loading its existing `*_basel_ATTACK-BERT.json` graph caches.
 *
 * Matching is on the lowercased basename and tolerates the `_`/`-` and
 * `-onnx`-suffix spellings (attack-bert, ATTACK_BERT, attack-bert-onnx, ...).
 */
const ATTACK_BERT_DIR_RE = /^attack[-_]?bert(?:[-_]?onnx)?$/;

/** Resolve the local converted-model directory (gitignored, produced by convert-model.ts). */
function resolveModelDir(): { localPath: string; modelId: string; dir: string } | null {
  // Candidates: env override, then the conventional location under the engine package.
  const candidates = [
    process.env.TF_ATTACK_BERT_DIR,
    join(process.cwd(), 'ts', 'models', 'attack-bert'),
    join(process.cwd(), 'models', 'attack-bert'),
  ].filter((c): c is string => Boolean(c));
  for (const dir of candidates) {
    if (existsSync(join(dir, 'onnx', 'model.onnx'))) {
      // transformers.js wants (localModelPath, modelId) where the model lives at
      // <localModelPath>/<modelId>/onnx/model.onnx.
      const parts = dir.split(/[/\\]/);
      const modelId = parts.pop()!;
      return { localPath: parts.join('/'), modelId, dir };
    }
  }
  return null;
}

/**
 * The model identity this embedder will ACTUALLY load, or null when nothing is
 * loadable. This exists because the embedder does not honour
 * `config.embeddingsModel` — it only ever loads an ATTACK-BERT ONNX conversion.
 * Callers compare this against the configured model so a mismatch can be
 * refused up front instead of silently producing wrong-model vectors (and
 * overwriting a differently-stamped graph cache with them).
 *
 * A dir whose basename looks like ATTACK-BERT reports `DEFAULT_MODEL_NAME`; any
 * other dir reports its own path, so a `TF_ATTACK_BERT_DIR` aimed at some other
 * model cannot masquerade as ATTACK-BERT.
 */
export function actualEmbeddingModel(): string | null {
  const local = resolveModelDir();
  if (local) {
    return ATTACK_BERT_DIR_RE.test(local.modelId.toLowerCase()) ? DEFAULT_MODEL_NAME : local.dir;
  }
  // No local ONNX: the remote branch fetches TF_ATTACK_BERT_HF (an explicit
  // operator override of WHICH repo hosts the conversion) or the default repo.
  // Treat an explicit override as consent and report it as the identity.
  return process.env.TF_ATTACK_BERT_HF || DEFAULT_MODEL_NAME;
}

/**
 * Compare model refs the way users actually write them — a HuggingFace id
 * (`basel/ATTACK-BERT`) or an absolute path to a local dir — so the canonical id
 * and the on-disk dir that contains it are recognized as the same model.
 */
export function modelRefKey(ref: string): string {
  const s = ref.replace(/\\/g, '/').replace(/\/+$/, '');
  const base = s.split('/').pop() ?? s;
  const lower = base.toLowerCase();
  return ATTACK_BERT_DIR_RE.test(lower) ? DEFAULT_MODEL_NAME.toLowerCase() : lower;
}

/**
 * Whether the in-process TS embedder can honour `configuredModel`.
 *
 * The embedder only ever loads an ATTACK-BERT ONNX conversion; it does NOT read
 * `embeddings.model`. Running anyway is unsafe in two distinct ways:
 *   - read path: the corpus cache is one model's vectors while queries are
 *     embedded with another — cross-model cosine returns plausible-looking but
 *     wrong techniques, leaving no artifact behind;
 *   - build path: a rebuild writes the wrong model's vectors over a cache named
 *     for the configured model.
 * Both are invisible in the output of a security tool, so callers refuse up front.
 */
export function embedderSupportsModel(configuredModel: string): boolean {
  const actual = actualEmbeddingModel();
  if (actual === null) return false;
  return modelRefKey(configuredModel) === modelRefKey(actual);
}

type FeatureExtractor = (
  text: string | string[],
  opts: { pooling: 'mean'; normalize: boolean },
) => Promise<{ data: Float32Array | number[]; dims: number[] }>;

let _extractorPromise: Promise<FeatureExtractor> | null = null;

async function getExtractor(): Promise<FeatureExtractor> {
  if (_extractorPromise) return _extractorPromise;
  _extractorPromise = (async () => {
    const tf = await import('@huggingface/transformers');
    const local = resolveModelDir();
    if (local) {
      tf.env.allowRemoteModels = false;
      tf.env.localModelPath = local.localPath;
      // eslint-disable-next-line no-console
      console.error(`[embedder] loading local ATTACK-BERT ONNX from ${local.localPath}/${local.modelId}`);
      return (await tf.pipeline('feature-extraction', local.modelId)) as unknown as FeatureExtractor;
    }
    // Fallback: fetch from a HuggingFace repo that hosts the ONNX conversion.
    // Override the repo id via TF_ATTACK_BERT_HF (must contain onnx/model.onnx).
    const hfId = process.env.TF_ATTACK_BERT_HF || DEFAULT_MODEL_NAME;
    // eslint-disable-next-line no-console
    console.error(
      `[embedder] no local model dir found; attempting remote load of "${hfId}". ` +
        `If this fails, run "npm run convert-model" to generate ts/models/attack-bert.`,
    );
    return (await tf.pipeline('feature-extraction', hfId)) as unknown as FeatureExtractor;
  })();
  return _extractorPromise;
}

/** Embed a single text → 768-dim L2-normalized vector. */
export async function getEmbedding(text: string): Promise<number[]> {
  if (!text) return [];
  const extractor = await getExtractor();
  const out = await extractor(text, { pooling: 'mean', normalize: true });
  return Array.from(out.data as ArrayLike<number>);
}

/** Embed many texts. transformers.js batches internally per call; we map for clarity. */
export async function getBatchEmbeddings(texts: string[]): Promise<number[][]> {
  if (texts.length === 0) return [];
  const extractor = await getExtractor();
  // One call per text keeps memory bounded on the 48MB ATT&CK corpus build;
  // transformers.js reuses the warm session so throughput stays high.
  const out: number[][] = [];
  for (const t of texts) {
    if (!t) {
      out.push([]);
      continue;
    }
    const r = await extractor(t, { pooling: 'mean', normalize: true });
    out.push(Array.from(r.data as ArrayLike<number>));
  }
  return out;
}

/** True when a local converted model is present (so we can prefer in-process TS). */
export function localModelAvailable(): boolean {
  return resolveModelDir() !== null;
}
