/**
 * Regression tests for the embedder/config model-mismatch bug.
 *
 * The in-process TS embedder only loads an ATTACK-BERT ONNX conversion and does
 * NOT honour `embeddings.model`, while the graph-cache filename IS derived from
 * `embeddings.model` (ml/matcher.ts). Before this guard, configuring a different
 * model (e.g. a local ThreatBERT) meant:
 *   - the cache named for ThreatBERT was rebuilt with ATTACK-BERT vectors and
 *     overwritten in place (corrupting an artifact the Python/eval path reads), and
 *   - queries were embedded with ATTACK-BERT against a foreign-model corpus,
 *     yielding plausible-looking but wrong techniques with no artifact left behind.
 *
 * Both are invisible in a security tool's output, so the contract is: refuse.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  modelRefKey,
  embedderSupportsModel,
  actualEmbeddingModel,
  DEFAULT_MODEL_NAME,
} from './embedder.js';
import { getOrBuildGraph, GraphModelMismatchError } from './graph.js';

/** Create a dir that looks like a converted-ONNX model dir, and point env at it. */
function withModelDir(dirName: string, fn: () => void): void {
  const root = mkdtempSync(join(tmpdir(), 'tf-embedder-guard-'));
  const modelDir = join(root, dirName);
  mkdirSync(join(modelDir, 'onnx'), { recursive: true });
  writeFileSync(join(modelDir, 'onnx', 'model.onnx'), 'not-a-real-onnx');
  const prev = process.env.TF_ATTACK_BERT_DIR;
  process.env.TF_ATTACK_BERT_DIR = modelDir;
  try {
    fn();
  } finally {
    if (prev === undefined) delete process.env.TF_ATTACK_BERT_DIR;
    else process.env.TF_ATTACK_BERT_DIR = prev;
    rmSync(root, { recursive: true, force: true });
  }
}

describe('modelRefKey', () => {
  it('treats the canonical HF id and the local attack-bert dir as the same model', () => {
    assert.equal(modelRefKey('basel/ATTACK-BERT'), modelRefKey('/x/y/attack-bert'));
  });

  it('tolerates case and separator spellings of the attack-bert dir', () => {
    const want = modelRefKey('basel/ATTACK-BERT');
    for (const spelling of ['attack-bert', 'ATTACK-BERT', 'attack_bert', 'attack-bert-onnx']) {
      assert.equal(modelRefKey(`/models/${spelling}`), want, spelling);
    }
  });

  it('does NOT conflate a different model with attack-bert', () => {
    assert.notEqual(modelRefKey('/models/threatbert-embed-asym'), modelRefKey('basel/ATTACK-BERT'));
  });
});

describe('embedderSupportsModel', () => {
  it('accepts the default ATTACK-BERT config against an attack-bert dir', () => {
    withModelDir('attack-bert', () => {
      assert.equal(actualEmbeddingModel(), DEFAULT_MODEL_NAME);
      assert.equal(embedderSupportsModel('basel/ATTACK-BERT'), true);
    });
  });

  it('REFUSES a ThreatBERT config, because the embedder would load ATTACK-BERT', () => {
    withModelDir('attack-bert', () => {
      assert.equal(
        embedderSupportsModel('/Users/x/ThreatForest-internal/models/threatbert-embed-asym'),
        false,
      );
    });
  });

  it('a TF_ATTACK_BERT_DIR pointing at another model cannot masquerade as ATTACK-BERT', () => {
    withModelDir('threatbert-embed-asym', () => {
      assert.notEqual(actualEmbeddingModel(), DEFAULT_MODEL_NAME);
      assert.equal(embedderSupportsModel('basel/ATTACK-BERT'), false);
    });
  });
});

describe('getOrBuildGraph cache-overwrite guard', () => {
  /** Write a graph cache stamped with `model`, plus a STIX bundle newer than it. */
  function seedCache(model: string): { dir: string; graphPath: string; stixPath: string } {
    const dir = mkdtempSync(join(tmpdir(), 'tf-graph-guard-'));
    const graphPath = join(dir, `attack_graph_${model.replace(/[/\\]/g, '_')}.json`);
    writeFileSync(
      graphPath,
      JSON.stringify({
        techniques: [{ id: 'technique-T1000', embedding: [0.1, 0.2] }],
        embedding_model: model,
        embedding_dim: 768,
        created_at: new Date(0).toISOString(),
        stix_version: '2.1',
      }),
    );
    // A STIX bundle newer than the cache makes isStale() want to rebuild.
    const stixPath = join(dir, 'bundle.json');
    writeFileSync(stixPath, JSON.stringify({ type: 'bundle', objects: [] }));
    return { dir, graphPath, stixPath };
  }

  it('refuses to overwrite a cache built by a DIFFERENT embedding model', async () => {
    const foreign = '/Users/x/ThreatForest-internal/models/threatbert-embed-asym';
    const { dir, graphPath, stixPath } = seedCache(foreign);
    try {
      await withModelDirAsync('attack-bert', async () => {
        await assert.rejects(
          () =>
            getOrBuildGraph({
              graphPath,
              stixBundlePath: stixPath,
              sourceName: 'mitre-attack',
              killChainName: 'mitre-attack',
            }),
          (err: unknown) => {
            assert.ok(
              err instanceof GraphModelMismatchError,
              `expected GraphModelMismatchError, got ${String(err)}`,
            );
            assert.equal(err.existingModel, foreign);
            assert.equal(err.actualModel, DEFAULT_MODEL_NAME);
            return true;
          },
        );
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves the foreign cache byte-identical after the refusal', async () => {
    const foreign = '/Users/x/ThreatForest-internal/models/threatbert-embed-asym';
    const { dir, graphPath, stixPath } = seedCache(foreign);
    const { readFileSync } = await import('node:fs');
    const before = readFileSync(graphPath, 'utf8');
    try {
      await withModelDirAsync('attack-bert', async () => {
        await getOrBuildGraph({
          graphPath,
          stixBundlePath: stixPath,
          sourceName: 'mitre-attack',
          killChainName: 'mitre-attack',
        }).catch(() => undefined);
      });
      assert.equal(readFileSync(graphPath, 'utf8'), before, 'cache must not be modified');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** Async variant of withModelDir. */
async function withModelDirAsync(dirName: string, fn: () => Promise<void>): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), 'tf-embedder-guard-'));
  const modelDir = join(root, dirName);
  mkdirSync(join(modelDir, 'onnx'), { recursive: true });
  writeFileSync(join(modelDir, 'onnx', 'model.onnx'), 'not-a-real-onnx');
  const prev = process.env.TF_ATTACK_BERT_DIR;
  process.env.TF_ATTACK_BERT_DIR = modelDir;
  try {
    await fn();
  } finally {
    if (prev === undefined) delete process.env.TF_ATTACK_BERT_DIR;
    else process.env.TF_ATTACK_BERT_DIR = prev;
    rmSync(root, { recursive: true, force: true });
  }
}
