import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AgentNode } from '@strands-agents/sdk/multiagent';

import { Config, createRunEngineConfig } from './config.js';
import { MlServiceClient } from './ml-client.js';
import { buildGraph } from './pipeline/graph.js';
import { createModel } from './providers.js';

interface InspectableModel {
  getConfig(): Record<string, unknown>;
}

test('concurrent run configs construct isolated models without filesystem config', async () => {
  const first = createRunEngineConfig({
    provider: 'AWS Bedrock',
    modelId: 'global.anthropic.claude-sonnet-4-6',
    modelParameters: {
      temperature: 0.2,
      max_tokens: 12_345,
      top_p: 0.7,
      useNativeTokenCount: true,
    },
    embeddingsModel: 'embedding-model-a',
    awsRegion: 'eu-west-2',
  });
  const second = createRunEngineConfig({
    provider: 'bedrock',
    modelId: 'global.amazon.nova-2-lite-v1:0',
    modelParameters: {
      temperature: 0.8,
      maxTokens: 6_789,
      topP: 0.4,
      useNativeTokenCount: false,
    },
    embeddingsModel: 'embedding-model-b',
    awsRegion: 'us-east-1',
  });

  const [firstModel, secondModel] = (await Promise.all([
    createModel(first, { temperature: 0, maxTokens: 99 }),
    createModel(second, { temperature: 0, maxTokens: 99 }),
  ])) as unknown as [InspectableModel, InspectableModel];

  assert.deepEqual(firstModel.getConfig(), {
    modelId: 'global.anthropic.claude-sonnet-4-6',
    temperature: 0.2,
    maxTokens: 12_345,
    topP: 0.7,
    useNativeTokenCount: true,
    contextWindowLimit: 1_000_000,
  });
  assert.deepEqual(secondModel.getConfig(), {
    modelId: 'global.amazon.nova-2-lite-v1:0',
    temperature: 0.8,
    maxTokens: 6_789,
    topP: 0.4,
    useNativeTokenCount: false,
    contextWindowLimit: 1_000_000,
  });
  assert.equal(first.embeddingsModel, 'embedding-model-a');
  assert.equal(second.embeddingsModel, 'embedding-model-b');
  assert.deepEqual(first.modelParameters, {
    temperature: 0.2,
    max_tokens: 12_345,
    top_p: 0.7,
    useNativeTokenCount: true,
  });
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.modelParameters), true);
  assert.notEqual(first.bedrock, second.bedrock);
});

test('filesystem-backed Config remains valid for local callers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'threatforest-local-config-'));
  try {
    await mkdir(join(root, '.threatforest'));
    await writeFile(
      join(root, '.threatforest', 'config.yaml'),
      [
        'bedrock:',
        '  model_id: global.anthropic.claude-sonnet-4-6',
        '  max_tokens: 2345',
        'embeddings:',
        '  model: local-embedding-model',
        '',
      ].join('\n'),
    );
    const localConfig = new Config(root);
    const model = (await createModel(localConfig)) as unknown as InspectableModel;

    assert.equal(model.getConfig().modelId, 'global.anthropic.claude-sonnet-4-6');
    assert.equal(model.getConfig().maxTokens, 2345);
    assert.equal(localConfig.embeddingsModel, 'local-embedding-model');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('two graph builds retain their own model config through agent and HITL nodes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'threatforest-run-graphs-'));
  try {
    const firstConfig = createRunEngineConfig({
      provider: 'AWS Bedrock',
      modelId: 'global.anthropic.claude-sonnet-4-6',
      modelParameters: { maxTokens: 3333 },
      embeddingsModel: 'embedding-a',
      awsRegion: 'eu-west-2',
    });
    const secondConfig = createRunEngineConfig({
      provider: 'AWS Bedrock',
      modelId: 'global.amazon.nova-2-lite-v1:0',
      modelParameters: { maxTokens: 4444 },
      embeddingsModel: 'embedding-b',
      awsRegion: 'eu-west-2',
    });
    const firstRepo = join(root, 'first-source');
    const secondRepo = join(root, 'second-source');
    await Promise.all([mkdir(firstRepo), mkdir(secondRepo)]);

    const [firstGraph, secondGraph] = await Promise.all([
      buildGraph(firstRepo, {
        runDir: join(root, 'first-run'),
        engineConfig: firstConfig,
      }),
      buildGraph(secondRepo, {
        runDir: join(root, 'second-run'),
        engineConfig: secondConfig,
      }),
    ]);

    assert.deepEqual(await agentModelConfig(firstGraph.nodes.get('scanner')), {
      modelId: 'global.anthropic.claude-sonnet-4-6',
      maxTokens: 3333,
      temperature: 0,
      contextWindowLimit: 1_000_000,
    });
    assert.deepEqual(await agentModelConfig(secondGraph.nodes.get('scanner')), {
      modelId: 'global.amazon.nova-2-lite-v1:0',
      maxTokens: 4444,
      temperature: 0,
      contextWindowLimit: 1_000_000,
    });
    assert.equal(
      (firstGraph.nodes.get('threat_review') as unknown as {
        engineConfig: unknown;
      }).engineConfig,
      firstConfig,
    );
    assert.equal(
      (secondGraph.nodes.get('threat_review') as unknown as {
        engineConfig: unknown;
      }).engineConfig,
      secondConfig,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('ML client sends the per-run embedding model without changing endpoint resolution', async (t) => {
  const originalFetch = globalThis.fetch;
  const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
  globalThis.fetch = async (input, init) => {
    requests.push({
      url: String(input),
      body: JSON.parse(String(init?.body)) as Record<string, unknown>,
    });
    return new Response(JSON.stringify({ results: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const client = new MlServiceClient({ baseUrl: 'http://ml.internal:8770' });
  await client.matchSteps(['step'], {
    topK: 4,
    minSimilarity: 0.55,
    frameworks: ['attack'],
    embeddingsModel: 'selected/embedding-model',
  });

  assert.deepEqual(requests, [
    {
      url: 'http://ml.internal:8770/match_steps',
      body: {
        steps: ['step'],
        top_k: 4,
        min_similarity: 0.55,
        frameworks: ['attack'],
        embedding_model: 'selected/embedding-model',
      },
    },
  ]);
});

async function agentModelConfig(node: unknown): Promise<Record<string, unknown>> {
  assert.equal((node as { type: string }).type, 'lazyNode');
  node = await (node as { create(): Promise<unknown> }).create();
  assert.equal(node instanceof AgentNode, true);
  return (
    (node as AgentNode).agent as unknown as { model: InspectableModel }
  ).model.getConfig();
}
