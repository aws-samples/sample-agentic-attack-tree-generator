/**
 * Tests for live Bedrock model discovery.
 *
 * These stub the catalogue client rather than calling AWS, so they run offline
 * and assert the merge/filter/fallback rules that are easy to get wrong:
 *  - cross-region profile ids (`global.*`) survive, since they exist ONLY in
 *    ListInferenceProfiles and are what the pipeline actually invokes;
 *  - base ids that are not ON_DEMAND are dropped (they 400 if invoked directly);
 *  - profiles inherit lifecycle from their base model, because the profile API
 *    omits it and an un-inherited `global.*` id would never warn about EOL;
 *  - a total API failure degrades to the static list instead of an empty
 *    dropdown, and a partial failure still returns live results.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import type {
  FoundationModelSummary,
  InferenceProfileSummary,
} from '@aws-sdk/client-bedrock';

import { discoverBedrockModels, type BedrockCatalogueClient } from './bedrock-models.js';

function fm(over: Partial<FoundationModelSummary> = {}): FoundationModelSummary {
  return {
    modelId: 'anthropic.claude-opus-4-8',
    modelName: 'Claude Opus 4.8',
    providerName: 'Anthropic',
    outputModalities: ['TEXT'],
    inferenceTypesSupported: ['ON_DEMAND'],
    ...over,
  } as FoundationModelSummary;
}

function ip(over: Partial<InferenceProfileSummary> = {}): InferenceProfileSummary {
  return {
    inferenceProfileId: 'global.anthropic.claude-opus-4-8',
    inferenceProfileName: 'Claude Opus 4.8',
    status: 'ACTIVE',
    ...over,
  } as InferenceProfileSummary;
}

function client(
  models: FoundationModelSummary[],
  profiles: InferenceProfileSummary[],
): BedrockCatalogueClient {
  return {
    listFoundationModels: async () => models,
    listInferenceProfiles: async () => profiles,
  };
}

test('keeps cross-region profile ids that ListFoundationModels never returns', async () => {
  // The real-world trap: query only foundation models and every `global.*` id
  // — i.e. everything ThreatForest is configured with — disappears.
  const res = await discoverBedrockModels('us-west-2', client([fm()], [ip()]));

  assert.equal(res.source, 'live');
  const ids = res.models.map((m) => m.id);
  assert.ok(ids.includes('global.anthropic.claude-opus-4-8'), 'profile id must survive');
  assert.ok(ids.includes('anthropic.claude-opus-4-8'), 'base id must survive');
  const profile = res.models.find((m) => m.id === 'global.anthropic.claude-opus-4-8');
  assert.equal(profile?.is_inference_profile, true);
});

test('drops base models that are not ON_DEMAND invocable', async () => {
  // INFERENCE_PROFILE-only ids fail if invoked directly, so offering them would
  // hand the user an id that always errors.
  //
  // The cast is deliberate: the live API returns "INFERENCE_PROFILE" in
  // `inferenceTypesSupported` (verified against us-west-2 for
  // anthropic.claude-opus-4-8), but the SDK's `InferenceType` union only lists
  // ON_DEMAND | PROVISIONED — its types lag the service. Production code
  // compares the raw string, so it behaves correctly; only this fixture needs
  // to step around the stale type.
  const res = await discoverBedrockModels(
    'us-west-2',
    client(
      [fm({ inferenceTypesSupported: ['INFERENCE_PROFILE' as unknown as 'ON_DEMAND'] })],
      [ip()],
    ),
  );

  assert.deepEqual(
    res.models.map((m) => m.id),
    ['global.anthropic.claude-opus-4-8'],
  );
});

test('drops models with no TEXT output', async () => {
  const res = await discoverBedrockModels(
    'us-west-2',
    client([fm({ modelId: 'amazon.titan-image', outputModalities: ['IMAGE'] })], []),
  );

  // No text models at all → fallback, since an empty dropdown is unusable.
  assert.equal(res.source, 'fallback');
});

test('profiles inherit LEGACY lifecycle and EOL from their base model', async () => {
  const res = await discoverBedrockModels(
    'us-west-2',
    client(
      [
        fm({
          modelId: 'anthropic.claude-sonnet-4-20250514-v1:0',
          modelLifecycle: {
            status: 'LEGACY',
            endOfLifeTime: new Date('2026-10-14T08:00:00Z'),
          },
        }),
      ],
      [ip({ inferenceProfileId: 'global.anthropic.claude-sonnet-4-20250514-v1:0' })],
    ),
  );

  const profile = res.models.find(
    (m) => m.id === 'global.anthropic.claude-sonnet-4-20250514-v1:0',
  );
  // Without inheritance this is UNKNOWN and the UI never warns — the id the
  // pipeline actually runs on would silently pass its EOL.
  assert.equal(profile?.lifecycle, 'LEGACY');
  assert.equal(profile?.end_of_life, '2026-10-14T08:00:00.000Z');
});

test('skips inference profiles that are not ACTIVE', async () => {
  // Same stale-type situation as above: the SDK narrows `status` to the literal
  // 'ACTIVE', so a non-active fixture needs a cast to be expressible at all.
  const res = await discoverBedrockModels(
    'us-west-2',
    client([], [ip({ status: 'INACTIVE' as unknown as 'ACTIVE' })]),
  );

  assert.equal(res.source, 'fallback', 'nothing invocable → fallback');
});

test('falls back to the static list when both APIs fail', async () => {
  const res = await discoverBedrockModels('us-west-2', {
    listFoundationModels: async () => {
      throw new Error('AccessDeniedException: not authorized');
    },
    listInferenceProfiles: async () => {
      throw new Error('AccessDeniedException: not authorized');
    },
  });

  assert.equal(res.source, 'fallback');
  assert.ok(res.models.length > 0, 'must never hand the UI an empty list');
  assert.match(res.warning ?? '', /not authorized/);
  // The fallback must still offer the ids the pipeline is configured with.
  assert.ok(res.models.some((m) => m.id === 'global.anthropic.claude-opus-4-8'));
});

test('a partial failure still returns live results, with a warning', async () => {
  const res = await discoverBedrockModels('us-west-2', {
    listFoundationModels: async () => {
      throw new Error('throttled');
    },
    listInferenceProfiles: async () => [ip()],
  });

  // A dropdown missing the base-model tail beats no dropdown.
  assert.equal(res.source, 'live');
  assert.deepEqual(
    res.models.map((m) => m.id),
    ['global.anthropic.claude-opus-4-8'],
  );
  assert.match(res.warning ?? '', /base foundation models/);
});

test('flags Anthropic and Amazon as recommended, others not', async () => {
  const res = await discoverBedrockModels(
    'us-west-2',
    client(
      [
        fm(),
        fm({ modelId: 'qwen.qwen3-32b-v1:0', modelName: 'Qwen3 32B', providerName: 'Qwen' }),
        fm({ modelId: 'amazon.nova-lite-v1:0', modelName: 'Nova Lite', providerName: 'Amazon' }),
      ],
      [],
    ),
  );

  const byId = new Map(res.models.map((m) => [m.id, m]));
  assert.equal(byId.get('anthropic.claude-opus-4-8')?.recommended, true);
  assert.equal(byId.get('amazon.nova-lite-v1:0')?.recommended, true);
  assert.equal(byId.get('qwen.qwen3-32b-v1:0')?.recommended, false);
  // Recommended models sort ahead of the rest.
  assert.notEqual(res.models[res.models.length - 1]?.id, 'anthropic.claude-opus-4-8');
});

test('derives a readable label when AWS supplies no model name', async () => {
  const res = await discoverBedrockModels(
    'us-west-2',
    client([], [ip({ inferenceProfileName: undefined })]),
  );

  // Date stamps and version suffixes are stripped; scope is kept as a hint.
  assert.equal(res.models[0]?.label, 'Claude Opus 4 8 (global)');
});
