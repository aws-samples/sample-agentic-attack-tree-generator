/**
 * Tests for `temperature` compatibility handling.
 *
 * The predicate cases below are not guesses — each expectation was measured
 * against live Bedrock (us-west-2) with a minimal Converse call carrying
 * `temperature: 0`, on 2026-07-27.
 *
 * The fallback tests drive a real BedrockModel with a stubbed transport so the
 * error travels the true path (BedrockModel.stream -> Model.streamAggregated
 * re-wrap), which is what makes the cause-chain walk in isTemperatureRejection
 * load-bearing.
 */
import assert from 'node:assert/strict';
import { test, beforeEach } from 'node:test';

import {
  TemperatureFallbackBedrockModel,
  hasObservedTemperatureDeprecation,
  isTemperatureRejection,
  modelDeprecatesTemperature,
  resetObservedTemperatureDeprecations,
} from './temperature.js';

beforeEach(() => resetObservedTemperatureDeprecations());

// --- predicate ---------------------------------------------------------------

test('rejects temperature for Opus 4.7+ minors', () => {
  for (const id of [
    'global.anthropic.claude-opus-4-7',
    'global.anthropic.claude-opus-4-8',
    'us.anthropic.claude-opus-4-8',
    'anthropic.claude-opus-4-10', // hypothetical future minor
  ]) {
    assert.equal(modelDeprecatesTemperature(id), true, id);
  }
});

test('rejects temperature for the Claude 5 family — the case that broke', () => {
  // Measured: all three reject `temperature` on Bedrock. The previous
  // `claude-opus-4-(\d)` regex matched NONE of them, so temperature was sent
  // and every scan died in <1s the moment these became selectable.
  for (const id of [
    'global.anthropic.claude-opus-5',
    'global.anthropic.claude-sonnet-5',
    'global.anthropic.claude-fable-5',
    'us.anthropic.claude-opus-5',
  ]) {
    assert.equal(modelDeprecatesTemperature(id), true, id);
  }
});

test('still sends temperature to models that accept it', () => {
  // Measured as ACCEPTING temperature — a false positive here would silently
  // break determinism, which the pipeline depends on (temperature=0).
  for (const id of [
    'global.anthropic.claude-sonnet-4-6',
    'global.anthropic.claude-opus-4-6-v1',
    'global.anthropic.claude-opus-4-5-20251101-v1:0',
    'global.anthropic.claude-haiku-4-5-20251001-v1:0',
    'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
    'global.amazon.nova-2-lite-v1:0',
  ]) {
    assert.equal(modelDeprecatesTemperature(id), false, id);
  }
});

test('does not read a date suffix as a version', () => {
  // `…opus-4-20250514…` is Opus 4.0 with a date stamp, NOT minor 20250514.
  assert.equal(
    modelDeprecatesTemperature('global.anthropic.claude-sonnet-4-20250514-v1:0'),
    false,
  );
  assert.equal(modelDeprecatesTemperature('anthropic.claude-3-sonnet-20240229-v1:0'), false);
});

test('covers a future major without a code change', () => {
  assert.equal(modelDeprecatesTemperature('global.anthropic.claude-opus-6'), true);
  assert.equal(modelDeprecatesTemperature('global.anthropic.claude-newfamily-7'), true);
});

// --- error classification ----------------------------------------------------

test('recognises the Bedrock temperature rejection, including nested in a cause', () => {
  const raw = new Error(
    'The model returned the following errors: `temperature` is deprecated for this model.',
  );
  assert.equal(isTemperatureRejection(raw), true);
  // The SDK re-wraps provider errors, so the text is usually one level down.
  assert.equal(isTemperatureRejection(new Error('model error', { cause: raw })), true);
});

test('does not mistake unrelated errors for a temperature rejection', () => {
  for (const msg of [
    'ThrottlingException: Too many requests',
    'The system encountered an unexpected error during processing.',
    'Input is too long for requested model',
    'topP is deprecated for this model', // different parameter
  ]) {
    assert.equal(isTemperatureRejection(new Error(msg)), false, msg);
  }
});

// --- runtime fallback --------------------------------------------------------

/** Stub the AWS client so the first N sends fail with the real rejection. */
function stubModel(
  model: TemperatureFallbackBedrockModel,
  failWhile: (attempt: number) => boolean,
): { sentTemperatures: (number | undefined)[] } {
  const sentTemperatures: (number | undefined)[] = [];
  let attempt = 0;
  (model as unknown as { _client: unknown })._client = {
    send: async (command: { input?: { inferenceConfig?: { temperature?: number } } }) => {
      attempt += 1;
      sentTemperatures.push(command.input?.inferenceConfig?.temperature);
      if (failWhile(attempt)) {
        throw new Error(
          'The model returned the following errors: `temperature` is deprecated for this model.',
        );
      }
      return {
        stream: (async function* () {
          yield { messageStart: { role: 'assistant' } };
          yield { contentBlockDelta: { delta: { text: 'ok' } } };
          yield { contentBlockStop: {} };
          yield { messageStop: { stopReason: 'end_turn' } };
        })(),
      };
    },
  };
  return { sentTemperatures };
}

const HELLO = [
  { type: 'message', role: 'user', content: [{ type: 'textBlock', text: 'hi' }] },
] as unknown as Parameters<TemperatureFallbackBedrockModel['stream']>[0];

test('drops temperature and retries when an unpredicted model rejects it', async () => {
  // Simulates the exact regression: a model the predicate thinks is fine.
  const model = new TemperatureFallbackBedrockModel({
    modelId: 'anthropic.claude-unknown-future',
    region: 'us-east-1',
    temperature: 0,
  });
  const { sentTemperatures } = stubModel(model, (n) => n === 1);

  const events = [];
  for await (const e of model.stream(HELLO)) events.push(e);

  assert.ok(events.length > 0, 'must recover and produce events');
  assert.deepEqual(sentTemperatures, [0, undefined], 'retry must omit temperature');
  assert.equal(model.getConfig().temperature, undefined, 'config updated for later calls');
  assert.equal(
    hasObservedTemperatureDeprecation('anthropic.claude-unknown-future'),
    true,
    'observation cached so other agents skip the probe',
  );
});

test('does not retry when the rejection persists', async () => {
  const model = new TemperatureFallbackBedrockModel({
    modelId: 'anthropic.claude-unknown-future',
    region: 'us-east-1',
    temperature: 0,
  });
  const { sentTemperatures } = stubModel(model, () => true);

  await assert.rejects(async () => {
    for await (const _ of model.stream(HELLO)) void _;
  }, /temperature/);

  // Exactly one retry — no unbounded loop.
  assert.equal(sentTemperatures.length, 2);
});

test('does not retry when temperature was never sent', async () => {
  const model = new TemperatureFallbackBedrockModel({
    modelId: 'anthropic.claude-unknown-future',
    region: 'us-east-1',
  });
  const { sentTemperatures } = stubModel(model, () => true);

  await assert.rejects(async () => {
    for await (const _ of model.stream(HELLO)) void _;
  });

  // Nothing to fix, so retrying would just waste a call.
  assert.equal(sentTemperatures.length, 1);
});

test('passes non-temperature errors straight through', async () => {
  const model = new TemperatureFallbackBedrockModel({
    modelId: 'anthropic.claude-unknown-future',
    region: 'us-east-1',
    temperature: 0,
  });
  let attempts = 0;
  (model as unknown as { _client: unknown })._client = {
    send: async () => {
      attempts += 1;
      throw new Error('ThrottlingException: slow down');
    },
  };

  await assert.rejects(async () => {
    for await (const _ of model.stream(HELLO)) void _;
  }, /Throttling/);
  assert.equal(attempts, 1, 'must not swallow or retry unrelated failures');
});

test('a predicted model never sends temperature in the first place', async () => {
  // No probe call is wasted for the families we already know about.
  const model = new TemperatureFallbackBedrockModel({
    modelId: 'global.anthropic.claude-opus-5',
    region: 'us-east-1',
    // providers.ts omits temperature for this id, so it is absent here too.
  });
  const { sentTemperatures } = stubModel(model, () => false);

  for await (const _ of model.stream(HELLO)) void _;

  assert.deepEqual(sentTemperatures, [undefined]);
});
