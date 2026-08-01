/**
 * Tests for the transient-Bedrock retry policy.
 *
 * These deliberately drive a real `BedrockModel` and stub only the AWS client's
 * `send()`, so the error travels the same path it does in production:
 * `BedrockModel.stream` maps the in-band stream event and throws, then
 * `Model.streamAggregated` re-wraps it into a `ModelError` carrying the original
 * as `.cause`, and only then does the retry strategy see it.
 *
 * That wrap is the whole reason for this file. A unit test that called
 * `isRetryable(new InternalServerException(...))` directly would pass against a
 * naive `error.name` check — while the shipped code retried nothing. The first
 * test below fails against such an implementation and passes only when the
 * strategy walks the `.cause` chain.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { InternalServerException, ValidationException } from '@aws-sdk/client-bedrock-runtime';
import { Agent, BedrockModel, ConstantBackoff } from '@strands-agents/sdk';

import { TransientBedrockRetryStrategy } from './retry.js';

/** A minimal well-formed success stream. */
function successEvents(): Record<string, unknown>[] {
  return [
    { messageStart: { role: 'assistant' } },
    { contentBlockDelta: { delta: { text: 'ok' } } },
    { contentBlockStop: {} },
    { messageStop: { stopReason: 'end_turn' } },
  ];
}

/**
 * A real BedrockModel whose transport fails `failN` times with an in-band error
 * event on an otherwise-200 stream, then succeeds. Returns an attempt counter so
 * tests assert on how many model calls actually happened.
 */
function stubModel(
  failN: number,
  eventKey: string,
  makeError: () => Error,
): { model: BedrockModel; attempts: () => number } {
  const model = new BedrockModel({ modelId: 'test-model', region: 'us-east-1' });
  let calls = 0;

  const fakeClient = {
    send: async (): Promise<{ stream: AsyncGenerator<Record<string, unknown>> }> => {
      const attempt = ++calls;
      return {
        stream: (async function* () {
          yield { messageStart: { role: 'assistant' } };
          if (attempt <= failN) {
            yield { [eventKey]: makeError() };
            return;
          }
          for (const event of successEvents().slice(1)) yield event;
        })(),
      };
    },
  };
  (model as unknown as { _client: unknown })._client = fakeClient;

  return { model, attempts: () => calls };
}

/** Fast backoff so the tests do not actually sleep for seconds. */
function strategy(): TransientBedrockRetryStrategy {
  return new TransientBedrockRetryStrategy({
    maxAttempts: 4,
    backoff: new ConstantBackoff({ delayMs: 1 }),
  });
}

function bedrockError<T>(Ctor: new (opts: never) => T): () => T {
  return () => new Ctor({ message: 'synthetic transient failure', $metadata: {} } as never);
}

test('retries a mid-stream InternalServerException and recovers', async () => {
  const { model, attempts } = stubModel(
    2,
    'internalServerException',
    bedrockError(InternalServerException),
  );
  const agent = new Agent({ model, printer: false, retryStrategy: strategy() });

  await agent.invoke('hi');

  // 2 transient failures + 1 success. An `error.name`-based gate yields 1 here,
  // because the strategy sees a ModelError wrapper, not InternalServerException.
  assert.equal(attempts(), 3);
});

test('does not retry ValidationException — a caller error, not transient', async () => {
  const { model, attempts } = stubModel(99, 'validationException', bedrockError(ValidationException));
  const agent = new Agent({ model, printer: false, retryStrategy: strategy() });

  await assert.rejects(() => agent.invoke('hi'));

  // Fails fast rather than burning the whole attempt budget on a doomed request.
  assert.equal(attempts(), 1);
});

test('gives up after maxAttempts when the transient never clears', async () => {
  const { model, attempts } = stubModel(
    99,
    'internalServerException',
    bedrockError(InternalServerException),
  );
  const agent = new Agent({ model, printer: false, retryStrategy: strategy() });

  await assert.rejects(() => agent.invoke('hi'));

  assert.equal(attempts(), 4);
});

test('retries a transport-level reset surfaced via error.code', async () => {
  const model = new BedrockModel({ modelId: 'test-model', region: 'us-east-1' });
  let calls = 0;
  (model as unknown as { _client: unknown })._client = {
    send: async (): Promise<{ stream: AsyncGenerator<Record<string, unknown>> }> => {
      const attempt = ++calls;
      if (attempt <= 2) {
        const inner: Error & { code?: string } = new Error('socket hang up');
        inner.code = 'ECONNRESET';
        throw new TypeError('fetch failed', { cause: inner });
      }
      return {
        stream: (async function* () {
          for (const event of successEvents()) yield event;
        })(),
      };
    },
  };

  const agent = new Agent({ model, printer: false, retryStrategy: strategy() });
  await agent.invoke('hi');

  assert.equal(calls, 3);
});

test('retries the HTTP/2 stream-inactivity TimeoutError, which carries no error.code', async () => {
  // Regression guard: Bedrock runs over HTTP/2, and that transport raises a bare
  // `new Error(...)` with only `name = 'TimeoutError'` — no `code` — unlike the
  // HTTP/1 path which sets code ETIMEDOUT. A code-only gate misses it, and this
  // is precisely the error that truncates a long-thinking stream (surfacing as
  // the opaque "Stream ended without completing a message").
  const model = new BedrockModel({ modelId: 'test-model', region: 'us-east-1' });
  let calls = 0;
  (model as unknown as { _client: unknown })._client = {
    send: async (): Promise<{ stream: AsyncGenerator<Record<string, unknown>> }> => {
      const attempt = ++calls;
      if (attempt <= 2) {
        const timeout = new Error('Stream timed out because of no activity for 120000 ms');
        timeout.name = 'TimeoutError';
        assert.equal((timeout as { code?: string }).code, undefined, 'h2 timeout has no code');
        throw timeout;
      }
      return {
        stream: (async function* () {
          for (const event of successEvents()) yield event;
        })(),
      };
    },
  };

  const agent = new Agent({ model, printer: false, retryStrategy: strategy() });
  await agent.invoke('hi');

  assert.equal(calls, 3);
});

test('a strategy instance cannot be shared across agents', async () => {
  // Guards the makeRetryStrategy()-per-agent contract: the SDK throws if one
  // instance is attached to a second agent, so hoisting it would break at runtime.
  const shared = strategy();
  const a = stubModel(0, 'internalServerException', bedrockError(InternalServerException));
  const b = stubModel(0, 'internalServerException', bedrockError(InternalServerException));

  const first = new Agent({ model: a.model, printer: false, retryStrategy: shared });
  await first.invoke('hi');

  const second = new Agent({ model: b.model, printer: false, retryStrategy: shared });
  await assert.rejects(() => second.invoke('hi'), /already attached to another agent/);
});
