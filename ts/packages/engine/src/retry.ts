/**
 * Retry policy for transient Bedrock failures.
 *
 * WHY THIS EXISTS
 * ---------------
 * The Strands SDK already installs a retry strategy on every `Agent` when
 * `retryStrategy` is omitted (see `dist/src/agent/agent.js`, the ctor's
 * `config?.retryStrategy === undefined ? [new DefaultModelRetryStrategy()]`
 * branch). But `DefaultModelRetryStrategy.isRetryable` is exactly
 * `error instanceof ModelThrottledError` — and `BedrockModel.stream` only wraps
 * Bedrock's `throttlingException` into that type. Every other Bedrock stream
 * error (`internalServerException`, `serviceUnavailableException`,
 * `modelStreamErrorException`, ...) is thrown raw and fails that gate, so a
 * single transient service blip killed a whole pipeline stage with zero retries.
 *
 * Bedrock delivers those errors as events *inside* an already-200 streaming
 * response body, so the AWS SDK's own HTTP-level retry middleware never sees
 * them either. This strategy is the only layer that can retry them.
 *
 * THE NON-OBVIOUS PART — classify on the CAUSE CHAIN, not `error.name`
 * -------------------------------------------------------------------
 * `Model.streamAggregated` wraps its entire body in a try/catch and re-wraps any
 * non-`ModelError` into `new ModelError(message, { cause: error })`
 * (`dist/src/models/model.js`). `BedrockModel` does not override
 * `streamAggregated`, so that wrap ALWAYS applies. By the time a retry hook
 * runs, `error.name === 'ModelError'` and the real `InternalServerException` is
 * only reachable via `.cause`.
 *
 * A tempting `TRANSIENT.has(error.name)` check therefore evaluates
 * `has('ModelError')` → false on every single call: it compiles, ships, and
 * retries nothing. Walk `.cause` instead. See `retry.test.ts`, whose first case
 * fails against the `error.name` version and passes only with the walk.
 *
 * Equally, do NOT widen the gate to `instanceof ModelError`:
 * `ContextWindowOverflowError`, `MaxTokensError` and `ProviderTokenCountError`
 * all extend `ModelError`, and retrying a context-window overflow just burns
 * backoff on a request that can never succeed. Calling `super.isRetryable`
 * first keeps `ModelThrottledError` working (it reaches us unwrapped, being a
 * `ModelError` subclass) without pulling in its siblings.
 */
import { DefaultModelRetryStrategy } from '@strands-agents/sdk';

/**
 * Bedrock exceptions that are safe and useful to retry, matched on the AWS SDK
 * class `name` (PascalCase).
 *
 * Note the camelCase spellings that appear in `BedrockModel.stream`'s switch
 * (`internalServerException`, ...) are *stream event keys*, not error
 * identities — matching those would never fire.
 *
 * Classification follows the ConverseStream API's documented semantics:
 *  - InternalServerException      internal server error; AWS says retry
 *  - ServiceUnavailableException  service not currently available
 *  - ModelStreamErrorException    error mid-stream
 *  - ModelTimeoutException        exceeded the model timeout
 *  - ModelNotReadyException       not ready to serve; AWS SDKs auto-retry this
 *  - ThrottlingException          quota exceeded (the raw, unwrapped form)
 *
 * Deliberately absent, because retrying them is wrong rather than merely
 * unhelpful: ValidationException, AccessDeniedException, ConflictException,
 * ResourceNotFoundException and ServiceQuotaExceededException are all caller
 * errors that will fail identically on every attempt.
 *
 * `ModelErrorException` is also deliberately absent. It is a judgement call,
 * not an oversight: it signals the model failed while processing the request —
 * in this pipeline that has shown up as a streamed tool-input JSON that cannot
 * be parsed (see the mitigation agent's catch in `stages/parallel.ts`), which a
 * retry does not fix.
 *
 * Do not use `$fault` as the discriminator: `ModelTimeoutException` and
 * `ModelNotReadyException` are both marked `$fault: 'client'` despite being
 * plainly transient.
 */
const TRANSIENT_BEDROCK_ERRORS = new Set([
  'InternalServerException',
  'ServiceUnavailableException',
  'ModelStreamErrorException',
  'ModelTimeoutException',
  'ModelNotReadyException',
  'ThrottlingException',
]);

/**
 * Transport-level transients, matched on `error.code`. These surface when the
 * socket dies mid-stream rather than as a Bedrock event, and are just as
 * retryable.
 */
const TRANSIENT_CODES = new Set([
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
  'ECONNREFUSED',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
]);

/**
 * Transport transients matched on `error.name` instead of `code`.
 *
 * `TimeoutError` needs its own entry because the AWS HTTP/2 transport — the one
 * Bedrock uses — raises a bare `new Error(...)` with only `name` set and NO
 * `code`, unlike the HTTP/1 path which attaches `code: 'ETIMEDOUT'`. Matching
 * codes alone therefore misses exactly the timeout that truncates a
 * long-thinking Bedrock stream.
 */
const TRANSIENT_ERROR_NAMES = new Set(['TimeoutError']);

/** How far to follow `.cause` before giving up. Guards against cyclic causes. */
const MAX_CAUSE_DEPTH = 5;

/**
 * Total model attempts (so 3 retries) before the error is re-raised.
 *
 * Lower than the SDK's default of 6 on purpose: the strategy's backoff `sleep`
 * is not abortable, so a large attempt budget makes a user-requested stop
 * unresponsive for the duration of the remaining backoff. The failures this
 * targets recovered on a plain re-run, so a few attempts is ample.
 */
const MAX_ATTEMPTS = 4;

/**
 * Retries transient Bedrock and transport failures in addition to the throttling
 * the SDK already handles.
 */
export class TransientBedrockRetryStrategy extends DefaultModelRetryStrategy {
  /**
   * Distinct from the base class's `'strands:default-model-retry-strategy'`.
   * `name` is an inherited instance field and the plugin registry throws on
   * duplicate names, so leaving it inherited risks a collision if a
   * `DefaultModelRetryStrategy` is ever attached to the same agent.
   */
  override name = 'threatforest:transient-bedrock-retry-strategy';

  protected override isRetryable(error: Error): boolean {
    // Keeps ModelThrottledError (which arrives unwrapped) retryable without
    // also catching its ContextWindowOverflow / MaxTokens siblings.
    if (super.isRetryable(error)) return true;

    let current: unknown = error;
    for (let depth = 0; current instanceof Error && depth < MAX_CAUSE_DEPTH; depth++) {
      if (TRANSIENT_BEDROCK_ERRORS.has(current.name)) return true;
      if (TRANSIENT_ERROR_NAMES.has(current.name)) return true;
      const code = (current as { code?: unknown }).code;
      if (typeof code === 'string' && TRANSIENT_CODES.has(code)) return true;
      current = (current as { cause?: unknown }).cause;
    }
    return false;
  }
}

/**
 * Builds a retry strategy for a single `Agent`.
 *
 * Always call this per agent and never hoist the result to module scope:
 * strategy instances carry per-turn backoff state and the SDK throws
 * ("already attached to another agent") if one is shared. Inside a loop that
 * constructs an agent per iteration, call it inside the loop body.
 */
export function makeRetryStrategy(): TransientBedrockRetryStrategy {
  return new TransientBedrockRetryStrategy({ maxAttempts: MAX_ATTEMPTS });
}
