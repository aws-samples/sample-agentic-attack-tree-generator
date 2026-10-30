/**
 * Model provider factory — TS analog of
 * `src/threatforest/modules/core/providers/provider_factory.py`.
 *
 * Detection order mirrors the Python (first configured block wins), but only the
 * four SDK-native providers are supported: Bedrock, Anthropic, OpenAI, Gemini.
 * The legacy Ollama / LiteLLM / SageMaker / LlamaAPI blocks are intentionally
 * unsupported here (see plan "Known bounded gaps"); Ollama/LiteLLM can still be
 * reached by pointing the OpenAI block at their OpenAI-compatible endpoint.
 *
 * Bedrock auth note (from the WS-0 spike): an empty/stale AWS_BEARER_TOKEN_BEDROCK
 * in the env makes the AWS SDK pick bearer auth and fail signing ("request could
 * not be signed with `token`"). An EMPTY value is never a usable credential, so
 * we proactively delete it from the process env before constructing the Bedrock
 * client, forcing SigV4. A non-empty value is left untouched (it may be a real
 * bearer token the user intends to use).
 */
import { type Model } from '@strands-agents/sdk';
import type { EngineConfigSource, ProviderBlock } from './config.js';
import {
  TemperatureFallbackBedrockModel,
  hasObservedTemperatureDeprecation,
  modelDeprecatesTemperature,
} from './temperature.js';

export type SupportedProvider = 'bedrock' | 'anthropic' | 'openai' | 'gemini';

export interface CreateModelOptions {
  temperature?: number;
  maxTokens?: number;
}

interface NormalizedModelParameters {
  temperature: number | undefined;
  maxTokens: number | undefined;
  topP: number | undefined;
  contextWindowLimit: number | undefined;
  extra: Record<string, unknown>;
}

const NORMALIZED_PARAMETER_KEYS = new Set([
  'model_id',
  'modelId',
  'temperature',
  'max_tokens',
  'maxTokens',
  'top_p',
  'topP',
  'context_window_limit',
  'contextWindowLimit',
]);

function optionalNumber(
  block: Readonly<ProviderBlock>,
  keys: readonly string[],
): number | undefined {
  for (const key of keys) {
    const value = block[key];
    if (value === undefined) continue;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error(`Model parameter ${JSON.stringify(key)} must be a finite number`);
    }
    return value;
  }
  return undefined;
}

function normalizeModelParameters(
  block: Readonly<ProviderBlock>,
): NormalizedModelParameters {
  const extra: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(block)) {
    if (!NORMALIZED_PARAMETER_KEYS.has(key)) extra[key] = value;
  }
  return {
    temperature: optionalNumber(block, ['temperature']),
    maxTokens: optionalNumber(block, ['maxTokens', 'max_tokens']),
    topP: optionalNumber(block, ['topP', 'top_p']),
    contextWindowLimit: optionalNumber(block, [
      'contextWindowLimit',
      'context_window_limit',
    ]),
    extra,
  };
}

/**
 * Per-request inactivity budget for Bedrock streaming calls, in ms.
 *
 * The SDK defaults this to 120s. Bedrock runs over HTTP/2, where the AWS
 * transport turns `requestTimeout` into `clientHttp2Stream.setTimeout` — an
 * INACTIVITY timer, i.e. the gap allowed between streamed chunks, not a cap on
 * total call duration.
 *
 * That default is too tight for this pipeline. The agents send large system
 * prompts and ask for long structured outputs, and a strong reasoning model can
 * legitimately go quiet for minutes before its first content chunk while it
 * thinks. Measured on the scanner agent with claude-opus-5: one call streamed
 * happily for 286s (max gap 1.4s) while another emitted 5 chunks and then went
 * silent past 120s. The transport `close()`d that stream, so it ended with no
 * `messageStop` and the SDK raised the maddeningly generic "Stream ended without
 * completing a message" — with the underlying TimeoutError swallowed.
 *
 * 15 minutes of *silence* is far beyond any healthy call (the observed worst gap
 * was ~1.4s) while still bounding a genuinely hung connection.
 */
const BEDROCK_STREAM_INACTIVITY_TIMEOUT_MS = 900_000;

function bedrockAuthSanityHint(): void {
  const bearer = process.env.AWS_BEARER_TOKEN_BEDROCK;
  // An empty (set-but-blank) bearer var is the common footgun: a launcher or
  // shell rc exports `AWS_BEARER_TOKEN_BEDROCK=` and the AWS SDK then prefers
  // (empty) bearer auth over valid SigV4 role/SSO creds, so EVERY Bedrock call
  // fails to sign. An empty string can't authenticate anything, so deleting it
  // is always safe and lets SigV4 resolve normally. Do this unconditionally for
  // the empty case (don't gate on detecting SigV4 creds — role/SSO setups don't
  // always expose AWS_ACCESS_KEY_ID/AWS_PROFILE in the env).
  if (bearer !== undefined && bearer.trim() === '') {
    delete process.env.AWS_BEARER_TOKEN_BEDROCK;
    // eslint-disable-next-line no-console
    console.warn(
      '[providers] AWS_BEARER_TOKEN_BEDROCK was set but empty — removed it so Bedrock ' +
        'uses SigV4 (an empty value can never authenticate and otherwise breaks signing).',
    );
  }
}

/**
 * Whether to send `temperature` for a model id.
 *
 * Combines the known-families predicate with any incompatibility already
 * observed at runtime in this process, so once one agent discovers a model
 * rejects temperature, every later agent omits it on the first call. See
 * temperature.ts for why this is a fast path rather than the source of truth.
 */
function shouldSendTemperature(modelId: string): boolean {
  return !modelDeprecatesTemperature(modelId) && !hasObservedTemperatureDeprecation(modelId);
}

/**
 * Create the configured Strands model. Currently always returns a BedrockModel
 * unless a non-Bedrock provider block is the first one configured, in which case
 * the caller must have the matching peer dep installed and we lazy-load it.
 */
export async function createModel(
  config: EngineConfigSource,
  opts: CreateModelOptions = {},
): Promise<Model> {
  // Default output-token budget. The legacy Python Bedrock provider allowed very
  // large outputs (up to 65_536 for opus-4-7); a 4096 default was far too small
  // and made the mitigation agent's large `store_mitigations` tool-call JSON hit
  // "Model reached maximum token limit" mid-call. 32k is a safe headroom for the
  // structured tool outputs in this pipeline without pinning the absolute max.
  if (config.bedrock?.model_id) {
    bedrockAuthSanityHint();
    const modelId = config.bedrock.model_id;
    const parameters = normalizeModelParameters(config.bedrock);
    const temperature = parameters.temperature ?? opts.temperature ?? 0;
    const maxTokens = parameters.maxTokens ?? opts.maxTokens ?? 32_768;
    // Newer Claude models reject a request carrying `temperature`, which kills
    // the scanner agent on its first call and fails the whole run in <1s. The
    // predicate skips it for families we know about; the model subclass catches
    // the rejection and retries without it for any model we did not predict, so
    // a future release cannot reintroduce the instant-failure bug. See
    // temperature.ts.
    return new TemperatureFallbackBedrockModel({
      ...parameters.extra,
      modelId,
      region: config.awsRegion,
      ...(shouldSendTemperature(modelId) ? { temperature } : {}),
      maxTokens,
      ...(parameters.topP === undefined ? {} : { topP: parameters.topP }),
      ...(parameters.contextWindowLimit === undefined
        ? {}
        : { contextWindowLimit: parameters.contextWindowLimit }),
      clientConfig: {
        // Raise the inter-chunk inactivity budget above the SDK's 120s default,
        // which silently truncates long-thinking streams. See the constant.
        requestHandler: { requestTimeout: BEDROCK_STREAM_INACTIVITY_TIMEOUT_MS },
      },
    });
  }

  if (config.anthropic?.model_id) {
    const { AnthropicModel } = await import('@strands-agents/sdk/models/anthropic');
    const modelId = config.anthropic.model_id;
    const parameters = normalizeModelParameters(config.anthropic);
    const temperature = parameters.temperature ?? opts.temperature ?? 0;
    const maxTokens = parameters.maxTokens ?? opts.maxTokens ?? 32_768;
    // Use the configured sampling preference when supported. Stable metadata
    // comes from the storage contract; temperature does not guarantee identical
    // analysis content across invocations or providers. The newer
    // Claude models deprecate `temperature` over the Anthropic API too (same
    // model behaviour as Bedrock), so reuse the same predicate. NOTE: only the
    // Bedrock path has the retry-without-temperature safety net; here an
    // unpredicted model still fails, since AnthropicModel is a lazily-imported
    // peer dep this package does not subclass.
    const supportsTemperature = shouldSendTemperature(modelId);
    return new AnthropicModel({
      ...parameters.extra,
      modelId,
      maxTokens,
      ...(supportsTemperature ? { temperature } : {}),
      ...(parameters.topP === undefined ? {} : { topP: parameters.topP }),
      ...(parameters.contextWindowLimit === undefined
        ? {}
        : { contextWindowLimit: parameters.contextWindowLimit }),
    }) as unknown as Model;
  }

  if (config.openai?.model_id) {
    const { OpenAIModel } = await import('@strands-agents/sdk/models/openai');
    const parameters = normalizeModelParameters(config.openai);
    const temperature = parameters.temperature ?? opts.temperature ?? 0;
    const maxTokens = parameters.maxTokens ?? opts.maxTokens ?? 32_768;
    return new OpenAIModel({
      ...parameters.extra,
      modelId: config.openai.model_id,
      maxTokens,
      temperature,
      ...(parameters.topP === undefined ? {} : { topP: parameters.topP }),
      ...(parameters.contextWindowLimit === undefined
        ? {}
        : { contextWindowLimit: parameters.contextWindowLimit }),
    }) as unknown as Model;
  }

  if (config.gemini?.model_id) {
    const { GoogleModel } = await import('@strands-agents/sdk/models/google');
    const parameters = normalizeModelParameters(config.gemini);
    const temperature = parameters.temperature ?? opts.temperature ?? 0;
    const maxTokens = parameters.maxTokens ?? opts.maxTokens ?? 32_768;
    // Gemini takes generation params via `params`, not a top-level field.
    return new GoogleModel({
      modelId: config.gemini.model_id,
      params: {
        ...parameters.extra,
        temperature,
        maxOutputTokens: maxTokens,
        ...(parameters.topP === undefined ? {} : { topP: parameters.topP }),
      },
      ...(parameters.contextWindowLimit === undefined
        ? {}
        : { contextWindowLimit: parameters.contextWindowLimit }),
    }) as unknown as Model;
  }

  throw new Error(
    'No supported model provider configured. ThreatForest TS supports bedrock, anthropic, ' +
      'openai, or gemini blocks in .threatforest/config.yaml. (Ollama/LiteLLM: point the ' +
      'openai block at their OpenAI-compatible endpoint.)',
  );
}

/** The active provider name, for display/logging (mirrors default_bedrock_model intent). */
export function activeProvider(config: EngineConfigSource): SupportedProvider | null {
  if (config.bedrock?.model_id) return 'bedrock';
  if (config.anthropic?.model_id) return 'anthropic';
  if (config.openai?.model_id) return 'openai';
  if (config.gemini?.model_id) return 'gemini';
  return null;
}
