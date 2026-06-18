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
 * in the env makes the AWS SDK pick bearer auth and fail signing. We surface a
 * clear hint rather than letting the cryptic signer error surface at first call.
 */
import { BedrockModel, type Model } from '@strands-agents/sdk';
import type { Config } from './config.js';

export type SupportedProvider = 'bedrock' | 'anthropic' | 'openai' | 'gemini';

export interface CreateModelOptions {
  temperature?: number;
  maxTokens?: number;
}

function bedrockAuthSanityHint(): void {
  const bearer = process.env.AWS_BEARER_TOKEN_BEDROCK;
  const hasSigv4 = !!process.env.AWS_ACCESS_KEY_ID || !!process.env.AWS_PROFILE;
  if (bearer !== undefined && bearer.trim() === '' && hasSigv4) {
    // The SDK would otherwise pick (empty) bearer auth over valid SigV4 creds.
    // eslint-disable-next-line no-console
    console.warn(
      '[providers] AWS_BEARER_TOKEN_BEDROCK is set but empty while SigV4 creds exist — ' +
        'unset it to force SigV4 (otherwise Bedrock signing fails with a "token is not defined" error).',
    );
  }
}

/**
 * Whether a Bedrock model id deprecates the `temperature` parameter.
 *
 * Anthropic's Claude Opus 4.7 onward reject any request carrying `temperature`
 * ("`temperature` is deprecated for this model"). Parse the `opus-4-<minor>`
 * version out of the model id and treat minor ≥ 7 as deprecating it, so future
 * minors (4.9, 4.10, …) are covered without a code change. Non-Opus families
 * (Sonnet/Haiku) and Opus ≤ 4.6 still accept temperature.
 */
function modelDeprecatesTemperature(modelId: string): boolean {
  // Capture the 1–2 digit minor, NOT followed by another digit, so a
  // date-suffixed base id (…opus-4-20250514…, Opus 4.0) doesn't parse the date
  // as the minor. Matches …opus-4-7, …opus-4-8, …opus-4-8-<date>, …opus-4-1-…
  const m = /claude-opus-4-(\d{1,2})(?!\d)/.exec(modelId);
  if (!m) return false;
  return Number(m[1]) >= 7;
}

/**
 * Create the configured Strands model. Currently always returns a BedrockModel
 * unless a non-Bedrock provider block is the first one configured, in which case
 * the caller must have the matching peer dep installed and we lazy-load it.
 */
export async function createModel(config: Config, opts: CreateModelOptions = {}): Promise<Model> {
  const temperature = opts.temperature ?? 0;
  // Default output-token budget. The legacy Python Bedrock provider allowed very
  // large outputs (up to 65_536 for opus-4-7); a 4096 default was far too small
  // and made the mitigation agent's large `store_mitigations` tool-call JSON hit
  // "Model reached maximum token limit" mid-call. 32k is a safe headroom for the
  // structured tool outputs in this pipeline without pinning the absolute max.
  const maxTokens = opts.maxTokens ?? 32_768;

  if (config.bedrock?.model_id) {
    bedrockAuthSanityHint();
    const modelId = config.bedrock.model_id;
    // Claude Opus 4.7+ deprecate the `temperature` parameter — Bedrock rejects
    // a request that carries it ("`temperature` is deprecated for this model"),
    // which otherwise kills the scanner agent on the first call and fails the
    // whole run in <1s. Omit temperature for Opus 4.7 and any later 4.x minor
    // (4.8, 4.9, 4.10, …). Sonnet/Haiku and Opus ≤4.6 still accept it.
    const supportsTemperature = !modelDeprecatesTemperature(modelId);
    return new BedrockModel({
      modelId,
      region: config.awsRegion,
      ...(supportsTemperature ? { temperature } : {}),
      maxTokens,
    });
  }

  if (config.anthropic?.model_id) {
    const { AnthropicModel } = await import('@strands-agents/sdk/models/anthropic');
    const modelId = config.anthropic.model_id;
    // The whole pipeline depends on temperature=0 for deterministic, reproducible
    // threat models; omitting it here let the SDK default (~1.0) through, silently
    // breaking determinism + Python parity for the Anthropic provider. Claude
    // Opus 4.7+ deprecate `temperature` over the Anthropic API too (same model
    // behaviour as Bedrock), so reuse the same guard.
    const supportsTemperature = !modelDeprecatesTemperature(modelId);
    return new AnthropicModel({
      modelId,
      maxTokens,
      ...(supportsTemperature ? { temperature } : {}),
    }) as unknown as Model;
  }

  if (config.openai?.model_id) {
    const { OpenAIModel } = await import('@strands-agents/sdk/models/openai');
    return new OpenAIModel({
      modelId: config.openai.model_id,
      maxTokens,
      temperature,
    }) as unknown as Model;
  }

  if (config.gemini?.model_id) {
    const { GoogleModel } = await import('@strands-agents/sdk/models/google');
    // Gemini takes generation params via `params`, not a top-level field.
    return new GoogleModel({
      modelId: config.gemini.model_id,
      params: { temperature },
    }) as unknown as Model;
  }

  throw new Error(
    'No supported model provider configured. ThreatForest TS supports bedrock, anthropic, ' +
      'openai, or gemini blocks in .threatforest/config.yaml. (Ollama/LiteLLM: point the ' +
      'openai block at their OpenAI-compatible endpoint.)',
  );
}

/** The active provider name, for display/logging (mirrors default_bedrock_model intent). */
export function activeProvider(config: Config): SupportedProvider | null {
  if (config.bedrock?.model_id) return 'bedrock';
  if (config.anthropic?.model_id) return 'anthropic';
  if (config.openai?.model_id) return 'openai';
  if (config.gemini?.model_id) return 'gemini';
  return null;
}
