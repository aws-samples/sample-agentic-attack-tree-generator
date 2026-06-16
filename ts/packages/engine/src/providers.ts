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
 * Create the configured Strands model. Currently always returns a BedrockModel
 * unless a non-Bedrock provider block is the first one configured, in which case
 * the caller must have the matching peer dep installed and we lazy-load it.
 */
export async function createModel(config: Config, opts: CreateModelOptions = {}): Promise<Model> {
  const temperature = opts.temperature ?? 0;
  const maxTokens = opts.maxTokens ?? 4096;

  if (config.bedrock?.model_id) {
    bedrockAuthSanityHint();
    return new BedrockModel({
      modelId: config.bedrock.model_id,
      region: config.awsRegion,
      temperature,
      maxTokens,
    });
  }

  if (config.anthropic?.model_id) {
    const { AnthropicModel } = await import('@strands-agents/sdk/models/anthropic');
    return new AnthropicModel({ modelId: config.anthropic.model_id, maxTokens }) as unknown as Model;
  }

  if (config.openai?.model_id) {
    const { OpenAIModel } = await import('@strands-agents/sdk/models/openai');
    return new OpenAIModel({ modelId: config.openai.model_id }) as unknown as Model;
  }

  if (config.gemini?.model_id) {
    const { GoogleModel } = await import('@strands-agents/sdk/models/google');
    return new GoogleModel({ modelId: config.gemini.model_id }) as unknown as Model;
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
