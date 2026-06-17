/**
 * Centralized model lists — port of
 * `src/threatforest/modules/utils/model_configs.py`.
 *
 * The TS engine only wires the four SDK-native providers (bedrock, anthropic,
 * openai, gemini); the lists below still include the others for wizard parity,
 * but providers.ts will reject a config that selects an unsupported block.
 */
export const BEDROCK_MODELS = [
  'global.amazon.nova-2-lite-v1:0',
  'global.anthropic.claude-haiku-4-5-20251001-v1:0',
  'global.anthropic.claude-sonnet-4-6',
  'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  'global.anthropic.claude-opus-4-5-20251101-v1:0',
  'global.anthropic.claude-opus-4-6-v1',
  'global.anthropic.claude-opus-4-7',
  'global.anthropic.claude-opus-4-8',
];

export const ANTHROPIC_MODELS = [
  'claude-3-sonnet-20240229',
  'claude-3-opus-20240229',
  'claude-3-haiku-20240307',
  'claude-sonnet-4-20250514',
];

export const OPENAI_MODELS = ['gpt-4o', 'gpt-4-turbo-preview', 'gpt-4'];

export const GEMINI_MODELS = ['gemini-2.5-flash-exp', 'gemini-2.5-flash', 'gemini-3-pro'];

export const DEFAULT_MODELS: Record<string, string> = {
  bedrock: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-4o',
  gemini: 'gemini-2.5-flash-exp',
  ollama: 'llama3.1',
};

export const PROVIDER_NAMES: Record<string, string> = {
  bedrock: 'AWS Bedrock',
  anthropic: 'Anthropic',
  openai: 'OpenAI',
  gemini: 'Google Gemini',
  ollama: 'Ollama (Local)',
  litellm: 'LiteLLM',
  llamaapi: 'LlamaAPI',
};
