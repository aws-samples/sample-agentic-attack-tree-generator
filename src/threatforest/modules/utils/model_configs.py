"""Centralized model configurations for AI providers"""

# AWS Bedrock Models
BEDROCK_MODELS = [
    "global.amazon.nova-2-lite-v1:0",
    "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "global.anthropic.claude-opus-4-5-20251101-v1:0",
]

# Anthropic Direct API Models
ANTHROPIC_MODELS = [
    "claude-3-sonnet-20240229",
    "claude-3-opus-20240229",
    "claude-3-haiku-20240307",
    "claude-sonnet-4-20250514",
]

# OpenAI Models
OPENAI_MODELS = [
    "gpt-4o",
    "gpt-4-turbo-preview",
    "gpt-4",
]

# Google Gemini Models
GEMINI_MODELS = [
    "gemini-2.5-flash-exp",
    "gemini-2.5-flash",
    "gemini-3-pro",
]

# Default models for each provider
DEFAULT_MODELS = {
    'bedrock': "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    'anthropic': "claude-sonnet-4-20250514",
    'openai': "gpt-4o",
    'gemini': "gemini-2.5-flash-exp",
    'ollama': "llama3.1"
}

# Provider display names
PROVIDER_NAMES = {
    'bedrock': 'AWS Bedrock',
    'anthropic': 'Anthropic',
    'openai': 'OpenAI',
    'gemini': 'Google Gemini',
    'ollama': 'Ollama (Local)',
    'litellm': 'LiteLLM',
    'llamaapi': 'LlamaAPI'
}
