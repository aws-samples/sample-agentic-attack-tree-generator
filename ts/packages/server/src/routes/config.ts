/**
 * Configuration routes — TS port of `src/server/routes/config.py`. Mounted under
 * `/api`. Reads/writes `.threatforest/config.yaml`.
 *
 *   GET  /config              current model/provider config
 *   GET  /config/frameworks   available threat-mapping frameworks
 *   GET  /config/providers    available providers (TS: bedrock/anthropic/openai/gemini)
 *   POST /config/test         validate a provider config
 *   POST /config/save         persist provider config
 *   GET  /config/langfuse     Langfuse tracing config
 *   POST /config/langfuse/test
 *   POST /config/langfuse
 *
 * NOTE on bounded gaps vs Python:
 *  - Providers list reflects the SDK-native four (Ollama is dropped — see WS-3
 *    "Known bounded gaps"); the Gemini YAML key is `gemini`, not `google_gemini`.
 *  - The Bedrock STS credential probe and the Langfuse live auth-check use
 *    Python-only deps (boto3, the langfuse SDK, EnvManager). They are ported as
 *    field-shape validation; the deep network checks are not duplicated here and
 *    the response shape is unchanged so the UI behaves identically.
 */
import { Router, type Request, type Response } from 'express';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { config as engineConfig, FRAMEWORKS } from '@threatforest/engine';
import {
  type ConfigResponse,
  ConfigSaveRequestSchema,
  ConfigTestRequestSchema,
  type ProvidersResponse,
  LangfuseConfigSaveRequestSchema,
} from '@threatforest/types';

export const configRouter: Router = Router();

// TS supports only the four SDK-native providers (no Ollama — see providers.ts).
const AVAILABLE_PROVIDERS = ['AWS Bedrock', 'Anthropic', 'OpenAI', 'Google Gemini'];

const PROVIDER_TO_KEY: Record<string, string> = {
  'AWS Bedrock': 'bedrock',
  Anthropic: 'anthropic',
  OpenAI: 'openai',
  'Google Gemini': 'gemini',
};
const KEY_TO_PROVIDER: Record<string, string> = Object.fromEntries(
  Object.entries(PROVIDER_TO_KEY).map(([k, v]) => [v, k]),
);

const DEFAULT_CONFIG: ConfigResponse = {
  model_provider: 'AWS Bedrock',
  model_id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  embeddings_model: 'basel/ATTACK-BERT',
  default_browse_path: process.cwd(),
  aws_profile: null,
};

// Module-level config override (for testing); null → auto-detect.
let _config: ConfigResponse | null = null;

export function setConfig(config: ConfigResponse | null): void {
  _config = config;
}

/**
 * Resolve config.yaml using the same order as the pipeline Config: cwd first,
 * then repo root. Returns the canonical CLI location even if neither exists, so
 * save creates the file there.
 */
function resolveConfigPath(): string {
  const cwdConfig = join('.threatforest', 'config.yaml');
  if (existsSync(cwdConfig)) return cwdConfig;
  return join(process.cwd(), '.threatforest', 'config.yaml');
}

function loadConfigFromYaml(path: string): ConfigResponse {
  const raw = (parseYaml(readFileSync(path, 'utf-8')) as Record<string, unknown> | null) ?? {};

  const embeddings = (raw.embeddings as Record<string, unknown> | undefined) ?? {};
  const embeddingsModel = (embeddings.model as string | undefined) ?? DEFAULT_CONFIG.embeddings_model;

  let modelProvider = DEFAULT_CONFIG.model_provider;
  let modelId = DEFAULT_CONFIG.model_id;
  let awsProfile: string | null = null;

  for (const [yamlKey, providerName] of Object.entries(KEY_TO_PROVIDER)) {
    if (yamlKey in raw) {
      const section = (raw[yamlKey] && typeof raw[yamlKey] === 'object'
        ? (raw[yamlKey] as Record<string, unknown>)
        : {}) as Record<string, unknown>;
      modelProvider = providerName;
      modelId = (section.model_id as string | undefined) ?? DEFAULT_CONFIG.model_id;
      awsProfile = (section.aws_profile as string | undefined) ?? null;
      break;
    }
  }

  return {
    model_provider: modelProvider,
    model_id: modelId,
    embeddings_model: embeddingsModel,
    default_browse_path: process.cwd(),
    aws_profile: awsProfile,
  };
}

function getConfig(): ConfigResponse {
  if (_config !== null) return _config;
  const path = resolveConfigPath();
  if (existsSync(path)) return loadConfigFromYaml(path);
  return {
    model_provider: DEFAULT_CONFIG.model_provider,
    model_id: DEFAULT_CONFIG.model_id,
    embeddings_model: DEFAULT_CONFIG.embeddings_model,
    default_browse_path: process.cwd(),
    aws_profile: null,
  };
}

/** GET /config — current model/provider configuration. */
configRouter.get('/config', (_req: Request, res: Response) => {
  res.json(getConfig());
});

/** GET /config/frameworks — available threat-mapping frameworks. */
configRouter.get('/config/frameworks', (_req: Request, res: Response) => {
  const frameworks: Record<string, { name: string; description: string }> = {};
  for (const [k, v] of Object.entries(FRAMEWORKS)) {
    frameworks[k] = { name: v.name ?? k, description: v.description ?? '' };
  }
  res.json({ frameworks });
});

/** GET /config/providers — available model providers. */
configRouter.get('/config/providers', (_req: Request, res: Response) => {
  const body: ProvidersResponse = { providers: AVAILABLE_PROVIDERS };
  res.json(body);
});

/** POST /config/test — validate a provider configuration. */
configRouter.post('/config/test', (req: Request, res: Response) => {
  const parsed = ConfigTestRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const request = parsed.data;

  if (!request.provider || !request.provider.trim()) {
    res.json({ success: false, message: 'Provider is required.' });
    return;
  }
  if (!request.model_id || !request.model_id.trim()) {
    res.json({ success: false, message: 'Model ID is required.' });
    return;
  }
  if (!AVAILABLE_PROVIDERS.includes(request.provider)) {
    res.json({
      success: false,
      message: `Unknown provider '${request.provider}'. Available: ${AVAILABLE_PROVIDERS.join(', ')}`,
    });
    return;
  }

  // AWS Bedrock: the Python path does an STS get_caller_identity probe via boto3.
  // That dep isn't part of the TS engine; credentials are validated on first
  // model call instead. Keep the success/contract shape stable.
  if (request.provider === 'AWS Bedrock') {
    res.json({
      success: true,
      message:
        'AWS Bedrock configured. Credentials are validated on first use via the ' +
        'AWS SDK default credential chain (profile/role/env).',
    });
    return;
  }

  // API-key providers — confirm a key looks present.
  if (request.api_key) {
    res.json({
      success: true,
      message: `API key configured for ${request.provider}. Key will be validated on first use.`,
    });
    return;
  }

  res.json({
    success: false,
    message: `${request.provider} requires an API key. Please provide one.`,
  });
});

/** POST /config/save — persist provider config to `.threatforest/config.yaml`. */
configRouter.post('/config/save', (req: Request, res: Response) => {
  const parsed = ConfigSaveRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const request = parsed.data;

  if (!request.provider || !request.provider.trim()) {
    res.status(400).json({ detail: 'Provider is required.' });
    return;
  }
  if (!request.model_id || !request.model_id.trim()) {
    res.status(400).json({ detail: 'Model ID is required.' });
    return;
  }

  const yamlKey = PROVIDER_TO_KEY[request.provider];
  if (yamlKey === undefined) {
    res.status(400).json({
      detail: `Unknown provider '${request.provider}'. Available: ${AVAILABLE_PROVIDERS.join(', ')}`,
    });
    return;
  }

  const configPath = resolveConfigPath();

  const providerSection: Record<string, unknown> = { model_id: request.model_id };
  if (request.aws_profile) providerSection.aws_profile = request.aws_profile;

  let existing: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    existing = (parseYaml(readFileSync(configPath, 'utf-8')) as Record<string, unknown> | null) ?? {};
  }
  // Remove all provider keys, then set the new one.
  for (const key of Object.values(PROVIDER_TO_KEY)) {
    delete existing[key];
  }
  existing[yamlKey] = providerSection;

  try {
    mkdirSync(dirname(configPath), { recursive: true });
    // Default key ordering preserves insertion order (matches `sort_keys=False`).
    writeFileSync(configPath, stringifyYaml(existing), 'utf-8');
  } catch (err) {
    res.status(500).json({ detail: `Failed to write config: ${(err as Error).message}` });
    return;
  }

  // Reset route cache + the pipeline Config singleton so the next read/run picks
  // up the new file.
  setConfig(null);
  try {
    engineConfig.reset();
  } catch {
    /* non-fatal */
  }

  res.json({ success: true, message: 'Configuration saved successfully.' });
});

// ---------------------------------------------------------------------------
// Langfuse tracing config. The Python path reads/writes a `.env` via EnvManager
// and does a live auth-check with the langfuse SDK. In TS we read process.env
// for the GET, and the live check is reported as configured-on-save (the SDK
// auth probe is a Python-only dep). Response shapes are unchanged.
// ---------------------------------------------------------------------------

/** GET /config/langfuse — current Langfuse tracing configuration. */
configRouter.get('/config/langfuse', (_req: Request, res: Response) => {
  res.json({
    enabled: process.env.LANGFUSE_ENABLED === 'true',
    public_key: process.env.LANGFUSE_PUBLIC_KEY ?? null,
    secret_key_configured: Boolean(process.env.LANGFUSE_SECRET_KEY),
    host: process.env.LANGFUSE_HOST || 'https://cloud.langfuse.com',
  });
});

/** POST /config/langfuse/test — test Langfuse connectivity. */
configRouter.post('/config/langfuse/test', (req: Request, res: Response) => {
  const parsed = LangfuseConfigSaveRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const request = parsed.data;
  const publicKey = request.public_key || process.env.LANGFUSE_PUBLIC_KEY;
  const secretKey = request.secret_key || process.env.LANGFUSE_SECRET_KEY;

  if (!publicKey || !secretKey) {
    res.json({
      success: false,
      message: 'Public key and secret key are required to test the connection.',
    });
    return;
  }
  res.json({
    success: true,
    message: 'Langfuse credentials present. Connectivity is verified when tracing starts.',
  });
});

/** POST /config/langfuse — save Langfuse tracing configuration. */
configRouter.post('/config/langfuse', (req: Request, res: Response) => {
  const parsed = LangfuseConfigSaveRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const request = parsed.data;
  if (request.enabled && (!request.public_key || !request.secret_key)) {
    res.status(400).json({
      detail: 'Public key and secret key are required when enabling Langfuse.',
    });
    return;
  }

  // Persist to the process environment so the engine tracing layer (which reads
  // LANGFUSE_* env) picks them up. (The Python path wrote a `.env`; the TS engine
  // reads env directly, so we set env vars in-process.)
  process.env.LANGFUSE_ENABLED = request.enabled ? 'true' : 'false';
  if (request.public_key) process.env.LANGFUSE_PUBLIC_KEY = request.public_key;
  if (request.secret_key) process.env.LANGFUSE_SECRET_KEY = request.secret_key;
  process.env.LANGFUSE_HOST = request.host;

  res.json({ success: true, message: 'Langfuse configuration saved.' });
});
