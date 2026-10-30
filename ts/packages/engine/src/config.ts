/**
 * Config loader — TS port of `src/threatforest/config.py`.
 *
 * Resolves `.threatforest/config.yaml` (cwd first, then a provided root), parses
 * it, and exposes the dot-notation `get()` plus the typed accessors the pipeline
 * uses (frameworks, embeddings model, ttc threshold, provider blocks). Frameworks
 * fall back to the canonical built-in registry when the file omits them.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export interface FrameworkDef {
  name?: string;
  description?: string;
  stix_bundle?: string;
  source_name?: string;
  kill_chain_name?: string;
}

/** Canonical framework registry (mirrors threatforest.frameworks.FRAMEWORKS). */
export const FRAMEWORKS: Record<string, FrameworkDef> = {
  attack: {
    name: 'MITRE ATT&CK Enterprise',
    stix_bundle: 'enterprise-attack-18.0.json',
    source_name: 'mitre-attack',
    kill_chain_name: 'mitre-attack',
  },
  atlas: {
    name: 'MITRE ATLAS',
    stix_bundle: 'stix-atlas.json',
    source_name: 'mitre-atlas',
    kill_chain_name: 'mitre-atlas',
  },
  wiz: {
    name: 'Wiz Cloud Threat Landscape',
    stix_bundle: 'wiz-cloud-threat-landscape.json',
    source_name: 'wiz-cloud-threat-landscape',
    kill_chain_name: 'wiz-cloud-threat-landscape',
  },
};

export interface ProviderBlock {
  model_id?: string;
  host?: string;
  endpoint_name?: string;
  [k: string]: unknown;
}

export type ModelParameterValue = string | number | boolean;

/**
 * The configuration surface consumed by one engine run.
 *
 * `Config` implements this interface with lazy filesystem-backed getters. Hosted
 * callers instead use `RunEngineConfig`, which is immutable and never reads the
 * process-global ThreatForest config file.
 */
export interface EngineConfigSource {
  /** Original durable selection when this is a per-run configuration. */
  readonly provider?: string;
  readonly modelId?: string;
  readonly modelParameters?: Readonly<Record<string, ModelParameterValue>>;
  readonly embeddingsModel: string;
  readonly ttcThreshold: number;
  readonly parallelMaxRetries: number;
  readonly parallelConcurrency?: number;
  readonly bedrock: Readonly<ProviderBlock>;
  readonly anthropic: Readonly<ProviderBlock>;
  readonly openai: Readonly<ProviderBlock>;
  readonly gemini: Readonly<ProviderBlock>;
  readonly awsRegion: string;
}

export interface RunEngineConfigInput {
  provider: string;
  modelId: string;
  modelParameters?: Readonly<Record<string, ModelParameterValue>>;
  embeddingsModel: string;
  /** Durable per-run region; local callers fall back to AWS_REGION. */
  awsRegion?: string;
  ttcThreshold?: number;
  parallelMaxRetries?: number;
  parallelConcurrency?: number;
}

type ProviderKey = 'bedrock' | 'anthropic' | 'openai' | 'gemini';

function providerKey(value: string): ProviderKey {
  switch (value.trim().toLowerCase()) {
    case 'aws bedrock':
    case 'bedrock':
      return 'bedrock';
    case 'anthropic':
      return 'anthropic';
    case 'openai':
      return 'openai';
    case 'google gemini':
    case 'gemini':
      return 'gemini';
    default:
      throw new Error(
        `Unsupported model provider ${JSON.stringify(value)}. ` +
          'Supported providers: AWS Bedrock, Anthropic, OpenAI, Google Gemini.',
      );
  }
}

function finiteNumber(value: number, name: string): number {
  if (!Number.isFinite(value)) {
    throw new Error(`${name} must be a finite number`);
  }
  return value;
}

/**
 * Immutable configuration for one graph invocation. No state is shared between
 * instances, so concurrent hosted runs cannot overwrite each other's provider,
 * model, model parameters, or embedding model.
 */
export class RunEngineConfig implements EngineConfigSource {
  readonly embeddingsModel: string;
  readonly ttcThreshold: number;
  readonly parallelMaxRetries: number;
  readonly parallelConcurrency: number;
  readonly bedrock: Readonly<ProviderBlock>;
  readonly anthropic: Readonly<ProviderBlock>;
  readonly openai: Readonly<ProviderBlock>;
  readonly gemini: Readonly<ProviderBlock>;
  readonly awsRegion: string;
  readonly provider: string;
  readonly modelId: string;
  readonly modelParameters: Readonly<Record<string, ModelParameterValue>>;

  constructor(input: RunEngineConfigInput) {
    const modelId = input.modelId.trim();
    const embeddingsModel = input.embeddingsModel.trim();
    if (modelId.length === 0) throw new Error('modelId must not be empty');
    if (embeddingsModel.length === 0) throw new Error('embeddingsModel must not be empty');

    this.provider = input.provider.trim();
    const selectedProvider = providerKey(this.provider);
    this.modelId = modelId;
    this.embeddingsModel = embeddingsModel;
    this.ttcThreshold = finiteNumber(input.ttcThreshold ?? 0.3, 'ttcThreshold');
    this.parallelMaxRetries = Math.trunc(
      finiteNumber(input.parallelMaxRetries ?? 1, 'parallelMaxRetries'),
    );
    if (this.parallelMaxRetries < 0) {
      throw new Error('parallelMaxRetries must be greater than or equal to zero');
    }
    this.parallelConcurrency = input.parallelConcurrency ?? 3;
    if (!Number.isInteger(this.parallelConcurrency) || this.parallelConcurrency < 1 || this.parallelConcurrency > 16) {
      throw new Error('parallelConcurrency must be an integer from 1 to 16');
    }
    this.awsRegion = input.awsRegion?.trim() || process.env.AWS_REGION || 'us-east-1';
    this.modelParameters = Object.freeze({ ...(input.modelParameters ?? {}) });

    const selected = Object.freeze({
      ...this.modelParameters,
      model_id: this.modelId,
    });
    const empty = Object.freeze({}) as Readonly<ProviderBlock>;
    this.bedrock = selectedProvider === 'bedrock' ? selected : empty;
    this.anthropic = selectedProvider === 'anthropic' ? selected : empty;
    this.openai = selectedProvider === 'openai' ? selected : empty;
    this.gemini = selectedProvider === 'gemini' ? selected : empty;
    Object.freeze(this);
  }
}

export function createRunEngineConfig(input: RunEngineConfigInput): RunEngineConfig {
  return new RunEngineConfig(input);
}

export class Config implements EngineConfigSource {
  private data: Record<string, unknown> | null = null;
  private path: string | null = null;

  constructor(private readonly rootDir: string = process.cwd()) {}

  private findConfigFile(): string {
    const candidates = [
      join(process.cwd(), '.threatforest', 'config.yaml'),
      join(this.rootDir, '.threatforest', 'config.yaml'),
    ];
    for (const c of candidates) {
      if (existsSync(c)) return c;
    }
    throw new Error(
      `Configuration file not found. Searched:\n  1. ${candidates[0]}\n  2. ${candidates[1]}\n` +
        "\nTo fix: run 'threatforest' to auto-create config, or save via the Configure page.",
    );
  }

  private load(): void {
    if (this.data !== null) return;
    this.path = this.findConfigFile();
    this.data = (parseYaml(readFileSync(this.path, 'utf8')) as Record<string, unknown>) ?? {};
  }

  reset(): void {
    this.data = null;
    this.path = null;
  }

  /** Dot-notation lookup (e.g. "embeddings.model"). */
  get<T = unknown>(key: string, fallback: T): T {
    this.load();
    let value: unknown = this.data;
    for (const k of key.split('.')) {
      if (value && typeof value === 'object' && k in (value as Record<string, unknown>)) {
        value = (value as Record<string, unknown>)[k];
      } else {
        return fallback;
      }
    }
    return (value ?? fallback) as T;
  }

  get frameworks(): Record<string, FrameworkDef> {
    return { ...FRAMEWORKS };
  }

  get embeddingsModel(): string {
    return this.get('embeddings.model', 'basel/ATTACK-BERT');
  }

  get ttcThreshold(): number {
    return this.get('embeddings.ttc_threshold', 0.3);
  }

  get parallelMaxRetries(): number {
    return Math.trunc(this.get('parallel.max_retries', 1));
  }
  get parallelConcurrency(): number {
    return this.get('parallel.concurrency', 3);
  }

  // Provider blocks (only the SDK-native four are wired in providers.ts).
  get bedrock(): ProviderBlock {
    return this.get('bedrock', {} as ProviderBlock);
  }
  get anthropic(): ProviderBlock {
    return this.get('anthropic', {} as ProviderBlock);
  }
  get openai(): ProviderBlock {
    return this.get('openai', {} as ProviderBlock);
  }
  get gemini(): ProviderBlock {
    return this.get('gemini', {} as ProviderBlock);
  }

  get awsRegion(): string {
    return process.env.AWS_REGION ?? this.get('aws.default_region', 'us-east-1');
  }
  get awsProfile(): string | undefined {
    const fromEnv = process.env.AWS_PROFILE;
    if (fromEnv) return fromEnv;
    return this.get('aws.default_profile', '' as string) || undefined;
  }
}

/** Default singleton (rooted at cwd, like the Python module-level `config`). */
export const config = new Config();
