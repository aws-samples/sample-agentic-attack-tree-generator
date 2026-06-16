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

export class Config {
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
