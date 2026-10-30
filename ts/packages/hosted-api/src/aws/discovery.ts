import {
  ListFoundationModelsCommand,
  ListInferenceProfilesCommand,
  type BedrockClient,
} from '@aws-sdk/client-bedrock';
import type {
  BedrockModel,
  BedrockModelsResponse,
  ConfigTestRequest,
  ConfigTestResponse,
} from '@threatforest/types';
import {
  TTP_FRAMEWORK_CATALOG,
  TTP_FRAMEWORK_IDS,
} from '@threatforest/types';
import type { DiscoveryService } from '../contracts.js';

const FALLBACK_MODELS = [
  'global.anthropic.claude-opus-4-8',
  'global.anthropic.claude-sonnet-4-6',
  'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  'global.anthropic.claude-haiku-4-5-20251001-v1:0',
  'global.amazon.nova-2-lite-v1:0',
];

function providerOf(id: string): string {
  return id.replace(/^(global|us|eu|apac)\./, '').split('.')[0] ?? 'Unknown';
}

function label(id: string): string {
  return id
    .replace(/^(global|us|eu|apac)\./, '')
    .replace(/^[^.]+\./, '')
    .replace(/-v\d+(:\d+)?$/, '')
    .split(/[-_]/)
    .filter((word) => !/^\d{8}$/.test(word))
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function model(id: string, providerName?: string): BedrockModel {
  const provider = providerName ?? providerOf(id);
  return {
    id,
    label: `${label(id)}${/^(global|us|eu|apac)\./.test(id) ? ` (${id.split('.')[0]})` : ''}`,
    provider,
    lifecycle: 'UNKNOWN',
    end_of_life: null,
    is_inference_profile: /^(global|us|eu|apac)\./.test(id),
    recommended: /anthropic|amazon/i.test(provider),
  };
}

export class BedrockDiscoveryService implements DiscoveryService {
  readonly #client: BedrockClient;
  readonly #region: string;
  readonly #clientForRegion: (region: string) => BedrockClient;

  constructor(
    client: BedrockClient,
    region: string,
    clientForRegion: (region: string) => BedrockClient = () => client,
  ) {
    this.#client = client;
    this.#region = region;
    this.#clientForRegion = clientForRegion;
  }

  async providers(): Promise<string[]> {
    return ['AWS Bedrock', 'Anthropic', 'OpenAI', 'Google Gemini'];
  }

  async frameworks(): Promise<
    Record<string, { name: string; description: string }>
  > {
    return Object.fromEntries(
      TTP_FRAMEWORK_IDS.map((id) => [id, { ...TTP_FRAMEWORK_CATALOG[id] }]),
    );
  }

  async models(region?: string, _refresh?: boolean): Promise<BedrockModelsResponse> {
    const selectedRegion = region?.trim() || this.#region;
    const client =
      selectedRegion === this.#region
        ? this.#client
        : this.#clientForRegion(selectedRegion);
    try {
      const [foundation, profiles] = await Promise.all([
        client.send(
          new ListFoundationModelsCommand({ byOutputModality: 'TEXT' }),
        ),
        client.send(new ListInferenceProfilesCommand({ maxResults: 1000 })),
      ]);
      const found = new Map<string, BedrockModel>();
      for (const entry of foundation.modelSummaries ?? []) {
        if (
          !entry.modelId ||
          !(entry.outputModalities ?? []).includes('TEXT') ||
          !(entry.inferenceTypesSupported ?? []).includes('ON_DEMAND')
        ) {
          continue;
        }
        const mapped = model(entry.modelId, entry.providerName);
        mapped.label = entry.modelName?.trim() || mapped.label;
        mapped.lifecycle =
          entry.modelLifecycle?.status === 'ACTIVE' ||
          entry.modelLifecycle?.status === 'LEGACY'
            ? entry.modelLifecycle.status
            : 'UNKNOWN';
        mapped.end_of_life =
          entry.modelLifecycle?.endOfLifeTime?.toISOString() ?? null;
        found.set(mapped.id, mapped);
      }
      for (const entry of profiles.inferenceProfileSummaries ?? []) {
        if (!entry.inferenceProfileId || entry.status !== 'ACTIVE') {
          continue;
        }
        const mapped = model(entry.inferenceProfileId);
        mapped.label = entry.inferenceProfileName?.trim() || mapped.label;
        mapped.lifecycle = 'ACTIVE';
        found.set(mapped.id, mapped);
      }
      if (found.size === 0) {
        throw new Error('Bedrock returned no invocable text models');
      }
      return {
        models: [...found.values()].sort(
          (left, right) =>
            Number(right.recommended) - Number(left.recommended) ||
            left.label.localeCompare(right.label),
        ),
        source: 'live',
        warning: null,
        region: selectedRegion,
      };
    } catch (error) {
      return {
        models: FALLBACK_MODELS.map((id) => model(id)),
        source: 'fallback',
        warning: `Bedrock model discovery failed: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
        region: selectedRegion,
      };
    }
  }

  async testConfiguration(input: ConfigTestRequest): Promise<ConfigTestResponse> {
    if (input.provider !== 'AWS Bedrock') {
      return {
        success: false,
        message:
          'Hosted provider credentials must be configured as managed secrets before use.',
      };
    }
    const discovered = await this.models(input.aws_region ?? undefined);
    const present = discovered.models.some((candidate) => candidate.id === input.model_id);
    return {
      success: present,
      message: present
        ? 'Model is discoverable in the hosted Bedrock region.'
        : 'Model was not returned by Bedrock discovery; entitlement is checked on invocation.',
    };
  }
}
