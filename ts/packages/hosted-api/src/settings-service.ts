import { createHash } from 'node:crypto';
import {
  ConfigSaveRequestSchema,
  ConfigTestRequestSchema,
  DEFAULT_TTP_FRAMEWORK_IDS,
  type ApplicationId,
  type BedrockModelsResponse,
  type ConfigResponse,
  type ConfigTestResponse,
  type UserId,
} from '@threatforest/types';
import type {
  ApplicationSettingsRecord,
  ControlPlaneScope,
  ControlPlaneStore,
} from '@threatforest/control-plane';
import type {
  Clock,
  DiscoveryService,
  MutationContext,
  MutationResponseRecord,
  ProviderCredentialStore,
} from './contracts.js';
import { ApplicationService } from './application-service.js';
import { badRequest } from './errors.js';
import { IdempotencyExecutor, requestHash } from './idempotency.js';
import { ACCOUNT_SCOPE_APPLICATION_ID } from './runtime.js';

export interface SettingsDefaults {
  provider: string;
  modelId: string;
  embeddingsModel: string;
  awsRegion: string;
  modelParameters: Record<string, string | number | boolean>;
  frameworks: string[];
}

export interface SettingsServiceOptions {
  controlPlane: ControlPlaneStore;
  applications: ApplicationService;
  discovery?: DiscoveryService;
  credentials?: ProviderCredentialStore;
  idempotency: IdempotencyExecutor;
  clock: Clock;
  defaults?: Partial<SettingsDefaults>;
}

const BASE_DEFAULTS: SettingsDefaults = {
  provider: 'AWS Bedrock',
  modelId: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
  embeddingsModel: 'basel/ATTACK-BERT',
  awsRegion: 'eu-west-2',
  modelParameters: {},
  frameworks: [...DEFAULT_TTP_FRAMEWORK_IDS],
};

export class SettingsService {
  readonly #controlPlane: ControlPlaneStore;
  readonly #applications: ApplicationService;
  readonly #discovery: DiscoveryService | undefined;
  readonly #credentials: ProviderCredentialStore | undefined;
  readonly #idempotency: IdempotencyExecutor;
  readonly #clock: Clock;
  readonly #defaults: SettingsDefaults;

  constructor(options: SettingsServiceOptions) {
    this.#controlPlane = options.controlPlane;
    this.#applications = options.applications;
    this.#discovery = options.discovery;
    this.#credentials = options.credentials;
    this.#idempotency = options.idempotency;
    this.#clock = options.clock;
    this.#defaults = {
      ...BASE_DEFAULTS,
      ...options.defaults,
      modelParameters: {
        ...BASE_DEFAULTS.modelParameters,
        ...options.defaults?.modelParameters,
      },
      frameworks: options.defaults?.frameworks ?? BASE_DEFAULTS.frameworks,
    };
  }

  scope(ownerId: UserId, applicationId?: ApplicationId): ControlPlaneScope {
    return {
      owner_id: ownerId,
      application_id: applicationId ?? ACCOUNT_SCOPE_APPLICATION_ID,
    };
  }

  async settings(
    ownerId: UserId,
    applicationId?: ApplicationId,
  ): Promise<ApplicationSettingsRecord> {
    if (applicationId !== undefined) {
      await this.#applications.require(ownerId, applicationId);
    }
    const scope = this.scope(ownerId, applicationId);
    return (await this.#controlPlane.getApplicationSettings(scope)) ?? this.#defaultRecord(scope);
  }

  async getConfig(ownerId: UserId, applicationId?: ApplicationId): Promise<ConfigResponse> {
    const settings = await this.settings(ownerId, applicationId);
    const apiKeyConfigured =
      this.#credentials === undefined
        ? false
        : await this.#credentials.configured(ownerId, settings.provider);
    let defaultBrowsePath = '';
    if (applicationId !== undefined) {
      defaultBrowsePath = (await this.#applications.get(ownerId, applicationId)).project_path;
    }
    return {
      model_provider: settings.provider,
      model_id: settings.model_id,
      embeddings_model: settings.embeddings_model,
      default_browse_path: defaultBrowsePath,
      aws_profile: null,
      aws_region: settings.aws_region ?? this.#defaults.awsRegion,
      api_key_configured: apiKeyConfigured,
    };
  }

  async saveConfig(
    context: MutationContext,
    applicationId: ApplicationId | undefined,
    input: unknown,
  ): Promise<MutationResponseRecord & { value: ConfigTestResponse }> {
    const parsed = ConfigSaveRequestSchema.parse(input);
    const scope = this.scope(context.ownerId, applicationId);
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'save_configuration',
      parsed,
      async () => {
        if (applicationId !== undefined) {
          await this.#applications.requireWritable(
            context.ownerId,
            applicationId,
          );
        }
        const current = await this.#controlPlane.getApplicationSettings(scope);
        const base = current ?? this.#defaultRecord(scope);
        const provider = parsed.provider.trim();
        const apiKey = parsed.api_key?.trim() || null;
        if (isExternalProvider(provider)) {
          const credentials = this.#requireCredentials();
          if (apiKey !== null) {
            await credentials.put(context.ownerId, provider, apiKey);
          } else if (!(await credentials.configured(context.ownerId, provider))) {
            throw badRequest(
              `An API key is required before ${provider} can be selected.`,
            );
          }
        } else if (apiKey !== null) {
          throw badRequest(
            'AWS Bedrock uses the hosted Runtime role, not an API key.',
          );
        }
        const nextWithoutHash = {
          provider,
          model_id: parsed.model_id.trim(),
          aws_region: parsed.aws_region?.trim() || this.#defaults.awsRegion,
          model_parameters: base.model_parameters,
          frameworks: base.frameworks,
          embeddings_model: base.embeddings_model,
        };
        const next: ApplicationSettingsRecord = {
          schema_version: 1,
          ...scope,
          revision: (current?.revision ?? 0) + 1,
          ...nextWithoutHash,
          config_hash: requestHash('application_settings', nextWithoutHash),
          updated_at: this.#clock.now().toISOString(),
        };
        await this.#controlPlane.putApplicationSettings(next, current?.revision ?? null);
        return {
          status: 200,
          value: {
            success: true,
            message: 'Configuration saved successfully.',
          },
        };
      },
    );
  }

  async providers(): Promise<{ providers: string[] }> {
    return { providers: await this.#requireDiscovery().providers() };
  }

  async frameworks(): Promise<{
    frameworks: Record<string, { name: string; description: string }>;
  }> {
    return { frameworks: await this.#requireDiscovery().frameworks() };
  }

  models(region?: string, refresh?: boolean): Promise<BedrockModelsResponse> {
    return this.#requireDiscovery().models(region, refresh);
  }

  async test(ownerId: UserId, input: unknown): Promise<ConfigTestResponse> {
    const parsed = ConfigTestRequestSchema.parse(input);
    if (isExternalProvider(parsed.provider)) {
      const configured =
        parsed.api_key?.trim().length
          ? true
          : await this.#requireCredentials().configured(
              ownerId,
              parsed.provider,
            );
      return {
        success: configured,
        message: configured
          ? `${parsed.provider} credential is available. It will be validated by the selected provider on invocation.`
          : `${parsed.provider} requires an API key.`,
      };
    }
    return this.#requireDiscovery().testConfiguration(parsed);
  }

  #requireDiscovery(): DiscoveryService {
    if (this.#discovery === undefined) {
      throw new Error(
        'Model discovery is unavailable in this service composition.',
      );
    }
    return this.#discovery;
  }

  #requireCredentials(): ProviderCredentialStore {
    if (this.#credentials === undefined) {
      throw new Error(
        'Managed model-provider credentials are unavailable in this service composition.',
      );
    }
    return this.#credentials;
  }

  #defaultRecord(scope: ControlPlaneScope): ApplicationSettingsRecord {
    const hashInput = {
      provider: this.#defaults.provider,
      model_id: this.#defaults.modelId,
      aws_region: this.#defaults.awsRegion,
      model_parameters: this.#defaults.modelParameters,
      frameworks: this.#defaults.frameworks,
      embeddings_model: this.#defaults.embeddingsModel,
    };
    return {
      schema_version: 1,
      ...scope,
      revision: 0,
      ...hashInput,
      config_hash: createHash('sha256')
        .update(JSON.stringify(hashInput))
        .digest('hex'),
      updated_at: this.#clock.now().toISOString(),
    };
  }
}

function isExternalProvider(provider: string): boolean {
  return !['aws bedrock', 'bedrock'].includes(provider.trim().toLowerCase());
}
