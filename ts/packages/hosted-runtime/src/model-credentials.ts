import {
  GetSecretValueCommand,
  SecretsManagerClient,
  type SecretsManagerClientConfig,
} from '@aws-sdk/client-secrets-manager';
import type { UserId } from '@threatforest/types';

export interface ModelCredentialResolver {
  resolve(
    ownerId: UserId,
    provider: string,
  ): Promise<Readonly<Record<string, string>>>;
}

export interface SecretsManagerModelCredentialResolverOptions {
  readonly secretPrefix: string;
  readonly region?: string;
  readonly client?: Pick<SecretsManagerClient, 'send'>;
  readonly clientConfig?: SecretsManagerClientConfig;
}

type ExternalProvider = 'anthropic' | 'openai' | 'gemini';

export class SecretsManagerModelCredentialResolver
  implements ModelCredentialResolver
{
  readonly #secretPrefix: string;
  readonly #client: Pick<SecretsManagerClient, 'send'>;

  constructor(options: SecretsManagerModelCredentialResolverOptions) {
    this.#secretPrefix = required(options.secretPrefix, 'secretPrefix').replace(
      /^\/+|\/+$/g,
      '',
    );
    this.#client =
      options.client ??
      new SecretsManagerClient({
        ...options.clientConfig,
        ...(options.region === undefined ? {} : { region: options.region }),
      });
  }

  async resolve(
    ownerId: UserId,
    provider: string,
  ): Promise<Readonly<Record<string, string>>> {
    const selected = externalProvider(provider);
    if (selected === null) {
      return {};
    }
    const secretId = `${this.#secretPrefix}/${ownerId}/providers/${selected}`;
    let response;
    try {
      response = await this.#client.send(
        new GetSecretValueCommand({ SecretId: secretId }),
      );
    } catch (error) {
      if (
        error instanceof Error &&
        error.name === 'ResourceNotFoundException'
      ) {
        throw new Error(
          `No managed ${provider} credential is configured for this user.`,
        );
      }
      throw error;
    }
    const raw =
      response.SecretString ??
      (response.SecretBinary === undefined
        ? undefined
        : Buffer.from(response.SecretBinary).toString('utf8'));
    if (raw === undefined || raw.trim().length === 0) {
      throw new Error(`Managed ${provider} credential is empty.`);
    }
    let apiKey = raw.trim();
    if (apiKey.startsWith('{')) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(apiKey) as unknown;
      } catch {
        throw new Error(
          `Managed ${provider} credential must be a string or JSON object.`,
        );
      }
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        throw new Error(
          `Managed ${provider} credential JSON must be an object.`,
        );
      }
      const record = parsed as Record<string, unknown>;
      const value = record['apiKey'] ?? record['api_key'];
      if (typeof value !== 'string' || value.trim().length === 0) {
        throw new Error(
          `Managed ${provider} credential JSON must contain apiKey.`,
        );
      }
      apiKey = value.trim();
    }
    return Object.freeze({ apiKey });
  }
}

function externalProvider(value: string): ExternalProvider | null {
  switch (value.trim().toLowerCase()) {
    case 'aws bedrock':
    case 'bedrock':
      return null;
    case 'anthropic':
      return 'anthropic';
    case 'openai':
      return 'openai';
    case 'google gemini':
    case 'gemini':
      return 'gemini';
    default:
      throw new Error(`Unsupported model provider ${JSON.stringify(value)}.`);
  }
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}
