import {
  CreateSecretCommand,
  DescribeSecretCommand,
  PutSecretValueCommand,
  type SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import type { UserId } from '@threatforest/types';
import type { ProviderCredentialStore } from '../contracts.js';

export interface SecretsManagerProviderCredentialStoreOptions {
  client: Pick<SecretsManagerClient, 'send'>;
  secretPrefix: string;
  kmsKeyId: string;
}

export class SecretsManagerProviderCredentialStore
  implements ProviderCredentialStore
{
  readonly #client: Pick<SecretsManagerClient, 'send'>;
  readonly #secretPrefix: string;
  readonly #kmsKeyId: string;

  constructor(options: SecretsManagerProviderCredentialStoreOptions) {
    this.#client = options.client;
    this.#secretPrefix = required(options.secretPrefix, 'secretPrefix').replace(
      /^\/+|\/+$/g,
      '',
    );
    this.#kmsKeyId = required(options.kmsKeyId, 'kmsKeyId');
  }

  async configured(ownerId: UserId, provider: string): Promise<boolean> {
    const providerId = externalProvider(provider);
    if (providerId === null) {
      return false;
    }
    try {
      await this.#client.send(
        new DescribeSecretCommand({
          SecretId: this.#secretId(ownerId, providerId),
        }),
      );
      return true;
    } catch (error) {
      if (isNamed(error, 'ResourceNotFoundException')) {
        return false;
      }
      throw error;
    }
  }

  async put(ownerId: UserId, provider: string, apiKey: string): Promise<void> {
    const providerId = externalProvider(provider);
    if (providerId === null) {
      throw new Error('AWS Bedrock uses the hosted Runtime role, not an API key.');
    }
    const normalizedKey = required(apiKey, 'apiKey');
    const secretId = this.#secretId(ownerId, providerId);
    const secretString = JSON.stringify({ apiKey: normalizedKey });
    try {
      await this.#client.send(
        new PutSecretValueCommand({
          SecretId: secretId,
          SecretString: secretString,
        }),
      );
      return;
    } catch (error) {
      if (!isNamed(error, 'ResourceNotFoundException')) {
        throw error;
      }
    }
    try {
      await this.#client.send(
        new CreateSecretCommand({
          Name: secretId,
          Description: `ThreatForest ${providerId} credential for one hosted user`,
          KmsKeyId: this.#kmsKeyId,
          SecretString: secretString,
          Tags: [
            { Key: 'Application', Value: 'ThreatForest' },
            { Key: 'CredentialType', Value: 'model-provider' },
          ],
        }),
      );
    } catch (error) {
      if (!isNamed(error, 'ResourceExistsException')) {
        throw error;
      }
      await this.#client.send(
        new PutSecretValueCommand({
          SecretId: secretId,
          SecretString: secretString,
        }),
      );
    }
  }

  #secretId(ownerId: UserId, providerId: string): string {
    return `${this.#secretPrefix}/${ownerId}/providers/${providerId}`;
  }
}

function externalProvider(provider: string): string | null {
  switch (provider.trim().toLowerCase()) {
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
      throw new Error(`Unsupported model provider ${JSON.stringify(provider)}.`);
  }
}

function isNamed(error: unknown, name: string): boolean {
  return error instanceof Error && error.name === name;
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}
