import {
  GetSecretValueCommand,
  type SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';

export interface HostedApiSecrets {
  originVerificationSecret: string;
  replayTicketSecret: string;
}

export class SecretsManagerStringProvider {
  readonly #client: SecretsManagerClient;
  readonly #secretId: string;
  readonly #minimumBytes: number;

  constructor(
    client: SecretsManagerClient,
    secretId: string,
    minimumBytes: number,
  ) {
    this.#client = client;
    this.#secretId = secretId;
    this.#minimumBytes = minimumBytes;
  }

  async load(): Promise<string> {
    const result = await this.#client.send(
      new GetSecretValueCommand({ SecretId: this.#secretId }),
    );
    const value =
      result.SecretString ??
      (result.SecretBinary === undefined
        ? undefined
        : Buffer.from(result.SecretBinary).toString('utf8'));
    if (value === undefined || Buffer.byteLength(value) < this.#minimumBytes) {
      throw new Error(
        `Secret ${this.#secretId} must contain at least ${this.#minimumBytes} bytes`,
      );
    }
    return value;
  }
}

export class SecretsManagerSecretProvider {
  readonly #client: SecretsManagerClient;
  readonly #secretId: string;

  constructor(client: SecretsManagerClient, secretId: string) {
    this.#client = client;
    this.#secretId = secretId;
  }

  async load(): Promise<HostedApiSecrets> {
    const result = await this.#client.send(
      new GetSecretValueCommand({ SecretId: this.#secretId }),
    );
    const raw =
      result.SecretString ??
      (result.SecretBinary === undefined
        ? undefined
        : Buffer.from(result.SecretBinary).toString('utf8'));
    if (raw === undefined) {
      throw new Error(`Secret ${this.#secretId} has no value`);
    }
    let value: unknown;
    try {
      value = JSON.parse(raw) as unknown;
    } catch {
      throw new Error(`Secret ${this.#secretId} must contain JSON`);
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      throw new Error(`Secret ${this.#secretId} must contain a JSON object`);
    }
    const record = value as Record<string, unknown>;
    const originVerificationSecret = record.originVerificationSecret;
    const replayTicketSecret = record.replayTicketSecret;
    if (
      typeof originVerificationSecret !== 'string' ||
      originVerificationSecret.length < 16 ||
      typeof replayTicketSecret !== 'string' ||
      Buffer.byteLength(replayTicketSecret) < 32
    ) {
      throw new Error(
        `Secret ${this.#secretId} must contain valid originVerificationSecret and replayTicketSecret values`,
      );
    }
    return { originVerificationSecret, replayTicketSecret };
  }
}
