import type { IngestionWorkerResult, UploadManifest, UploadScope } from './types.js';
import {
  IdempotencyConflictError,
  ManifestConflictError,
  type IdempotencyBeginResult,
  type IngestionIdempotencyRecord,
  type IngestionIdempotencyStore,
  type UploadManifestStore,
} from './worker.js';
import { validateUploadScope, validateWorkspaceIdentifier } from './keys.js';

interface SdkCommand {
  readonly input?: unknown;
}

interface SdkCommandConstructor {
  new (input: Record<string, unknown>): SdkCommand;
}

interface SdkClient {
  send(command: SdkCommand): Promise<Record<string, unknown>>;
}

interface DynamoSdkModule {
  readonly DynamoDBClient: new (configuration: Record<string, unknown>) => unknown;
}

interface DynamoDocumentSdkModule {
  readonly DynamoDBDocumentClient: {
    from(client: unknown, options?: Record<string, unknown>): SdkClient;
  };
  readonly GetCommand: SdkCommandConstructor;
  readonly PutCommand: SdkCommandConstructor;
  readonly UpdateCommand: SdkCommandConstructor;
}

interface DynamoCommands {
  readonly get: SdkCommandConstructor;
  readonly put: SdkCommandConstructor;
  readonly update: SdkCommandConstructor;
}

export interface AwsDynamoIngestionStoreConfiguration {
  readonly tableName: string;
  readonly region?: string;
  readonly endpoint?: string;
  readonly idempotencyTtlSeconds?: number;
  readonly processingLeaseSeconds?: number;
  readonly clientConfiguration?: Readonly<Record<string, unknown>>;
}

export async function createAwsDynamoIngestionStore(
  configuration: AwsDynamoIngestionStoreConfiguration,
): Promise<DynamoIngestionStore> {
  const clientPackage = '@aws-sdk/client-dynamodb';
  const documentPackage = '@aws-sdk/lib-dynamodb';
  const dynamo = (await import(clientPackage)) as unknown as DynamoSdkModule;
  const document = (await import(documentPackage)) as unknown as DynamoDocumentSdkModule;
  const baseClient = new dynamo.DynamoDBClient({
    ...configuration.clientConfiguration,
    ...(configuration.region === undefined ? {} : { region: configuration.region }),
    ...(configuration.endpoint === undefined ? {} : { endpoint: configuration.endpoint }),
  });
  const client = document.DynamoDBDocumentClient.from(baseClient, {
    marshallOptions: {
      removeUndefinedValues: true,
      convertClassInstanceToMap: false,
    },
  });
  return new DynamoIngestionStore(
    configuration.tableName,
    client,
    {
      get: document.GetCommand,
      put: document.PutCommand,
      update: document.UpdateCommand,
    },
    configuration.idempotencyTtlSeconds,
    configuration.processingLeaseSeconds,
  );
}

export class DynamoIngestionStore
  implements UploadManifestStore, IngestionIdempotencyStore
{
  private readonly idempotencyTtlSeconds: number;
  private readonly processingLeaseSeconds: number;

  public constructor(
    private readonly tableName: string,
    private readonly client: SdkClient,
    private readonly commands: DynamoCommands,
    idempotencyTtlSeconds = 30 * 24 * 60 * 60,
    processingLeaseSeconds = 15 * 60,
    private readonly now: () => Date = () => new Date(),
  ) {
    if (tableName.trim().length === 0) {
      throw new Error('DynamoDB table name is required');
    }
    if (!Number.isSafeInteger(idempotencyTtlSeconds) || idempotencyTtlSeconds < 60) {
      throw new Error('Idempotency TTL must be an integer of at least 60 seconds');
    }
    this.idempotencyTtlSeconds = idempotencyTtlSeconds;
    if (!Number.isSafeInteger(processingLeaseSeconds) || processingLeaseSeconds < 30) {
      throw new Error('Processing lease must be an integer of at least 30 seconds');
    }
    this.processingLeaseSeconds = processingLeaseSeconds;
  }

  /** Used by the upload control plane when the initial manifest is created. */
  public async create(manifest: UploadManifest): Promise<void> {
    validateManifest(manifest);
    try {
      await this.client.send(
        new this.commands.put({
          TableName: this.tableName,
          Item: manifestItem(manifest),
          ConditionExpression: 'attribute_not_exists(PK)',
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw new ManifestConflictError();
      }
      throw error;
    }
  }

  public async get(scope: UploadScope): Promise<UploadManifest | null> {
    validateUploadScope(scope);
    const response = await this.client.send(
      new this.commands.get({
        TableName: this.tableName,
        Key: manifestKey(scope),
        ConsistentRead: true,
      }),
    );
    const item = asRecord(response['Item']);
    if (item === null) {
      return null;
    }
    const manifest = item['manifest'];
    validateManifest(manifest);
    ensureScopeMatches(scope, manifest);
    return structuredClone(manifest);
  }

  public async put(manifest: UploadManifest, expectedRevision: number): Promise<void> {
    validateManifest(manifest);
    try {
      await this.client.send(
        new this.commands.put({
          TableName: this.tableName,
          Item: manifestItem(manifest),
          ConditionExpression: 'attribute_exists(PK) AND revision = :expected',
          ExpressionAttributeValues: { ':expected': expectedRevision },
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw new ManifestConflictError();
      }
      throw error;
    }
  }

  public async begin(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly attempt: number;
  }): Promise<IdempotencyBeginResult> {
    validateIdempotencyInput(input);
    const key = idempotencyKey(input);
    const nowEpoch = this.nowEpochSeconds();
    const record: IngestionIdempotencyRecord = {
      idempotencyKey: input.idempotencyKey,
      requestHash: input.requestHash,
      attempt: input.attempt,
      status: 'in_progress',
      result: null,
      leaseExpiresAt: nowEpoch + this.processingLeaseSeconds,
    };
    try {
      await this.client.send(
        new this.commands.put({
          TableName: this.tableName,
          Item: {
            ...key,
            entity: 'ingestion_idempotency',
            ...record,
            ttl: this.expiryEpochSeconds(),
          },
          ConditionExpression: 'attribute_not_exists(PK)',
        }),
      );
      return { state: 'acquired' };
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
    }

    const existing = await this.getIdempotency(input);
    if (existing === null) {
      return this.begin(input);
    }
    if (existing.requestHash !== input.requestHash) {
      throw new IdempotencyConflictError();
    }
    if (existing.status === 'failed' && input.attempt > existing.attempt) {
      try {
        await this.client.send(
          new this.commands.update({
            TableName: this.tableName,
            Key: key,
            UpdateExpression:
              'SET #status = :inProgress, attempt = :attempt, #result = :empty, leaseExpiresAt = :lease, #ttl = :ttl',
            ConditionExpression:
              '#status = :failed AND attempt < :attempt AND requestHash = :requestHash',
            ExpressionAttributeNames: {
              '#status': 'status',
              '#result': 'result',
              '#ttl': 'ttl',
            },
            ExpressionAttributeValues: {
              ':inProgress': 'in_progress',
              ':failed': 'failed',
              ':attempt': input.attempt,
              ':requestHash': input.requestHash,
              ':empty': null,
              ':lease': nowEpoch + this.processingLeaseSeconds,
              ':ttl': this.expiryEpochSeconds(),
            },
          }),
        );
        return { state: 'acquired' };
      } catch (error) {
        if (!isConditionalFailure(error)) {
          throw error;
        }
        return this.begin(input);
      }
    }
    if (existing.status === 'in_progress') {
      if (existing.leaseExpiresAt <= nowEpoch) {
        try {
          await this.client.send(
            new this.commands.update({
              TableName: this.tableName,
              Key: key,
              UpdateExpression:
                'SET attempt = :attempt, leaseExpiresAt = :lease, #ttl = :ttl',
              ConditionExpression:
                '#status = :inProgress AND leaseExpiresAt <= :now AND requestHash = :requestHash',
              ExpressionAttributeNames: {
                '#status': 'status',
                '#ttl': 'ttl',
              },
              ExpressionAttributeValues: {
                ':inProgress': 'in_progress',
                ':attempt': input.attempt,
                ':lease': nowEpoch + this.processingLeaseSeconds,
                ':now': nowEpoch,
                ':requestHash': input.requestHash,
                ':ttl': this.expiryEpochSeconds(),
              },
            }),
          );
          return { state: 'acquired' };
        } catch (error) {
          if (!isConditionalFailure(error)) {
            throw error;
          }
          return this.begin(input);
        }
      }
      return { state: 'in_progress' };
    }
    if (existing.result === null) {
      throw new Error('Terminal ingestion idempotency item has no result');
    }
    return existing.status === 'completed'
      ? { state: 'completed', result: existing.result }
      : { state: 'failed', result: existing.result };
  }

  public async complete(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly result: IngestionWorkerResult;
  }): Promise<void> {
    await this.finish(input, 'completed');
  }

  public async fail(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly result: IngestionWorkerResult;
  }): Promise<void> {
    await this.finish(input, 'failed');
  }

  private async finish(
    input: {
      readonly ownerId: string;
      readonly applicationId: string;
      readonly idempotencyKey: string;
      readonly requestHash: string;
      readonly result: IngestionWorkerResult;
    },
    status: 'completed' | 'failed',
  ): Promise<void> {
    validateIdempotencyInput({ ...input, attempt: 1 });
    try {
      await this.client.send(
        new this.commands.update({
          TableName: this.tableName,
          Key: idempotencyKey(input),
          UpdateExpression: 'SET #status = :terminal, #result = :result, #ttl = :ttl',
          ConditionExpression: '#status = :inProgress AND requestHash = :requestHash',
          ExpressionAttributeNames: {
            '#status': 'status',
            '#result': 'result',
            '#ttl': 'ttl',
          },
          ExpressionAttributeValues: {
            ':terminal': status,
            ':inProgress': 'in_progress',
            ':requestHash': input.requestHash,
            ':result': input.result,
            ':ttl': this.expiryEpochSeconds(),
          },
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw new IdempotencyConflictError();
      }
      throw error;
    }
  }

  private async getIdempotency(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
  }): Promise<IngestionIdempotencyRecord | null> {
    const response = await this.client.send(
      new this.commands.get({
        TableName: this.tableName,
        Key: idempotencyKey(input),
        ConsistentRead: true,
      }),
    );
    const item = asRecord(response['Item']);
    if (item === null) {
      return null;
    }
    const status = item['status'];
    if (status !== 'in_progress' && status !== 'completed' && status !== 'failed') {
      throw new Error('Invalid ingestion idempotency status in DynamoDB');
    }
    const result = item['result'];
    return {
      idempotencyKey: requiredString(item['idempotencyKey'], 'idempotencyKey'),
      requestHash: requiredString(item['requestHash'], 'requestHash'),
      attempt: requiredPositiveInteger(item['attempt'], 'attempt'),
      status,
      result: result === null || result === undefined ? null : parseWorkerResult(result),
      leaseExpiresAt: requiredPositiveInteger(item['leaseExpiresAt'], 'leaseExpiresAt'),
    };
  }

  private expiryEpochSeconds(): number {
    return this.nowEpochSeconds() + this.idempotencyTtlSeconds;
  }

  private nowEpochSeconds(): number {
    return Math.floor(this.now().getTime() / 1_000);
  }
}

function manifestKey(scope: UploadScope): { readonly PK: string; readonly SK: string } {
  return {
    PK: partitionKey(scope.ownerId, scope.applicationId),
    SK: `UPLOAD#${encodeKeyPart(scope.uploadId)}#MANIFEST`,
  };
}

function manifestItem(manifest: UploadManifest): Record<string, unknown> {
  return {
    ...manifestKey(manifest),
    entity: 'upload_manifest',
    revision: manifest.revision,
    updatedAt: manifest.updatedAt,
    manifest: structuredClone(manifest),
  };
}

function idempotencyKey(input: {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly idempotencyKey: string;
}): { readonly PK: string; readonly SK: string } {
  return {
    PK: partitionKey(input.ownerId, input.applicationId),
    SK: `INGESTION_IDEMPOTENCY#${encodeKeyPart(input.idempotencyKey)}`,
  };
}

function partitionKey(ownerId: string, applicationId: string): string {
  return `OWNER#${encodeKeyPart(ownerId)}#APP#${encodeKeyPart(applicationId)}`;
}

function encodeKeyPart(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function validateManifest(value: unknown): asserts value is UploadManifest {
  if (value === null || typeof value !== 'object') {
    throw new Error('Upload manifest must be an object');
  }
  const manifest = value as Partial<UploadManifest>;
  if (manifest.schemaVersion !== 1) {
    throw new Error('Unsupported upload manifest schema');
  }
  if (!Number.isSafeInteger(manifest.revision) || (manifest.revision ?? 0) < 1) {
    throw new Error('Upload manifest revision is invalid');
  }
  if (
    typeof manifest.ownerId !== 'string' ||
    typeof manifest.applicationId !== 'string' ||
    typeof manifest.uploadId !== 'string'
  ) {
    throw new Error('Upload manifest scope is invalid');
  }
  validateUploadScope({
    ownerId: manifest.ownerId,
    applicationId: manifest.applicationId,
    uploadId: manifest.uploadId,
  });
  if (
    typeof manifest.updatedAt !== 'string' ||
    typeof manifest.status !== 'string' ||
    !Array.isArray(manifest.parts) ||
    !Array.isArray(manifest.normalizedObjectIds) ||
    !Array.isArray(manifest.authoritativeThreatObjectIds)
  ) {
    throw new Error('Upload manifest fields are invalid');
  }
}

function ensureScopeMatches(scope: UploadScope, manifest: UploadManifest): void {
  if (
    manifest.ownerId !== scope.ownerId ||
    manifest.applicationId !== scope.applicationId ||
    manifest.uploadId !== scope.uploadId
  ) {
    throw new Error('Stored upload manifest does not match its DynamoDB key');
  }
}

function validateIdempotencyInput(input: {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly attempt: number;
}): void {
  validateWorkspaceIdentifier(input.ownerId, 'ownerId');
  validateWorkspaceIdentifier(input.applicationId, 'applicationId');
  validateWorkspaceIdentifier(input.idempotencyKey, 'idempotencyKey');
  if (!/^[a-f0-9]{64}$/.test(input.requestHash)) {
    throw new Error('requestHash must be a lowercase SHA-256 digest');
  }
  if (!Number.isSafeInteger(input.attempt) || input.attempt < 1) {
    throw new Error('attempt must be a positive safe integer');
  }
}

function parseWorkerResult(value: unknown): IngestionWorkerResult {
  const record = asRecord(value);
  if (record === null) {
    throw new Error('Invalid ingestion worker result in DynamoDB');
  }
  const status = record['status'];
  if (status !== 'completed' && status !== 'duplicate' && status !== 'failed') {
    throw new Error('Invalid ingestion worker result status');
  }
  const normalizedObjectIds = record['normalizedObjectIds'];
  if (
    !Array.isArray(normalizedObjectIds) ||
    normalizedObjectIds.some((item) => typeof item !== 'string')
  ) {
    throw new Error('Invalid normalized object IDs in DynamoDB');
  }
  const failureCode = record['failureCode'];
  if (failureCode !== null && typeof failureCode !== 'string') {
    throw new Error('Invalid ingestion failure code in DynamoDB');
  }
  return {
    status,
    uploadId: requiredString(record['uploadId'], 'uploadId'),
    normalizedObjectIds,
    failureCode,
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : null;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${field} in DynamoDB`);
  }
  return value;
}

function requiredPositiveInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`Invalid ${field} in DynamoDB`);
  }
  return value as number;
}

function isConditionalFailure(error: unknown): boolean {
  return (
    error !== null &&
    typeof error === 'object' &&
    (error as { readonly name?: unknown }).name === 'ConditionalCheckFailedException'
  );
}
