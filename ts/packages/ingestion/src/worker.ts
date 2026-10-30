import { sha256Hex, stableJson } from './hash.js';
import { redactFailureReason, transitionUploadManifest } from './manifest.js';
import { UploadNormalizer } from './normalizer.js';
import type {
  IngestionJob,
  IngestionWorkerResult,
  UploadManifest,
  UploadScope,
} from './types.js';
import { validateUploadScope, validateWorkspaceIdentifier } from './keys.js';

export interface UploadManifestStore {
  get(scope: UploadScope): Promise<UploadManifest | null>;
  put(manifest: UploadManifest, expectedRevision: number): Promise<void>;
}

export interface IngestionIdempotencyRecord {
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly attempt: number;
  readonly status: 'in_progress' | 'completed' | 'failed';
  readonly result: IngestionWorkerResult | null;
  readonly leaseExpiresAt: number;
}

export type IdempotencyBeginResult =
  | { readonly state: 'acquired' }
  | { readonly state: 'in_progress' }
  | { readonly state: 'completed'; readonly result: IngestionWorkerResult }
  | { readonly state: 'failed'; readonly result: IngestionWorkerResult };

export interface IngestionIdempotencyStore {
  begin(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly attempt: number;
  }): Promise<IdempotencyBeginResult>;
  complete(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly result: IngestionWorkerResult;
  }): Promise<void>;
  fail(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly result: IngestionWorkerResult;
  }): Promise<void>;
}

export class IdempotencyConflictError extends Error {
  public constructor() {
    super('Idempotency key was reused for a different ingestion request');
    this.name = 'IdempotencyConflictError';
  }
}

export class ManifestConflictError extends Error {
  public constructor() {
    super('Upload manifest changed concurrently');
    this.name = 'ManifestConflictError';
  }
}

export class IngestionAlreadyInProgressError extends Error {
  public constructor() {
    super('Ingestion is already in progress');
    this.name = 'IngestionAlreadyInProgressError';
  }
}

export class IngestionWorker {
  public constructor(
    private readonly manifests: UploadManifestStore,
    private readonly idempotency: IngestionIdempotencyStore,
    private readonly normalizer: UploadNormalizer,
  ) {}

  public async handle(job: IngestionJob): Promise<IngestionWorkerResult> {
    validateJob(job);
    const requestHash = sha256Hex(
      stableJson({
        schemaVersion: job.schemaVersion,
        jobId: job.jobId,
        ownerId: job.ownerId,
        applicationId: job.applicationId,
        uploadId: job.uploadId,
      }),
    );
    const begin = await this.idempotency.begin({
      ownerId: job.ownerId,
      applicationId: job.applicationId,
      idempotencyKey: job.idempotencyKey,
      requestHash,
      attempt: job.attempt,
    });
    if (begin.state === 'completed') {
      return { ...begin.result, status: 'duplicate' };
    }
    if (begin.state === 'failed') {
      return begin.result;
    }
    if (begin.state === 'in_progress') {
      throw new IngestionAlreadyInProgressError();
    }

    const scope: UploadScope = {
      ownerId: job.ownerId,
      applicationId: job.applicationId,
      uploadId: job.uploadId,
    };
    const manifest = await this.manifests.get(scope);
    if (manifest === null) {
      throw new Error('Upload manifest does not exist');
    }
    if (manifest.status === 'ready') {
      const recovered = completedResult(manifest);
      await this.completeIdempotency(job, requestHash, recovered);
      return recovered;
    }
    if (manifest.status === 'failed' && job.attempt <= manifest.attempt) {
      const recovered = failedResult(manifest);
      await this.failIdempotency(job, requestHash, recovered);
      return recovered;
    }

    const inProgress = this.normalizer.beginNormalization(manifest);
    if (inProgress.revision !== manifest.revision) {
      await this.manifests.put(inProgress, manifest.revision);
    }

    let normalized: Awaited<ReturnType<UploadNormalizer['process']>>;
    try {
      normalized = await this.normalizer.process(inProgress);
    } catch (error) {
      if (isRetryableInfrastructureError(error)) {
        throw error;
      }
      const failureCode = ingestionFailureCode(error);
      const failed = transitionUploadManifest(inProgress, 'failed', {
        failureCode,
        failureReason: redactFailureReason(error),
      });
      await this.manifests.put(failed, inProgress.revision);
      const result: IngestionWorkerResult = {
        status: 'failed',
        uploadId: job.uploadId,
        normalizedObjectIds: [],
        failureCode,
      };
      await this.failIdempotency(job, requestHash, result);
      return result;
    }

    await this.manifests.put(normalized.manifest, inProgress.revision);
    const result = completedResult(normalized.manifest);
    await this.completeIdempotency(job, requestHash, result);
    return result;
  }

  private async completeIdempotency(
    job: IngestionJob,
    requestHash: string,
    result: IngestionWorkerResult,
  ): Promise<void> {
    await this.idempotency.complete({
      ownerId: job.ownerId,
      applicationId: job.applicationId,
      idempotencyKey: job.idempotencyKey,
      requestHash,
      result,
    });
  }

  private async failIdempotency(
    job: IngestionJob,
    requestHash: string,
    result: IngestionWorkerResult,
  ): Promise<void> {
    await this.idempotency.fail({
      ownerId: job.ownerId,
      applicationId: job.applicationId,
      idempotencyKey: job.idempotencyKey,
      requestHash,
      result,
    });
  }
}

export class InMemoryUploadManifestStore implements UploadManifestStore {
  private readonly manifests = new Map<string, UploadManifest>();

  public seed(manifest: UploadManifest): void {
    this.manifests.set(scopeKey(manifest), structuredClone(manifest));
  }

  public async get(scope: UploadScope): Promise<UploadManifest | null> {
    const manifest = this.manifests.get(scopeKey(scope));
    return manifest === undefined ? null : structuredClone(manifest);
  }

  public async put(manifest: UploadManifest, expectedRevision: number): Promise<void> {
    const key = scopeKey(manifest);
    const existing = this.manifests.get(key);
    if (existing === undefined || existing.revision !== expectedRevision) {
      throw new ManifestConflictError();
    }
    this.manifests.set(key, structuredClone(manifest));
  }
}

export class InMemoryIngestionIdempotencyStore implements IngestionIdempotencyStore {
  private readonly records = new Map<string, IngestionIdempotencyRecord>();

  public constructor(
    private readonly leaseSeconds = 15 * 60,
    private readonly now: () => Date = () => new Date(),
  ) {}

  public async begin(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly attempt: number;
  }): Promise<IdempotencyBeginResult> {
    const key = idempotencyRecordKey(input);
    const existing = this.records.get(key);
    const nowEpoch = Math.floor(this.now().getTime() / 1_000);
    if (existing !== undefined && existing.requestHash !== input.requestHash) {
      throw new IdempotencyConflictError();
    }
    if (existing === undefined || (existing.status === 'failed' && input.attempt > existing.attempt)) {
      this.records.set(key, {
        idempotencyKey: input.idempotencyKey,
        requestHash: input.requestHash,
        attempt: input.attempt,
        status: 'in_progress',
        result: null,
        leaseExpiresAt: nowEpoch + this.leaseSeconds,
      });
      return { state: 'acquired' };
    }
    if (existing.status === 'in_progress' && existing.leaseExpiresAt <= nowEpoch) {
      this.records.set(key, {
        ...existing,
        attempt: input.attempt,
        leaseExpiresAt: nowEpoch + this.leaseSeconds,
      });
      return { state: 'acquired' };
    }
    if (existing.status === 'in_progress') {
      return { state: 'in_progress' };
    }
    if (existing.result === null) {
      throw new Error('Terminal idempotency record has no result');
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
    this.finish(input, 'completed');
  }

  public async fail(input: {
    readonly ownerId: string;
    readonly applicationId: string;
    readonly idempotencyKey: string;
    readonly requestHash: string;
    readonly result: IngestionWorkerResult;
  }): Promise<void> {
    this.finish(input, 'failed');
  }

  private finish(
    input: {
      readonly ownerId: string;
      readonly applicationId: string;
      readonly idempotencyKey: string;
      readonly requestHash: string;
      readonly result: IngestionWorkerResult;
    },
    status: 'completed' | 'failed',
  ): void {
    const key = idempotencyRecordKey(input);
    const existing = this.records.get(key);
    if (
      existing === undefined ||
      existing.requestHash !== input.requestHash ||
      existing.status !== 'in_progress'
    ) {
      throw new IdempotencyConflictError();
    }
    this.records.set(key, {
      ...existing,
      status,
      result: structuredClone(input.result),
    });
  }
}

function validateJob(job: IngestionJob): void {
  if (job.schemaVersion !== 1) {
    throw new Error('Unsupported ingestion job schema');
  }
  validateUploadScope(job);
  validateWorkspaceIdentifier(job.jobId, 'jobId');
  validateWorkspaceIdentifier(job.idempotencyKey, 'idempotencyKey');
  if (!Number.isSafeInteger(job.attempt) || job.attempt < 1) {
    throw new Error('Ingestion attempt must be a positive safe integer');
  }
  if (Number.isNaN(Date.parse(job.enqueuedAt))) {
    throw new Error('Ingestion enqueuedAt must be an ISO timestamp');
  }
}

function scopeKey(scope: UploadScope): string {
  validateUploadScope(scope);
  return `${scope.ownerId}\u0000${scope.applicationId}\u0000${scope.uploadId}`;
}

function idempotencyRecordKey(input: {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly idempotencyKey: string;
}): string {
  validateWorkspaceIdentifier(input.ownerId, 'ownerId');
  validateWorkspaceIdentifier(input.applicationId, 'applicationId');
  validateWorkspaceIdentifier(input.idempotencyKey, 'idempotencyKey');
  return `${input.ownerId}\u0000${input.applicationId}\u0000${input.idempotencyKey}`;
}

function ingestionFailureCode(error: unknown): string {
  if (error !== null && typeof error === 'object') {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code)) {
      return code;
    }
  }
  return 'INGESTION_FAILED';
}

function completedResult(manifest: UploadManifest): IngestionWorkerResult {
  return {
    status: 'completed',
    uploadId: manifest.uploadId,
    normalizedObjectIds: manifest.normalizedObjectIds,
    failureCode: null,
  };
}

function failedResult(manifest: UploadManifest): IngestionWorkerResult {
  return {
    status: 'failed',
    uploadId: manifest.uploadId,
    normalizedObjectIds: [],
    failureCode: manifest.failureCode ?? 'INGESTION_FAILED',
  };
}

function isRetryableInfrastructureError(error: unknown): boolean {
  if (error instanceof ManifestConflictError) {
    return true;
  }
  if (error === null || typeof error !== 'object') {
    return false;
  }
  const record = error as Record<string, unknown>;
  if (record['$retryable'] === true) {
    return true;
  }
  const metadata = record['$metadata'];
  const status =
    metadata !== null && typeof metadata === 'object'
      ? (metadata as Record<string, unknown>)['httpStatusCode']
      : undefined;
  if (typeof status === 'number' && (status === 429 || status >= 500)) {
    return true;
  }
  const name = typeof record['name'] === 'string' ? record['name'] : '';
  return [
    'AbortError',
    'InternalServerError',
    'ProvisionedThroughputExceededException',
    'RequestTimeout',
    'ServiceUnavailable',
    'ThrottlingException',
  ].includes(name);
}
