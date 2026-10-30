import type { UploadManifest, UploadStatus } from './types.js';
import { validateUploadScope } from './keys.js';

const TRANSITIONS: Readonly<Record<UploadStatus, readonly UploadStatus[]>> = {
  pending: ['uploading', 'cancelled', 'failed'],
  uploading: ['uploaded', 'cancelled', 'failed'],
  uploaded: ['normalizing', 'cancelled', 'failed'],
  normalizing: ['ready', 'failed'],
  ready: [],
  failed: [],
  cancelled: [],
};

export class InvalidUploadTransitionError extends Error {
  public constructor(from: UploadStatus, to: UploadStatus) {
    super(`Upload cannot transition from ${from} to ${to}`);
    this.name = 'InvalidUploadTransitionError';
  }
}

export function createUploadManifest(input: {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly uploadId: string;
  readonly filename: string;
  readonly declaredContentType: string;
  readonly declaredSizeBytes: number;
  readonly now?: string;
}): UploadManifest {
  validateUploadScope(input);
  validateFilename(input.filename);
  if (!Number.isSafeInteger(input.declaredSizeBytes) || input.declaredSizeBytes < 0) {
    throw new Error('declaredSizeBytes must be a non-negative safe integer');
  }
  if (input.declaredContentType.trim().length === 0) {
    throw new Error('declaredContentType is required');
  }
  const now = input.now ?? new Date().toISOString();
  return {
    schemaVersion: 1,
    revision: 1,
    ownerId: input.ownerId,
    applicationId: input.applicationId,
    uploadId: input.uploadId,
    filename: input.filename.normalize('NFC'),
    declaredContentType: input.declaredContentType,
    declaredSizeBytes: input.declaredSizeBytes,
    status: 'pending',
    parts: [],
    sourceObjectId: null,
    sourceSha256: null,
    normalizedObjectIds: [],
    authoritativeThreatObjectIds: [],
    attempt: 0,
    createdAt: now,
    updatedAt: now,
    failureCode: null,
    failureReason: null,
  };
}

export function transitionUploadManifest(
  manifest: UploadManifest,
  status: UploadStatus,
  update: Partial<
    Pick<
      UploadManifest,
      | 'parts'
      | 'sourceObjectId'
      | 'sourceSha256'
      | 'normalizedObjectIds'
      | 'authoritativeThreatObjectIds'
      | 'attempt'
      | 'failureCode'
      | 'failureReason'
    >
  > & { readonly now?: string } = {},
): UploadManifest {
  if (!TRANSITIONS[manifest.status].includes(status)) {
    throw new InvalidUploadTransitionError(manifest.status, status);
  }
  enforceStatusFields(status, update.failureCode ?? null, update.failureReason ?? null);
  const { now, ...fields } = update;
  return {
    ...manifest,
    ...fields,
    revision: manifest.revision + 1,
    status,
    updatedAt: now ?? new Date().toISOString(),
  };
}

export function retryFailedNormalization(
  manifest: UploadManifest,
  now = new Date().toISOString(),
): UploadManifest {
  if (manifest.status !== 'failed' || manifest.sourceObjectId === null) {
    throw new InvalidUploadTransitionError(manifest.status, 'normalizing');
  }
  return {
    ...manifest,
    revision: manifest.revision + 1,
    status: 'normalizing',
    attempt: manifest.attempt + 1,
    updatedAt: now,
    failureCode: null,
    failureReason: null,
  };
}

export function redactFailureReason(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Unknown ingestion error';
  return message
    .replace(/s3:\/\/[^\s]+/gi, '[object]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[credential]')
    .slice(0, 2048);
}

function validateFilename(filename: string): void {
  if (filename.length === 0 || filename.length > 1024) {
    throw new Error('filename must be between 1 and 1024 characters');
  }
  if (/[\u0000-\u001f\u007f-\u009f]/.test(filename)) {
    throw new Error('filename contains control characters');
  }
}

function enforceStatusFields(
  status: UploadStatus,
  failureCode: string | null,
  failureReason: string | null,
): void {
  if (status === 'failed' && (failureCode === null || failureReason === null)) {
    throw new Error('Failed uploads require failureCode and failureReason');
  }
  if (status !== 'failed' && (failureCode !== null || failureReason !== null)) {
    throw new Error('Failure fields are only valid for failed uploads');
  }
}
