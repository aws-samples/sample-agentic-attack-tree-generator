import { randomUUID } from 'node:crypto';
import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  RunIdSchema,
  UploadIdSchema,
  type ApplicationId,
  type ArtifactId,
  type RunId,
  type UploadId,
} from '@threatforest/types';
import type { Clock, IdFactory } from './contracts.js';

function opaque(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

export const randomIdFactory: IdFactory = {
  applicationId: () => ApplicationIdSchema.parse(opaque('app')),
  runId: () => RunIdSchema.parse(opaque('run')),
  uploadId: () => UploadIdSchema.parse(opaque('upload')),
  artifactId: () => ArtifactIdSchema.parse(opaque('artifact')),
  traceId: () => randomUUID().replaceAll('-', ''),
  ticketId: () => opaque('ticket'),
};

export const ACCOUNT_SCOPE_APPLICATION_ID = 'account' as ApplicationId;

export function asApplicationId(value: unknown): ApplicationId {
  return ApplicationIdSchema.parse(value);
}

export function asRunId(value: unknown): RunId {
  return RunIdSchema.parse(value);
}

export function asUploadId(value: unknown): UploadId {
  return UploadIdSchema.parse(value);
}

export function asArtifactId(value: unknown): ArtifactId {
  return ArtifactIdSchema.parse(value);
}

export function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return slug || 'application';
}

export function copy<T>(value: T): T {
  return structuredClone(value);
}
