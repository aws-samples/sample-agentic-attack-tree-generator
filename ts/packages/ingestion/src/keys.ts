import { sha256Hex } from './hash.js';
import type {
  RunObjectLocator,
  RunScope,
  UploadObjectLocator,
  UploadScope,
  WorkspaceListScope,
  WorkspaceObjectLocator,
} from './types.js';

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;

export class InvalidWorkspaceIdentifierError extends Error {
  public constructor(readonly field: string, message: string) {
    super(`Invalid ${field}: ${message}`);
    this.name = 'InvalidWorkspaceIdentifierError';
  }
}

export function validateWorkspaceIdentifier(value: string, field: string): string {
  if (value.length === 0) {
    throw new InvalidWorkspaceIdentifierError(field, 'must not be empty');
  }
  if (CONTROL_CHARACTERS.test(value)) {
    throw new InvalidWorkspaceIdentifierError(field, 'control characters are not allowed');
  }
  if (
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    value.includes('%2f') ||
    value.includes('%2F') ||
    value.includes('%5c') ||
    value.includes('%5C')
  ) {
    throw new InvalidWorkspaceIdentifierError(field, 'path syntax and traversal are not allowed');
  }
  if (!SAFE_SEGMENT.test(value)) {
    throw new InvalidWorkspaceIdentifierError(
      field,
      'must be 1-128 ASCII letters, digits, dots, underscores, or hyphens and start alphanumeric',
    );
  }
  return value;
}

export function validateUploadScope(scope: UploadScope): void {
  validateWorkspaceIdentifier(scope.ownerId, 'ownerId');
  validateWorkspaceIdentifier(scope.applicationId, 'applicationId');
  validateWorkspaceIdentifier(scope.uploadId, 'uploadId');
}

export function validateRunScope(scope: RunScope): void {
  validateWorkspaceIdentifier(scope.ownerId, 'ownerId');
  validateWorkspaceIdentifier(scope.applicationId, 'applicationId');
  validateWorkspaceIdentifier(scope.runId, 'runId');
}

export function canonicalObjectKey(locator: WorkspaceObjectLocator): string {
  validateWorkspaceIdentifier(locator.objectId, 'objectId');
  return `${canonicalListPrefix(locator)}${locator.objectId}`;
}

export function canonicalListPrefix(scope: WorkspaceListScope): string {
  if (scope.scope === 'upload') {
    validateUploadScope(scope);
    return `v1/owners/${scope.ownerId}/applications/${scope.applicationId}/uploads/${scope.uploadId}/${scope.area}/`;
  }
  validateRunScope(scope);
  return `v1/owners/${scope.ownerId}/applications/${scope.applicationId}/runs/${scope.runId}/${scope.area}/`;
}

export function objectIdFromKey(scope: WorkspaceListScope, key: string): string {
  const prefix = canonicalListPrefix(scope);
  if (!key.startsWith(prefix)) {
    throw new InvalidWorkspaceIdentifierError('key', 'object is outside the requested scope');
  }
  const objectId = key.slice(prefix.length);
  validateWorkspaceIdentifier(objectId, 'objectId');
  return objectId;
}

export function locatorForObjectId(
  scope: WorkspaceListScope,
  objectId: string,
): WorkspaceObjectLocator {
  validateWorkspaceIdentifier(objectId, 'objectId');
  return { ...scope, objectId } as UploadObjectLocator | RunObjectLocator;
}

export function createObjectId(
  category: 'source' | 'entry' | 'markdown' | 'text' | 'citations' | 'manifest',
  seed: Uint8Array | string,
): string {
  return `${category}-${sha256Hex(seed)}`;
}
