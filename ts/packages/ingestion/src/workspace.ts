import {
  canonicalListPrefix,
  canonicalObjectKey,
  locatorForObjectId,
  objectIdFromKey,
} from './keys.js';
import { sha256Base64, sha256Hex } from './hash.js';
import type {
  WorkspaceListScope,
  WorkspaceObject,
  WorkspaceObjectLocator,
  WorkspaceObjectSummary,
  WorkspaceWriteResult,
} from './types.js';

export interface AdapterPutInput {
  readonly key: string;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly checksumSha256: string;
  readonly serverSideEncryption: 'aws:kms';
  readonly ssekmsKeyId: string;
  readonly ifNoneMatch?: '*';
}

export interface AdapterGetInput {
  readonly key: string;
}

export interface AdapterHeadInput {
  readonly key: string;
}

export interface AdapterListInput {
  readonly prefix: string;
}

export interface AdapterCopyInput {
  readonly sourceKey: string;
  readonly destinationKey: string;
  readonly contentType: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly checksumSha256: string;
  readonly serverSideEncryption: 'aws:kms';
  readonly ssekmsKeyId: string;
  readonly ifNoneMatch?: '*';
}

export interface AdapterObject {
  readonly key: string;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly sizeBytes: number;
  readonly metadata: Readonly<Record<string, string>>;
  readonly etag?: string;
}

export type AdapterObjectSummary = Omit<AdapterObject, 'body'>;

export interface ObjectAdapter {
  put(input: AdapterPutInput): Promise<{ readonly etag?: string }>;
  get(input: AdapterGetInput): Promise<AdapterObject | null>;
  head(input: AdapterHeadInput): Promise<AdapterObjectSummary | null>;
  list(input: AdapterListInput): Promise<readonly AdapterObjectSummary[]>;
  copy(input: AdapterCopyInput): Promise<{ readonly etag?: string }>;
}

export class ObjectAlreadyExistsError extends Error {
  public constructor(readonly key: string) {
    super(`Object already exists: ${key}`);
    this.name = 'ObjectAlreadyExistsError';
  }
}

export class ImmutableObjectConflictError extends Error {
  public constructor(readonly locator: WorkspaceObjectLocator) {
    super(`Immutable object already exists with different content: ${locator.objectId}`);
    this.name = 'ImmutableObjectConflictError';
  }
}

export class WorkspaceIntegrityError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'WorkspaceIntegrityError';
  }
}

export interface WorkspaceWriteOptions {
  readonly contentType: string;
  readonly metadata?: Readonly<Record<string, string>>;
  readonly immutable?: boolean;
  readonly expectedSha256?: string;
}

export interface WorkspaceCopyOptions {
  readonly immutable?: boolean;
  readonly contentType?: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

export class S3Workspace {
  public constructor(
    private readonly adapter: ObjectAdapter,
    private readonly kmsKeyId: string,
  ) {
    if (kmsKeyId.trim().length === 0) {
      throw new Error('kmsKeyId is required');
    }
  }

  public async write(
    locator: WorkspaceObjectLocator,
    body: Uint8Array | string,
    options: WorkspaceWriteOptions,
  ): Promise<WorkspaceWriteResult> {
    const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : Uint8Array.from(body);
    const sha256 = sha256Hex(bytes);
    if (options.expectedSha256 !== undefined && options.expectedSha256 !== sha256) {
      throw new WorkspaceIntegrityError('Content does not match expected SHA-256');
    }
    const key = canonicalObjectKey(locator);
    const metadata = normalizeMetadata({
      ...options.metadata,
      sha256,
    });
    const immutable = options.immutable ?? false;
    try {
      const response = await this.adapter.put({
        key,
        body: bytes,
        contentType: options.contentType,
        metadata,
        checksumSha256: sha256Base64(bytes),
        serverSideEncryption: 'aws:kms',
        ssekmsKeyId: this.kmsKeyId,
        ...(immutable ? { ifNoneMatch: '*' as const } : {}),
      });
      return {
        locator,
        contentType: options.contentType,
        sizeBytes: bytes.byteLength,
        sha256,
        metadata,
        ...(response.etag === undefined ? {} : { etag: response.etag }),
        created: true,
      };
    } catch (error) {
      if (!(error instanceof ObjectAlreadyExistsError) || !immutable) {
        throw error;
      }
      const existing = await this.head(locator);
      if (existing?.sha256 !== sha256) {
        throw new ImmutableObjectConflictError(locator);
      }
      return { ...existing, created: false };
    }
  }

  public async read(
    locator: WorkspaceObjectLocator,
    options: { readonly verifyHash?: boolean } = {},
  ): Promise<WorkspaceObject | null> {
    const object = await this.adapter.get({ key: canonicalObjectKey(locator) });
    if (object === null) {
      return null;
    }
    const summary = summaryFromAdapter(locator, object);
    if (options.verifyHash ?? true) {
      const actual = sha256Hex(object.body);
      if (summary.sha256 !== actual) {
        throw new WorkspaceIntegrityError(
          `SHA-256 mismatch for object ${locator.objectId}: expected ${summary.sha256}, received ${actual}`,
        );
      }
    }
    return { ...summary, body: Uint8Array.from(object.body) };
  }

  public async head(locator: WorkspaceObjectLocator): Promise<WorkspaceObjectSummary | null> {
    const object = await this.adapter.head({ key: canonicalObjectKey(locator) });
    return object === null ? null : summaryFromAdapter(locator, object);
  }

  public async exists(locator: WorkspaceObjectLocator): Promise<boolean> {
    return (await this.head(locator)) !== null;
  }

  public async list(scope: WorkspaceListScope): Promise<readonly WorkspaceObjectSummary[]> {
    const objects = await this.adapter.list({ prefix: canonicalListPrefix(scope) });
    return objects
      .map((object) => {
        const objectId = objectIdFromKey(scope, object.key);
        return summaryFromAdapter(locatorForObjectId(scope, objectId), object);
      })
      .sort((left, right) => left.locator.objectId.localeCompare(right.locator.objectId));
  }

  public async copy(
    source: WorkspaceObjectLocator,
    destination: WorkspaceObjectLocator,
    options: WorkspaceCopyOptions = {},
  ): Promise<WorkspaceWriteResult> {
    const sourceObject = await this.head(source);
    if (sourceObject === null) {
      throw new Error(`Source object does not exist: ${source.objectId}`);
    }
    const immutable = options.immutable ?? false;
    const metadata = normalizeMetadata({
      ...sourceObject.metadata,
      ...options.metadata,
      sha256: sourceObject.sha256,
    });
    try {
      const response = await this.adapter.copy({
        sourceKey: canonicalObjectKey(source),
        destinationKey: canonicalObjectKey(destination),
        contentType: options.contentType ?? sourceObject.contentType,
        metadata,
        checksumSha256: hexToBase64(sourceObject.sha256),
        serverSideEncryption: 'aws:kms',
        ssekmsKeyId: this.kmsKeyId,
        ...(immutable ? { ifNoneMatch: '*' as const } : {}),
      });
      return {
        locator: destination,
        contentType: options.contentType ?? sourceObject.contentType,
        sizeBytes: sourceObject.sizeBytes,
        sha256: sourceObject.sha256,
        metadata,
        ...(response.etag === undefined ? {} : { etag: response.etag }),
        created: true,
      };
    } catch (error) {
      if (!(error instanceof ObjectAlreadyExistsError) || !immutable) {
        throw error;
      }
      const existing = await this.head(destination);
      if (existing?.sha256 !== sourceObject.sha256) {
        throw new ImmutableObjectConflictError(destination);
      }
      return { ...existing, created: false };
    }
  }
}

function summaryFromAdapter(
  locator: WorkspaceObjectLocator,
  object: AdapterObjectSummary,
): WorkspaceObjectSummary {
  const sha256 = object.metadata['sha256'];
  if (sha256 === undefined || !/^[a-f0-9]{64}$/.test(sha256)) {
    throw new WorkspaceIntegrityError(`Object ${locator.objectId} has no valid SHA-256 metadata`);
  }
  return {
    locator,
    contentType: object.contentType,
    sizeBytes: object.sizeBytes,
    sha256,
    metadata: object.metadata,
    ...(object.etag === undefined ? {} : { etag: object.etag }),
  };
}

function normalizeMetadata(metadata: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const normalizedKey = key.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(normalizedKey)) {
      throw new Error(`Invalid object metadata key: ${key}`);
    }
    if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) {
      throw new Error(`Invalid control character in object metadata: ${normalizedKey}`);
    }
    normalized[normalizedKey] = value;
  }
  return normalized;
}

function hexToBase64(value: string): string {
  return Buffer.from(value, 'hex').toString('base64');
}

interface StoredObject {
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly etag: string;
  readonly kmsKeyId: string;
}

export class InMemoryObjectAdapter implements ObjectAdapter {
  private readonly objects = new Map<string, StoredObject>();
  public readonly putInputs: AdapterPutInput[] = [];
  public readonly copyInputs: AdapterCopyInput[] = [];

  public async put(input: AdapterPutInput): Promise<{ readonly etag?: string }> {
    assertEncrypted(input);
    this.putInputs.push(clonePutInput(input));
    if (input.ifNoneMatch === '*' && this.objects.has(input.key)) {
      throw new ObjectAlreadyExistsError(input.key);
    }
    const etag = `"${sha256Hex(input.body).slice(0, 32)}"`;
    this.objects.set(input.key, {
      body: Uint8Array.from(input.body),
      contentType: input.contentType,
      metadata: { ...input.metadata },
      etag,
      kmsKeyId: input.ssekmsKeyId,
    });
    return { etag };
  }

  public async get(input: AdapterGetInput): Promise<AdapterObject | null> {
    const object = this.objects.get(input.key);
    return object === undefined ? null : toAdapterObject(input.key, object, true);
  }

  public async head(input: AdapterHeadInput): Promise<AdapterObjectSummary | null> {
    const object = this.objects.get(input.key);
    return object === undefined ? null : toAdapterObject(input.key, object, false);
  }

  public async list(input: AdapterListInput): Promise<readonly AdapterObjectSummary[]> {
    return [...this.objects.entries()]
      .filter(([key]) => key.startsWith(input.prefix))
      .map(([key, object]) => toAdapterObject(key, object, false))
      .sort((left, right) => left.key.localeCompare(right.key));
  }

  public async copy(input: AdapterCopyInput): Promise<{ readonly etag?: string }> {
    assertEncrypted(input);
    this.copyInputs.push({ ...input, metadata: { ...input.metadata } });
    const source = this.objects.get(input.sourceKey);
    if (source === undefined) {
      throw new Error(`Source object does not exist: ${input.sourceKey}`);
    }
    if (input.ifNoneMatch === '*' && this.objects.has(input.destinationKey)) {
      throw new ObjectAlreadyExistsError(input.destinationKey);
    }
    const etag = source.etag;
    this.objects.set(input.destinationKey, {
      body: Uint8Array.from(source.body),
      contentType: input.contentType,
      metadata: { ...input.metadata },
      etag,
      kmsKeyId: input.ssekmsKeyId,
    });
    return { etag };
  }

  public corrupt(locator: WorkspaceObjectLocator, replacement: Uint8Array): void {
    const key = canonicalObjectKey(locator);
    const object = this.objects.get(key);
    if (object === undefined) {
      throw new Error('Cannot corrupt a missing object');
    }
    this.objects.set(key, { ...object, body: Uint8Array.from(replacement) });
  }
}

function assertEncrypted(
  input: Pick<AdapterPutInput, 'serverSideEncryption' | 'ssekmsKeyId'>,
): void {
  if (input.serverSideEncryption !== 'aws:kms' || input.ssekmsKeyId.trim().length === 0) {
    throw new Error('SSE-KMS is required for object writes');
  }
}

function clonePutInput(input: AdapterPutInput): AdapterPutInput {
  return {
    ...input,
    body: Uint8Array.from(input.body),
    metadata: { ...input.metadata },
  };
}

function toAdapterObject(
  key: string,
  object: StoredObject,
  includeBody: true,
): AdapterObject;
function toAdapterObject(
  key: string,
  object: StoredObject,
  includeBody: false,
): AdapterObjectSummary;
function toAdapterObject(
  key: string,
  object: StoredObject,
  includeBody: boolean,
): AdapterObject | AdapterObjectSummary {
  const common: AdapterObjectSummary = {
    key,
    contentType: object.contentType,
    sizeBytes: object.body.byteLength,
    metadata: { ...object.metadata },
    etag: object.etag,
  };
  return includeBody ? { ...common, body: Uint8Array.from(object.body) } : common;
}
