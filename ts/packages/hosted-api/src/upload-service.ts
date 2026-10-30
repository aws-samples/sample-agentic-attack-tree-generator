import {
  UploadManifestSchema,
  type ApplicationId,
  type ArtifactRef,
  type UploadId,
  type UserId,
} from '@threatforest/types';
import {
  conflict,
  notFound,
  unprocessable,
} from './errors.js';
import type {
  Clock,
  IdFactory,
  MultipartCompletionRecord,
  MultipartInitiateRequest,
  MultipartInspection,
  MultipartPartSignature,
  MultipartStorageAdapter,
  MutationContext,
  MutationResponseRecord,
  NormalizationOrchestrator,
  UploadSessionRecord,
  UploadSessionStore,
} from './contracts.js';
import { ApplicationService } from './application-service.js';
import { IdempotencyExecutor } from './idempotency.js';
import { asArtifactId, asUploadId } from './runtime.js';

const CHECKSUM_PATTERN = /^[a-f0-9]{64}$/;
const MIN_MULTIPART_PART_BYTES = 5 * 1024 * 1024;
const COMPLETION_LEASE_MILLISECONDS = 60_000;

export interface UploadServiceOptions {
  applications: ApplicationService;
  sessions: UploadSessionStore;
  storage: MultipartStorageAdapter;
  normalization: NormalizationOrchestrator;
  idempotency: IdempotencyExecutor;
  ids: IdFactory;
  clock: Clock;
  bucket: string;
  kmsKeyId: string;
  maximumSizeBytes?: number;
  defaultPartSizeBytes?: number;
  presignLifetimeSeconds?: number;
}

interface CreateUploadInput {
  filename: string;
  content_type: string;
  size_bytes: number;
  checksum_sha256: string;
  part_size_bytes?: number;
}

interface PresignPartInput {
  part_number: number;
  size_bytes: number;
  checksum_sha256: string;
}

interface CompleteUploadInput {
  parts: Array<{
    part_number: number;
    size_bytes: number;
    etag: string;
    checksum_sha256: string;
  }>;
}

function objectInput(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw unprocessable('Upload request must be a JSON object.');
  }
  return value as Record<string, unknown>;
}

function stringField(input: Record<string, unknown>, field: string): string {
  const value = input[field];
  if (typeof value !== 'string') {
    throw unprocessable(`${field} must be a string.`);
  }
  return value;
}

function integerField(input: Record<string, unknown>, field: string): number {
  const value = input[field];
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw unprocessable(`${field} must be a positive integer.`);
  }
  return value as number;
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const match = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  );
  return match?.[1];
}

function sameInitiation(
  expected: MultipartInitiateRequest,
  actual: MultipartInspection,
): boolean {
  return (
    expected.bucket === actual.bucket &&
    expected.key === actual.key &&
    expected.contentType === actual.contentType &&
    expected.sizeBytes === actual.sizeBytes &&
    expected.checksumSha256 === actual.checksumSha256 &&
    expected.kmsKeyId === actual.kmsKeyId
  );
}

export class UploadService {
  readonly #applications: ApplicationService;
  readonly #sessions: UploadSessionStore;
  readonly #storage: MultipartStorageAdapter;
  readonly #normalization: NormalizationOrchestrator;
  readonly #idempotency: IdempotencyExecutor;
  readonly #ids: IdFactory;
  readonly #clock: Clock;
  readonly #bucket: string;
  readonly #kmsKeyId: string;
  readonly #maximumSizeBytes: number;
  readonly #defaultPartSizeBytes: number;
  readonly #presignLifetimeSeconds: number;

  constructor(options: UploadServiceOptions) {
    if (!options.bucket || !options.kmsKeyId) {
      throw new Error('upload bucket and KMS key ID are required');
    }
    this.#applications = options.applications;
    this.#sessions = options.sessions;
    this.#storage = options.storage;
    this.#normalization = options.normalization;
    this.#idempotency = options.idempotency;
    this.#ids = options.ids;
    this.#clock = options.clock;
    this.#bucket = options.bucket;
    this.#kmsKeyId = options.kmsKeyId;
    this.#maximumSizeBytes = options.maximumSizeBytes ?? 5 * 1024 ** 4;
    this.#defaultPartSizeBytes =
      options.defaultPartSizeBytes ?? 16 * 1024 * 1024;
    this.#presignLifetimeSeconds = options.presignLifetimeSeconds ?? 900;
  }

  async create(
    context: MutationContext,
    applicationId: ApplicationId,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = this.#parseCreate(value);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'create_upload',
      input,
      async () => {
        await this.#applications.requireWritable(
          context.ownerId,
          applicationId,
        );
        const uploadId = this.#ids.uploadId();
        const partSizeBytes = input.part_size_bytes ?? this.#defaultPartSizeBytes;
        if (partSizeBytes < MIN_MULTIPART_PART_BYTES) {
          throw unprocessable(
            `part_size_bytes must be at least ${MIN_MULTIPART_PART_BYTES}.`,
          );
        }
        const partCount = Math.ceil(input.size_bytes / partSizeBytes);
        if (partCount > 10_000) {
          throw unprocessable('Multipart upload would exceed the 10,000 part limit.');
        }
        const now = this.#clock.now().toISOString();
        const source = this.#normalization.describeSource({
          ownerId: context.ownerId,
          applicationId,
          uploadId,
          checksumSha256: input.checksum_sha256,
        });
        const key = source.objectKey;
        const initiation: MultipartInitiateRequest = {
          bucket: this.#bucket,
          key,
          contentType: input.content_type,
          sizeBytes: input.size_bytes,
          checksumSha256: input.checksum_sha256,
          kmsKeyId: this.#kmsKeyId,
          metadata: {
            owner_id: context.ownerId,
            application_id: applicationId,
            upload_id: uploadId,
            sha256: input.checksum_sha256,
            checksum_sha256: input.checksum_sha256,
          },
        };
        const initiated = await this.#storage.initiate(initiation);
        if (!initiated.storageUploadId) {
          throw new Error('storage adapter returned an empty multipart upload ID');
        }
        try {
          await this.#normalization.createPending({
            ownerId: context.ownerId,
            applicationId,
            uploadId,
            filename: input.filename,
            contentType: input.content_type,
            sizeBytes: input.size_bytes,
          });
        } catch (error) {
          await this.#storage
            .abort({
              ...initiation,
              storageUploadId: initiated.storageUploadId,
            })
            .catch(() => {});
          throw error;
        }
        const manifest = UploadManifestSchema.parse({
          schema_version: 1,
          owner_id: context.ownerId,
          upload_id: uploadId,
          application_id: applicationId,
          filename: input.filename,
          content_type: input.content_type,
          size_bytes: input.size_bytes,
          status: 'pending',
          parts: [],
          source_artifact: null,
          normalized_artifacts: [],
          created_at: now,
          updated_at: now,
          failure_reason: null,
        });
        const session: UploadSessionRecord = {
          manifest,
          bucket: this.#bucket,
          key,
          sourceObjectId: source.sourceObjectId,
          kmsKeyId: this.#kmsKeyId,
          checksumSha256: input.checksum_sha256,
          storageUploadId: initiated.storageUploadId,
          partSizeBytes,
          partCount,
          signedParts: {},
        };
        await this.#sessions.put(scope, session);
        return {
          status: 201,
          value: {
            upload_id: uploadId,
            manifest,
            part_size_bytes: partSizeBytes,
            part_count: partCount,
          },
        };
      },
    );
  }

  async get(
    ownerId: UserId,
    applicationId: ApplicationId,
    uploadId: UploadId,
  ): Promise<UploadSessionRecord> {
    await this.#applications.require(ownerId, applicationId);
    const session = await this.#sessions.get(
      { owner_id: ownerId, application_id: applicationId },
      uploadId,
    );
    if (session === null) {
      throw notFound(`Upload ${uploadId} was not found.`);
    }
    const normalization = await this.#normalization.status(
      { owner_id: ownerId, application_id: applicationId },
      uploadId,
    );
    if (
      normalization !== null &&
      ['normalizing', 'ready', 'failed'].includes(normalization.status)
    ) {
      session.manifest = {
        ...session.manifest,
        status: normalization.status,
        failure_reason:
          normalization.status === 'failed'
            ? normalization.failureCode ?? 'INGESTION_FAILED'
            : null,
      };
    }
    return session;
  }

  async presignPart(
    context: MutationContext,
    applicationId: ApplicationId,
    uploadId: UploadId,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = this.#parsePart(value);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'presign_upload_part',
      { uploadId, input },
      async () => {
        const session = await this.get(
          context.ownerId,
          applicationId,
          uploadId,
        );
        if (
          !['pending', 'uploading'].includes(session.manifest.status) ||
          session.completion !== undefined
        ) {
          throw conflict(`Upload ${uploadId} is ${session.manifest.status}.`);
        }
        if (input.part_number > session.partCount) {
          throw unprocessable(
            `part_number must be between 1 and ${session.partCount}.`,
          );
        }
        const expectedSize = this.#expectedPartSize(session, input.part_number);
        if (input.size_bytes !== expectedSize) {
          throw unprocessable(
            `Part ${input.part_number} must contain exactly ${expectedSize} bytes.`,
          );
        }
        const request = {
          ...this.#initiation(session),
          storageUploadId: session.storageUploadId,
          partNumber: input.part_number,
          partSizeBytes: input.size_bytes,
          partChecksumSha256: input.checksum_sha256,
          expiresInSeconds: this.#presignLifetimeSeconds,
        };
        const signature = await this.#storage.presignPart(request);
        this.#assertSignature(signature, input.checksum_sha256);
        const signedAt = this.#clock.now().toISOString();
        const recorded = await this.#sessions.recordSignedPart(
          scope,
          uploadId,
          {
            partNumber: input.part_number,
            sizeBytes: input.size_bytes,
            checksumSha256: input.checksum_sha256,
          },
          signedAt,
        );
        if (recorded === null) {
          throw conflict(
            `Upload ${uploadId} started completion while the part was being signed.`,
            'completion_in_progress',
          );
        }
        return {
          status: 200,
          value: {
            upload_id: uploadId,
            part_number: input.part_number,
            url: signature.url,
            expires_at: signature.expiresAt,
            headers: signature.headers,
          },
        };
      },
    );
  }

  async complete(
    context: MutationContext,
    applicationId: ApplicationId,
    uploadId: UploadId,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = this.#parseComplete(value);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'complete_upload',
      { uploadId, input },
      async () => {
        let session = await this.get(context.ownerId, applicationId, uploadId);
        if (['uploaded', 'normalizing', 'ready'].includes(session.manifest.status)) {
          await this.#normalization.markUploaded({
            ownerId: context.ownerId,
            applicationId,
            uploadId,
            sourceObjectId: session.sourceObjectId,
            sourceSha256: session.checksumSha256,
            parts: session.manifest.parts.map((part) => {
              if (part.etag === null || part.checksum_sha256 === null) {
                throw new Error(
                  `Completed upload ${uploadId} has incomplete metadata for part ${part.part_number}`,
                );
              }
              return {
                partNumber: part.part_number,
                sizeBytes: part.size_bytes,
                etag: part.etag,
                checksumSha256: part.checksum_sha256,
              };
            }),
          });
          await this.#normalization.dispatch({
            ownerId: context.ownerId,
            applicationId,
            uploadId,
          });
          return {
            status: 200,
            value: { upload_id: uploadId, manifest: session.manifest },
          };
        }
        if (!['pending', 'uploading'].includes(session.manifest.status)) {
          throw conflict(`Upload ${uploadId} is ${session.manifest.status}.`);
        }
        this.#assertClientParts(session, input.parts);
        if (session.completion !== undefined) {
          this.#assertCompletionParts(session, input.parts);
          session = await this.#claimCompletion(
            scope,
            session,
            context.idempotencyKey,
          );
          await this.#ensureStorageCompleted(session);
          return this.#finalizeCompletion(
            scope,
            session,
            context.ownerId,
            applicationId,
            uploadId,
          );
        }
        const initiation = this.#initiation(session);
        const inspection = await this.#storage.inspect({
          ...initiation,
          storageUploadId: session.storageUploadId,
        });
        this.#assertInspection(session, inspection, input.parts);
        const startedAt = this.#clock.now().toISOString();
        const completion: MultipartCompletionRecord = {
          state: 'completing',
          parts: inspection.parts,
          startedAt,
          completedAt: null,
          storageVersionId: null,
          claimId: context.idempotencyKey,
          claimExpiresAt: new Date(
            Date.parse(startedAt) + COMPLETION_LEASE_MILLISECONDS,
          ).toISOString(),
        };
        const claimed = await this.#sessions.claimCompletion(
          scope,
          uploadId,
          completion,
          startedAt,
        );
        if (claimed === null) {
          throw conflict(
            'Upload completion is already in progress.',
            'completion_in_progress',
          );
        }
        session = claimed;
        const completed = await this.#storage.complete({
          ...initiation,
          storageUploadId: session.storageUploadId,
          parts: inspection.parts,
        });
        const activeCompletion = session.completion;
        if (activeCompletion === undefined) {
          throw new Error(`Upload ${uploadId} lost its completion journal.`);
        }
        session.completion = {
          ...activeCompletion,
          state: 'completed',
          completedAt: this.#clock.now().toISOString(),
          storageVersionId: completed.versionId,
        };
        return this.#finalizeCompletion(
          scope,
          session,
          context.ownerId,
          applicationId,
          uploadId,
        );
      },
    );
  }

  async abort(
    context: MutationContext,
    applicationId: ApplicationId,
    uploadId: UploadId,
  ): Promise<MutationResponseRecord> {
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'abort_upload',
      { uploadId },
      async () => {
        const session = await this.get(context.ownerId, applicationId, uploadId);
        if (
          session.completion !== undefined &&
          ['pending', 'uploading'].includes(session.manifest.status)
        ) {
          throw conflict('A completing upload cannot be cancelled.');
        }
        if (!['uploaded', 'ready', 'cancelled'].includes(session.manifest.status)) {
          await this.#storage.abort({
            ...this.#initiation(session),
            storageUploadId: session.storageUploadId,
          });
        }
        session.manifest = {
          ...session.manifest,
          status: 'cancelled',
          updated_at: this.#clock.now().toISOString(),
        };
        await this.#sessions.put(scope, session);
        return { status: 200, value: { success: true } };
      },
    );
  }

  #parseCreate(value: unknown): CreateUploadInput {
    const input = objectInput(value);
    const filename = stringField(input, 'filename').trim();
    const contentType = stringField(input, 'content_type').trim().toLowerCase();
    const checksum = stringField(input, 'checksum_sha256');
    const sizeBytes = integerField(input, 'size_bytes');
    if (
      filename.length === 0 ||
      filename.length > 1024 ||
      filename.includes('/') ||
      filename.includes('\\') ||
      filename.includes('\0') ||
      filename === '.' ||
      filename === '..'
    ) {
      throw unprocessable('filename must be a safe basename of 1-1024 characters.');
    }
    if (
      contentType.length === 0 ||
      contentType.length > 255 ||
      /[\r\n\0]/.test(contentType)
    ) {
      throw unprocessable('content_type is invalid.');
    }
    if (!CHECKSUM_PATTERN.test(checksum)) {
      throw unprocessable('checksum_sha256 must be a lowercase hexadecimal SHA-256.');
    }
    if (sizeBytes > this.#maximumSizeBytes) {
      throw unprocessable(`Upload exceeds the ${this.#maximumSizeBytes} byte limit.`);
    }
    let partSizeBytes: number | undefined;
    if (input.part_size_bytes !== undefined) {
      partSizeBytes = integerField(input, 'part_size_bytes');
    }
    return {
      filename,
      content_type: contentType,
      size_bytes: sizeBytes,
      checksum_sha256: checksum,
      ...(partSizeBytes === undefined ? {} : { part_size_bytes: partSizeBytes }),
    };
  }

  #parsePart(value: unknown): PresignPartInput {
    const input = objectInput(value);
    const checksum = stringField(input, 'checksum_sha256');
    if (!CHECKSUM_PATTERN.test(checksum)) {
      throw unprocessable('checksum_sha256 must be a lowercase hexadecimal SHA-256.');
    }
    return {
      part_number: integerField(input, 'part_number'),
      size_bytes: integerField(input, 'size_bytes'),
      checksum_sha256: checksum,
    };
  }

  #parseComplete(value: unknown): CompleteUploadInput {
    const input = objectInput(value);
    if (!Array.isArray(input.parts) || input.parts.length === 0) {
      throw unprocessable('parts must be a non-empty array.');
    }
    const parts = input.parts.map((part): CompleteUploadInput['parts'][number] => {
      const record = objectInput(part);
      const checksum = stringField(record, 'checksum_sha256');
      const etag = stringField(record, 'etag');
      if (!CHECKSUM_PATTERN.test(checksum)) {
        throw unprocessable('Each part checksum must be lowercase hexadecimal SHA-256.');
      }
      if (etag.length === 0 || etag.length > 1024 || /[\r\n\0]/.test(etag)) {
        throw unprocessable('Part ETag is invalid.');
      }
      return {
        part_number: integerField(record, 'part_number'),
        size_bytes: integerField(record, 'size_bytes'),
        etag,
        checksum_sha256: checksum,
      };
    });
    return { parts };
  }

  #expectedPartSize(session: UploadSessionRecord, partNumber: number): number {
    if (partNumber < session.partCount) {
      return session.partSizeBytes;
    }
    return (
      session.manifest.size_bytes -
      session.partSizeBytes * (session.partCount - 1)
    );
  }

  #assertSignature(signature: MultipartPartSignature, checksum: string): void {
    if (!/^https:\/\//.test(signature.url)) {
      throw new Error('storage adapter returned a non-HTTPS presigned URL');
    }
    const encodedChecksum = Buffer.from(checksum, 'hex').toString('base64');
    if (
      headerValue(signature.headers, 'x-amz-checksum-sha256') !== encodedChecksum
    ) {
      throw new Error('presigned request does not enforce the expected part checksum');
    }
  }

  #assertClientParts(
    session: UploadSessionRecord,
    parts: CompleteUploadInput['parts'],
  ): void {
    if (parts.length !== session.partCount) {
      throw unprocessable(`Upload requires exactly ${session.partCount} parts.`);
    }
    const numbers = new Set<number>();
    for (const part of parts) {
      if (numbers.has(part.part_number)) {
        throw unprocessable(`Part ${part.part_number} is duplicated.`);
      }
      numbers.add(part.part_number);
      const signed = session.signedParts[String(part.part_number)];
      if (
        signed === undefined ||
        signed.sizeBytes !== part.size_bytes ||
        signed.checksumSha256 !== part.checksum_sha256 ||
        part.size_bytes !== this.#expectedPartSize(session, part.part_number)
      ) {
        throw unprocessable(`Part ${part.part_number} does not match its signed constraints.`);
      }
    }
  }

  #assertInspection(
    session: UploadSessionRecord,
    inspection: MultipartInspection,
    clientParts: CompleteUploadInput['parts'],
  ): void {
    const initiation = this.#initiation(session);
    if (
      inspection.storageUploadId !== session.storageUploadId ||
      !sameInitiation(initiation, inspection)
    ) {
      throw conflict(
        'Stored multipart metadata does not match the upload session.',
        'upload_constraint_mismatch',
      );
    }
    if (inspection.parts.length !== session.partCount) {
      throw conflict('Stored multipart parts are incomplete.', 'upload_constraint_mismatch');
    }
    const byNumber = new Map(clientParts.map((part) => [part.part_number, part]));
    let total = 0;
    for (const observed of inspection.parts) {
      const client = byNumber.get(observed.partNumber);
      if (
        client === undefined ||
        observed.sizeBytes !== client.size_bytes ||
        observed.checksumSha256 !== client.checksum_sha256 ||
        observed.etag !== client.etag
      ) {
        throw conflict(
          `Stored part ${observed.partNumber} does not match completion input.`,
          'upload_constraint_mismatch',
        );
      }
      total += observed.sizeBytes;
    }
    if (total !== session.manifest.size_bytes) {
      throw conflict(
        'Stored multipart size does not match the expected object size.',
        'upload_constraint_mismatch',
      );
    }
  }

  #assertCompletionParts(
    session: UploadSessionRecord,
    clientParts: CompleteUploadInput['parts'],
  ): void {
    const completed = session.completion?.parts;
    const byNumber = new Map(
      clientParts.map((part) => [part.part_number, part]),
    );
    if (
      completed === undefined ||
      completed.length !== clientParts.length ||
      completed.some((part) => {
        const client = byNumber.get(part.partNumber);
        return (
          client === undefined ||
          client.size_bytes !== part.sizeBytes ||
          client.etag !== part.etag ||
          client.checksum_sha256 !== part.checksumSha256
        );
      })
    ) {
      throw conflict(
        'Upload completion input does not match the durable completion.',
        'upload_constraint_mismatch',
      );
    }
  }

  async #finalizeCompletion(
    scope: { owner_id: UserId; application_id: ApplicationId },
    session: UploadSessionRecord,
    ownerId: UserId,
    applicationId: ApplicationId,
    uploadId: UploadId,
  ): Promise<MutationResponseRecord> {
    const completion = session.completion;
    if (completion === undefined) {
      throw new Error(`Upload ${uploadId} has no durable completion state.`);
    }
    const completedAt =
      completion.completedAt ?? this.#clock.now().toISOString();
    const artifact: ArtifactRef = {
      artifact_id: asArtifactId(uploadId),
      kind: 'source',
      version: 1,
      content_type: session.manifest.content_type,
      size_bytes: session.manifest.size_bytes,
      sha256: session.checksumSha256,
      created_at: completedAt,
    };
    session.completion = {
      ...completion,
      state: 'completed',
      completedAt,
    };
    session.manifest = {
      ...session.manifest,
      status: 'uploaded',
      source_artifact: artifact,
      parts: completion.parts.map((part) => ({
        part_number: part.partNumber,
        size_bytes: part.sizeBytes,
        etag: part.etag,
        checksum_sha256: part.checksumSha256,
      })),
      updated_at: completedAt,
    };
    await this.#sessions.put(scope, session);
    await this.#normalization.markUploaded({
      ownerId,
      applicationId,
      uploadId,
      sourceObjectId: session.sourceObjectId,
      sourceSha256: session.checksumSha256,
      parts: completion.parts,
    });
    await this.#normalization.dispatch({ ownerId, applicationId, uploadId });
    return {
      status: 200,
      value: { upload_id: uploadId, manifest: session.manifest },
    };
  }

  async #ensureStorageCompleted(
    session: UploadSessionRecord,
  ): Promise<void> {
    const completion = session.completion;
    if (completion === undefined || completion.state === 'completed') {
      return;
    }
    const initiation = this.#initiation(session);
    const observed = await this.#storage.inspectCompleted({
      ...initiation,
      parts: completion.parts,
    });
    const completed =
      observed ??
      (await this.#storage.complete({
        ...initiation,
        storageUploadId: session.storageUploadId,
        parts: completion.parts,
      }));
    session.completion = {
      ...completion,
      state: 'completed',
      completedAt: this.#clock.now().toISOString(),
      storageVersionId: completed.versionId,
    };
  }

  async #claimCompletion(
    scope: { owner_id: UserId; application_id: ApplicationId },
    session: UploadSessionRecord,
    claimId: string,
  ): Promise<UploadSessionRecord> {
    const existing = session.completion;
    if (existing === undefined) {
      throw new Error(
        `Upload ${session.manifest.upload_id} has no completion journal.`,
      );
    }
    const claimedAt = this.#clock.now().toISOString();
    const claimed = await this.#sessions.claimCompletion(
      scope,
      session.manifest.upload_id,
      {
        ...existing,
        claimId,
        claimExpiresAt: new Date(
          Date.parse(claimedAt) + COMPLETION_LEASE_MILLISECONDS,
        ).toISOString(),
      },
      claimedAt,
    );
    if (claimed === null) {
      throw conflict(
        'Upload completion is already in progress.',
        'completion_in_progress',
      );
    }
    return claimed;
  }

  #initiation(session: UploadSessionRecord): MultipartInitiateRequest {
    return {
      bucket: session.bucket,
      key: session.key,
      contentType: session.manifest.content_type,
      sizeBytes: session.manifest.size_bytes,
      checksumSha256: session.checksumSha256,
      kmsKeyId: session.kmsKeyId,
      metadata: {
        owner_id: session.manifest.owner_id,
        application_id: session.manifest.application_id,
        upload_id: session.manifest.upload_id,
        sha256: session.checksumSha256,
        checksum_sha256: session.checksumSha256,
      },
    };
  }

}

export function uploadId(value: unknown): UploadId {
  return asUploadId(value);
}
