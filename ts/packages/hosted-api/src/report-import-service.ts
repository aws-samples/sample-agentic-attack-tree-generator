import type { ApplicationId, UploadId, UserId } from '@threatforest/types';
import { encodeKeyPart } from '@threatforest/control-plane';
import { conflict, notFound, unprocessable } from './errors.js';
import type {
  Clock,
  CompletedPart,
  IdFactory,
  MultipartInitiateRequest,
  MultipartCompletionRecord,
  MultipartInspection,
  MultipartPartSignature,
  MultipartStorageAdapter,
  MutationContext,
  MutationResponseRecord,
  SignedMultipartPart,
} from './contracts.js';
import { IdempotencyExecutor } from './idempotency.js';
import { ACCOUNT_SCOPE_APPLICATION_ID, asUploadId } from './runtime.js';

const CHECKSUM_PATTERN = /^[a-f0-9]{64}$/;
const MIN_MULTIPART_PART_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAXIMUM_REPORT_BYTES = 200 * 1024 * 1024;
const COMPLETION_LEASE_MILLISECONDS = 60_000;

export type ReportImportStatus =
  | 'pending'
  | 'uploading'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface ReportImportResult {
  bundle: string;
  status: 'imported' | 'merged' | 'skipped' | 'failed';
  folder_name: string | null;
  versions_added: string[];
  versions_skipped: string[];
  error: string | null;
}

export interface ReportImportSession {
  schemaVersion: 1;
  importId: UploadId;
  ownerId: UserId;
  filename: string;
  contentType: string;
  sizeBytes: number;
  checksumSha256: string;
  bucket: string;
  key: string;
  kmsKeyId: string;
  storageUploadId: string;
  partSizeBytes: number;
  partCount: number;
  signedParts: Record<
    string,
    { sizeBytes: number; checksumSha256: string; signedAt: string }
  >;
  completedParts: CompletedPart[];
  completion?: MultipartCompletionRecord;
  destination?: ReportImportDestination;
  workerLease?: ReportImportWorkerLease | null;
  status: ReportImportStatus;
  result: ReportImportResult | null;
  failureCode: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ReportImportDestination {
  mode: 'new' | 'merge';
  applicationId: ApplicationId;
  name: string;
  importedAt: string;
}

export interface ReportImportWorkerLease {
  leaseId: string;
  acquiredAt: string;
  expiresAt: string;
}

export interface ReportImportStore {
  get(ownerId: UserId, importId: UploadId): Promise<ReportImportSession | null>;
  put(session: ReportImportSession): Promise<void>;
  list(ownerId: UserId): Promise<ReportImportSession[]>;
  recordSignedPart(
    ownerId: UserId,
    importId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<ReportImportSession | null>;
  claimCompletion(
    ownerId: UserId,
    importId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<ReportImportSession | null>;
  acquireProcessingLease?(
    ownerId: UserId,
    importId: UploadId,
    lease: ReportImportWorkerLease,
  ): Promise<ReportImportSession | null>;
  saveLeased?(
    session: ReportImportSession,
    leaseId: string,
  ): Promise<boolean>;
}

export interface ReportImportDispatcher {
  dispatch(ownerId: UserId, importId: UploadId): Promise<void>;
}

export interface ReportImportServiceOptions {
  store: ReportImportStore;
  storage: MultipartStorageAdapter;
  dispatcher: ReportImportDispatcher;
  idempotency: IdempotencyExecutor;
  ids: IdFactory;
  clock: Clock;
  bucket: string;
  kmsKeyId: string;
  maximumSizeBytes?: number;
  defaultPartSizeBytes?: number;
  presignLifetimeSeconds?: number;
}

interface CreateInput {
  filename: string;
  content_type: string;
  size_bytes: number;
  checksum_sha256: string;
  part_size_bytes?: number;
}

interface PartInput {
  part_number: number;
  size_bytes: number;
  checksum_sha256: string;
}

interface CompleteInput {
  parts: Array<{
    part_number: number;
    size_bytes: number;
    etag: string;
    checksum_sha256: string;
  }>;
}

export class ReportImportService {
  readonly #store: ReportImportStore;
  readonly #storage: MultipartStorageAdapter;
  readonly #dispatcher: ReportImportDispatcher;
  readonly #idempotency: IdempotencyExecutor;
  readonly #ids: IdFactory;
  readonly #clock: Clock;
  readonly #bucket: string;
  readonly #kmsKeyId: string;
  readonly #maximumSizeBytes: number;
  readonly #defaultPartSizeBytes: number;
  readonly #presignLifetimeSeconds: number;

  constructor(options: ReportImportServiceOptions) {
    this.#store = options.store;
    this.#storage = options.storage;
    this.#dispatcher = options.dispatcher;
    this.#idempotency = options.idempotency;
    this.#ids = options.ids;
    this.#clock = options.clock;
    this.#bucket = required(options.bucket, 'report import bucket');
    this.#kmsKeyId = required(options.kmsKeyId, 'report import KMS key');
    this.#maximumSizeBytes =
      options.maximumSizeBytes ?? DEFAULT_MAXIMUM_REPORT_BYTES;
    this.#defaultPartSizeBytes =
      options.defaultPartSizeBytes ?? 16 * 1024 * 1024;
    this.#presignLifetimeSeconds = options.presignLifetimeSeconds ?? 900;
  }

  async create(
    context: MutationContext,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = parseCreate(value, this.#maximumSizeBytes);
    return this.#idempotency.execute(
      accountScope(context.ownerId),
      context.idempotencyKey,
      'create_report_import',
      input,
      async () => {
        const importId = this.#ids.uploadId();
        const partSizeBytes = input.part_size_bytes ?? this.#defaultPartSizeBytes;
        if (partSizeBytes < MIN_MULTIPART_PART_BYTES) {
          throw unprocessable(
            `part_size_bytes must be at least ${MIN_MULTIPART_PART_BYTES}.`,
          );
        }
        const partCount = Math.ceil(input.size_bytes / partSizeBytes);
        if (partCount > 10_000) {
          throw unprocessable('Report import exceeds the multipart part limit.');
        }
        const key = [
          'v1',
          'owners',
          encodeKeyPart(context.ownerId),
          'report-imports',
          encodeKeyPart(importId),
          'source.tfreport',
        ].join('/');
        const initiation: MultipartInitiateRequest = {
          bucket: this.#bucket,
          key,
          contentType: input.content_type,
          sizeBytes: input.size_bytes,
          checksumSha256: input.checksum_sha256,
          kmsKeyId: this.#kmsKeyId,
          metadata: {
            owner_id: context.ownerId,
            import_id: importId,
            checksum_sha256: input.checksum_sha256,
          },
        };
        const initiated = await this.#storage.initiate(initiation);
        const now = this.#clock.now().toISOString();
        const session: ReportImportSession = {
          schemaVersion: 1,
          importId,
          ownerId: context.ownerId,
          filename: input.filename,
          contentType: input.content_type,
          sizeBytes: input.size_bytes,
          checksumSha256: input.checksum_sha256,
          bucket: this.#bucket,
          key,
          kmsKeyId: this.#kmsKeyId,
          storageUploadId: required(
            initiated.storageUploadId,
            'storage multipart upload ID',
          ),
          partSizeBytes,
          partCount,
          signedParts: {},
          completedParts: [],
          status: 'pending',
          result: null,
          failureCode: null,
          createdAt: now,
          updatedAt: now,
        };
        try {
          await this.#store.put(session);
        } catch (error) {
          await this.#storage
            .abort({
              ...initiation,
              storageUploadId: session.storageUploadId,
            })
            .catch(() => {});
          throw error;
        }
        return {
          status: 201,
          value: responseSession(session, {
            part_size_bytes: partSizeBytes,
            part_count: partCount,
          }),
        };
      },
    );
  }

  async get(ownerId: UserId, importId: UploadId): Promise<ReportImportSession> {
    const session = await this.#store.get(ownerId, importId);
    if (session === null) {
      throw notFound(`Report import ${importId} was not found.`);
    }
    return session;
  }

  async info(ownerId: UserId): Promise<Record<string, unknown>> {
    const sessions = await this.#store.list(ownerId);
    return {
      hosted: true,
      imports_dir: '',
      processed: sessions
        .filter((session) => session.status === 'completed')
        .map((session) => ({
          name: session.filename,
          size: session.sizeBytes,
        })),
      failed: sessions
        .filter((session) => session.status === 'failed')
        .map((session) => ({
          name: session.filename,
          size: session.sizeBytes,
        })),
    };
  }

  async presignPart(
    context: MutationContext,
    importId: UploadId,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = parsePart(value);
    return this.#idempotency.execute(
      accountScope(context.ownerId),
      context.idempotencyKey,
      'presign_report_import_part',
      { importId, input },
      async () => {
        const session = await this.get(context.ownerId, importId);
        if (
          !['pending', 'uploading'].includes(session.status) ||
          session.completion !== undefined
        ) {
          throw conflict(`Report import ${importId} is ${session.status}.`);
        }
        if (input.part_number > session.partCount) {
          throw unprocessable(
            `part_number must be between 1 and ${session.partCount}.`,
          );
        }
        const expectedSize = expectedPartSize(session, input.part_number);
        if (input.size_bytes !== expectedSize) {
          throw unprocessable(
            `Part ${input.part_number} must contain exactly ${expectedSize} bytes.`,
          );
        }
        const signature = await this.#storage.presignPart({
          ...initiation(session),
          storageUploadId: session.storageUploadId,
          partNumber: input.part_number,
          partSizeBytes: input.size_bytes,
          partChecksumSha256: input.checksum_sha256,
          expiresInSeconds: this.#presignLifetimeSeconds,
        });
        assertSignature(signature, input.checksum_sha256);
        const now = this.#clock.now().toISOString();
        const recorded = await this.#store.recordSignedPart(
          context.ownerId,
          importId,
          {
            partNumber: input.part_number,
            sizeBytes: input.size_bytes,
            checksumSha256: input.checksum_sha256,
          },
          now,
        );
        if (recorded === null) {
          throw conflict(
            `Report import ${importId} started completion while the part was being signed.`,
            'completion_in_progress',
          );
        }
        return {
          status: 200,
          value: {
            import_id: importId,
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
    importId: UploadId,
    value: unknown,
  ): Promise<MutationResponseRecord> {
    const input = parseComplete(value);
    return this.#idempotency.execute(
      accountScope(context.ownerId),
      context.idempotencyKey,
      'complete_report_import',
      { importId, input },
      async () => {
        let session = await this.get(context.ownerId, importId);
        if (session.status === 'processing' || session.status === 'completed') {
          return { status: 200, value: responseSession(session) };
        }
        if (!['pending', 'uploading'].includes(session.status)) {
          throw conflict(`Report import ${importId} is ${session.status}.`);
        }
        assertClientParts(session, input.parts);
        if (session.completion !== undefined) {
          assertCompletionParts(session.completion.parts, input.parts);
          session = await this.#claimCompletion(
            session,
            context.idempotencyKey,
          );
          await this.#ensureStorageCompleted(session);
          await this.#markProcessing(session);
          await this.#dispatcher.dispatch(context.ownerId, importId);
          return { status: 202, value: responseSession(session) };
        }
        const observed = await this.#storage.inspect({
          ...initiation(session),
          storageUploadId: session.storageUploadId,
        });
        assertInspection(session, observed, input.parts);
        const startedAt = this.#clock.now().toISOString();
        const completion: MultipartCompletionRecord = {
          state: 'completing',
          parts: observed.parts,
          startedAt,
          completedAt: null,
          storageVersionId: null,
          claimId: context.idempotencyKey,
          claimExpiresAt: new Date(
            Date.parse(startedAt) + COMPLETION_LEASE_MILLISECONDS,
          ).toISOString(),
        };
        const claimed = await this.#store.claimCompletion(
          context.ownerId,
          importId,
          completion,
          startedAt,
        );
        if (claimed === null) {
          throw conflict(
            'Report import completion is already in progress.',
            'completion_in_progress',
          );
        }
        session = claimed;
        const completed = await this.#storage.complete({
          ...initiation(session),
          storageUploadId: session.storageUploadId,
          parts: observed.parts,
        });
        const completedAt = this.#clock.now().toISOString();
        const activeCompletion = session.completion;
        if (activeCompletion === undefined) {
          throw new Error(
            `Report import ${importId} lost its completion journal.`,
          );
        }
        session.completion = {
          ...activeCompletion,
          state: 'completed',
          completedAt,
          storageVersionId: completed.versionId,
        };
        await this.#markProcessing(session, completedAt);
        await this.#dispatcher.dispatch(context.ownerId, importId);
        return { status: 202, value: responseSession(session) };
      },
    );
  }

  async abort(
    context: MutationContext,
    importId: UploadId,
  ): Promise<MutationResponseRecord> {
    return this.#idempotency.execute(
      accountScope(context.ownerId),
      context.idempotencyKey,
      'abort_report_import',
      { importId },
      async () => {
        const session = await this.get(context.ownerId, importId);
        if (
          session.status === 'processing' ||
          (session.completion !== undefined &&
            ['pending', 'uploading'].includes(session.status))
        ) {
          throw conflict(
            'A processing or completing report import cannot be cancelled.',
          );
        }
        if (!['completed', 'failed', 'cancelled'].includes(session.status)) {
          await this.#storage.abort({
            ...initiation(session),
            storageUploadId: session.storageUploadId,
          });
        }
        if (session.status !== 'completed' && session.status !== 'failed') {
          session.status = 'cancelled';
          session.updatedAt = this.#clock.now().toISOString();
          await this.#store.put(session);
        }
        return { status: 200, value: responseSession(session) };
      },
    );
  }

  async #markProcessing(
    session: ReportImportSession,
    at = this.#clock.now().toISOString(),
  ): Promise<void> {
    session.completedParts = session.completion?.parts ?? session.completedParts;
    session.status = 'processing';
    session.updatedAt = at;
    await this.#store.put(session);
  }

  async #ensureStorageCompleted(
    session: ReportImportSession,
  ): Promise<void> {
    const completion = session.completion;
    if (completion === undefined || completion.state === 'completed') {
      return;
    }
    const request = initiation(session);
    const observed = await this.#storage.inspectCompleted({
      ...request,
      parts: completion.parts,
    });
    const completed =
      observed ??
      (await this.#storage.complete({
        ...request,
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
    session: ReportImportSession,
    claimId: string,
  ): Promise<ReportImportSession> {
    const existing = session.completion;
    if (existing === undefined) {
      throw new Error(
        `Report import ${session.importId} has no completion journal.`,
      );
    }
    const claimedAt = this.#clock.now().toISOString();
    const claimed = await this.#store.claimCompletion(
      session.ownerId,
      session.importId,
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
        'Report import completion is already in progress.',
        'completion_in_progress',
      );
    }
    return claimed;
  }
}

export function reportImportId(value: unknown): UploadId {
  return asUploadId(value);
}

function parseCreate(value: unknown, maximumSizeBytes: number): CreateInput {
  const input = objectInput(value);
  const filename = stringField(input, 'filename').trim();
  const contentType = stringField(input, 'content_type').trim().toLowerCase();
  const checksum = stringField(input, 'checksum_sha256');
  const sizeBytes = integerField(input, 'size_bytes');
  if (
    !filename.endsWith('.tfreport') ||
    filename.length > 1_024 ||
    filename.includes('/') ||
    filename.includes('\\') ||
    /[\u0000-\u001f]/.test(filename)
  ) {
    throw unprocessable('filename must be a safe .tfreport basename.');
  }
  if (!['application/zip', 'application/octet-stream'].includes(contentType)) {
    throw unprocessable('content_type must identify a ZIP report.');
  }
  if (!CHECKSUM_PATTERN.test(checksum)) {
    throw unprocessable('checksum_sha256 must be lowercase hexadecimal SHA-256.');
  }
  if (sizeBytes > maximumSizeBytes) {
    throw unprocessable(`Report exceeds the ${maximumSizeBytes} byte limit.`);
  }
  const partSize =
    input.part_size_bytes === undefined
      ? undefined
      : integerField(input, 'part_size_bytes');
  return {
    filename,
    content_type: contentType,
    size_bytes: sizeBytes,
    checksum_sha256: checksum,
    ...(partSize === undefined ? {} : { part_size_bytes: partSize }),
  };
}

function parsePart(value: unknown): PartInput {
  const input = objectInput(value);
  const checksum = stringField(input, 'checksum_sha256');
  if (!CHECKSUM_PATTERN.test(checksum)) {
    throw unprocessable('checksum_sha256 must be lowercase hexadecimal SHA-256.');
  }
  return {
    part_number: integerField(input, 'part_number'),
    size_bytes: integerField(input, 'size_bytes'),
    checksum_sha256: checksum,
  };
}

function parseComplete(value: unknown): CompleteInput {
  const input = objectInput(value);
  if (!Array.isArray(input.parts) || input.parts.length === 0) {
    throw unprocessable('parts must be a non-empty array.');
  }
  return {
    parts: input.parts.map((value) => {
      const part = objectInput(value);
      const checksum = stringField(part, 'checksum_sha256');
      const etag = stringField(part, 'etag');
      if (!CHECKSUM_PATTERN.test(checksum) || etag.length > 1_024) {
        throw unprocessable('Report import part metadata is invalid.');
      }
      return {
        part_number: integerField(part, 'part_number'),
        size_bytes: integerField(part, 'size_bytes'),
        etag,
        checksum_sha256: checksum,
      };
    }),
  };
}

function objectInput(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw unprocessable('Report import request must be a JSON object.');
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
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw unprocessable(`${field} must be a positive integer.`);
  }
  return Number(value);
}

function required(value: string, label: string): string {
  if (value.trim().length === 0) throw new Error(`${label} is required`);
  return value;
}

function accountScope(ownerId: UserId) {
  return { owner_id: ownerId, application_id: ACCOUNT_SCOPE_APPLICATION_ID };
}

function initiation(session: ReportImportSession): MultipartInitiateRequest {
  return {
    bucket: session.bucket,
    key: session.key,
    contentType: session.contentType,
    sizeBytes: session.sizeBytes,
    checksumSha256: session.checksumSha256,
    kmsKeyId: session.kmsKeyId,
    metadata: {
      owner_id: session.ownerId,
      import_id: session.importId,
      checksum_sha256: session.checksumSha256,
    },
  };
}

function expectedPartSize(
  session: ReportImportSession,
  partNumber: number,
): number {
  return partNumber < session.partCount
    ? session.partSizeBytes
    : session.sizeBytes - session.partSizeBytes * (session.partCount - 1);
}

function assertSignature(
  signature: MultipartPartSignature,
  checksum: string,
): void {
  const actual = Object.entries(signature.headers).find(
    ([name]) => name.toLowerCase() === 'x-amz-checksum-sha256',
  )?.[1];
  if (
    !signature.url.startsWith('https://') ||
    actual !== Buffer.from(checksum, 'hex').toString('base64')
  ) {
    throw new Error('Report import signature does not enforce its checksum.');
  }
}

function assertClientParts(
  session: ReportImportSession,
  parts: CompleteInput['parts'],
): void {
  if (parts.length !== session.partCount) {
    throw unprocessable(`Report import requires ${session.partCount} parts.`);
  }
  const seen = new Set<number>();
  for (const part of parts) {
    const signed = session.signedParts[String(part.part_number)];
    if (
      seen.has(part.part_number) ||
      signed === undefined ||
      signed.sizeBytes !== part.size_bytes ||
      signed.checksumSha256 !== part.checksum_sha256 ||
      part.size_bytes !== expectedPartSize(session, part.part_number)
    ) {
      throw unprocessable(`Part ${part.part_number} violates its signed constraints.`);
    }
    seen.add(part.part_number);
  }
}

function assertInspection(
  session: ReportImportSession,
  inspection: MultipartInspection,
  parts: CompleteInput['parts'],
): void {
  const byNumber = new Map(parts.map((part) => [part.part_number, part]));
  let total = 0;
  if (
    inspection.storageUploadId !== session.storageUploadId ||
    inspection.parts.length !== session.partCount
  ) {
    throw conflict('Stored report import parts are incomplete.');
  }
  for (const observed of inspection.parts) {
    const expected = byNumber.get(observed.partNumber);
    if (
      expected === undefined ||
      observed.sizeBytes !== expected.size_bytes ||
      observed.etag !== expected.etag ||
      observed.checksumSha256 !== expected.checksum_sha256
    ) {
      throw conflict(`Stored report part ${observed.partNumber} is inconsistent.`);
    }
    total += observed.sizeBytes;
  }
  if (total !== session.sizeBytes) {
    throw conflict('Stored report size does not match the declared size.');
  }
}

function assertCompletionParts(
  completed: CompletedPart[],
  requested: CompleteInput['parts'],
): void {
  const requestedByNumber = new Map(
    requested.map((part) => [part.part_number, part]),
  );
  if (
    completed.length !== requested.length ||
    completed.some((part) => {
      const expected = requestedByNumber.get(part.partNumber);
      return (
        expected === undefined ||
        expected.size_bytes !== part.sizeBytes ||
        expected.etag !== part.etag ||
        expected.checksum_sha256 !== part.checksumSha256
      );
    })
  ) {
    throw conflict(
      'Report import completion input does not match the durable completion.',
    );
  }
}

function responseSession(
  session: ReportImportSession,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    import_id: session.importId,
    status: session.status,
    filename: session.filename,
    size_bytes: session.sizeBytes,
    result: session.result,
    failure_code: session.failureCode,
    created_at: session.createdAt,
    updated_at: session.updatedAt,
    ...extra,
  };
}
