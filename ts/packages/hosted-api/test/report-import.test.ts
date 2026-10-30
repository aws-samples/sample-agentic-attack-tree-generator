import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import {
  buildThreatforestReportArchive,
} from '../../hosted-runtime/src/report-archive.js';
import { parseThreatforestReportArchive } from '../src/report-format.js';
import { HostedApiError } from '../src/errors.js';
import {
  DurableReportImportCommitter,
  ReportImportLeaseUnavailableError,
  ReportImportWorker,
  type ReportImportCommitter,
  type ReportImportObjectWriter,
  type ReportImportStateClient,
} from '../src/report-import-worker.js';
import { S3ReportImportSourceReader } from '../src/aws/report-import-source.js';
import {
  InMemoryReportImportStore,
} from '../src/report-import-in-memory.js';
import type {
  ReportImportSession,
  ReportImportWorkerLease,
} from '../src/report-import-service.js';
import { DynamoReportImportStore } from '../src/aws/report-imports.js';
import {
  OWNER_A,
  apiEvent,
  json,
  makeFixture,
} from './support.js';
import { asUploadId } from '../src/runtime.js';

const BUSINESS_CONTEXT = {
  description: 'Imported payments service',
  regulatory_frameworks: ['PCI DSS'],
  data_sensitivity: 'confidential',
  cia_priority: ['confidentiality', 'integrity', 'availability'],
};

function archive(
  versionId = 'run_123',
  businessContext: Readonly<Record<string, unknown>> = BUSINESS_CONTEXT,
): Buffer {
  return buildThreatforestReportArchive({
    applicationId: 'source-app',
    applicationName: 'Imported Payments',
    applicationSlug: 'imported-payments',
    applicationDescription: 'Imported payments service',
    applicationCreatedAt: '2026-08-19T10:00:00.000Z',
    businessContext,
    includeScannerContext: true,
    exportedAt: '2026-08-19T12:00:00.000Z',
    versions: [
      {
        id: versionId,
        entries: [
          {
            path: 'output/threatforest_data.json',
            body: Buffer.from(
              JSON.stringify({
                status: 'complete',
                threat_count: 3,
                high_severity_count: 1,
                categories: ['Spoofing'],
              }),
            ),
          },
          {
            path: 'output/threat_model_report.md',
            body: Buffer.from('# Threat model\n'),
          },
          {
            path: 'run_metadata.json',
            body: Buffer.from(
              JSON.stringify({ started_at: '2026-08-19T11:00:00.000Z' }),
            ),
          },
        ],
      },
    ],
  });
}

test('parses importable hosted report archives with opaque run IDs', () => {
  const parsed = parseThreatforestReportArchive(archive());
  assert.equal(parsed.manifest.source_app_id, 'source-app');
  assert.equal(parsed.versions[0]?.id, 'run_123');
  assert.equal(parsed.versions[0]?.summary.threat_count, 3);
  assert.equal(
    parsed.versions[0]?.createdAt,
    '2026-08-19T11:00:00.000Z',
  );
  assert.equal(
    parsed.application.businessContext?.data_sensitivity,
    'confidential',
  );
});

test('invalid report metadata is a terminal validation failure', async () => {
  const bytes = archive('run_invalid', {
    ...BUSINESS_CONTEXT,
    data_sensitivity: 'high',
  });
  assert.throws(
    () => parseThreatforestReportArchive(bytes),
    (error) => error instanceof HostedApiError && error.status === 422,
  );

  const session = processingSession(bytes);
  const store = new LeaseMemoryReportImportStore();
  await store.put(session);
  const worker = new ReportImportWorker(
    store,
    {
      async get() {
        return sourceObject(session, bytes);
      },
    },
    {
      async prepareDestination() {
        throw new Error('invalid reports must not reserve a destination');
      },
      async commit() {
        throw new Error('invalid reports must not reach the committer');
      },
    },
  );

  const failed = await worker.process(OWNER_A, session.importId);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.failureCode, 'invalid_input');
  assert.match(failed.result?.error ?? '', /metadata is invalid/i);
});

test('S3 report source retrieval validates the multipart composite and computes the canonical digest', async () => {
  const bytes = archive('run_s3_source');
  const session = processingSession(bytes);
  const partDigest = createHash('sha256').update(bytes).digest('hex');
  const composite = createHash('sha256')
    .update(Buffer.from(partDigest, 'hex'))
    .digest('base64');
  session.completedParts = [
    {
      partNumber: 1,
      sizeBytes: bytes.byteLength,
      etag: '"etag-1"',
      checksumSha256: partDigest,
    },
  ];
  const commands: Array<{ input: Record<string, unknown> }> = [];
  const reader = new S3ReportImportSourceReader({
    async send(command: { input: Record<string, unknown> }) {
      commands.push(command);
      return {
        Body: {
          async transformToByteArray() {
            return Uint8Array.from(bytes);
          },
        },
        ContentLength: bytes.byteLength,
        ChecksumSHA256: `${composite}-1`,
        ChecksumType: 'COMPOSITE',
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: session.kmsKeyId,
        BucketKeyEnabled: true,
        Metadata: {
          owner_id: session.ownerId,
          import_id: session.importId,
        },
      };
    },
  } as never);

  const source = await reader.get(session);
  assert.equal(commands[0]!.input['ChecksumMode'], 'ENABLED');
  assert.equal(source.checksumSha256, session.checksumSha256);
  assert.notEqual(
    Buffer.from(source.checksumSha256, 'hex').toString('base64'),
    `${composite}-1`,
  );

  const mismatched = new S3ReportImportSourceReader({
    async send() {
      return {
        Body: {
          async transformToByteArray() {
            return Uint8Array.from(bytes);
          },
        },
        ChecksumSHA256: `${composite}-2`,
        ChecksumType: 'COMPOSITE',
      };
    },
  } as never);
  await assert.rejects(
    mismatched.get(session),
    (error) =>
      error instanceof HostedApiError &&
      error.code === 'report_source_integrity_failed',
  );
});

test('hosted report imports use encrypted multipart control requests and owner scope', async () => {
  const fixture = makeFixture();
  const body = archive();
  const digest = createHash('sha256').update(body).digest('hex');
  const created = await fixture.handler(
    apiEvent('POST', '/api/imports/tfreport', {
      idempotencyKey: 'create-import',
      body: {
        filename: 'payments.tfreport',
        content_type: 'application/zip',
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  assert.equal(created.statusCode, 201);
  const importId = String(json(created).import_id);
  assert.equal(fixture.storage.initiated[0]?.kmsKeyId.includes(':kms:'), true);

  const part = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/parts`, {
      idempotencyKey: 'sign-import-part',
      body: {
        part_number: 1,
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  assert.equal(part.statusCode, 200);
  fixture.storage.recordPart('storage-1', {
    partNumber: 1,
    sizeBytes: body.byteLength,
    etag: '"etag-1"',
    checksumSha256: digest,
  });
  const completed = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/complete`, {
      idempotencyKey: 'complete-import',
      body: {
        parts: [
          {
            part_number: 1,
            size_bytes: body.byteLength,
            etag: '"etag-1"',
            checksum_sha256: digest,
          },
        ],
      },
    }),
  );
  assert.equal(completed.statusCode, 202);
  assert.equal(json(completed).status, 'processing');
  assert.equal(fixture.reportImportDispatcher.dispatches.length, 1);

  const crossUser = await fixture.handler(
    apiEvent('GET', `/api/imports/tfreport/${importId}`, {
      owner: 'user_b' as typeof OWNER_A,
    }),
  );
  assert.equal(crossUser.statusCode, 404);
});

test('a stale report presign cannot overwrite a completion journal', async () => {
  const fixture = makeFixture();
  const body = archive('run_presign_race');
  const digest = createHash('sha256').update(body).digest('hex');
  const created = await fixture.handler(
    apiEvent('POST', '/api/imports/tfreport', {
      idempotencyKey: 'create-presign-race-import',
      body: {
        filename: 'presign-race.tfreport',
        content_type: 'application/zip',
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  const importId = asUploadId(String(json(created).import_id));
  const originalPresign = fixture.storage.presignPart.bind(fixture.storage);
  let releasePresign!: () => void;
  const presignReleased = new Promise<void>((resolve) => {
    releasePresign = resolve;
  });
  let presignStarted!: () => void;
  const presignEntered = new Promise<void>((resolve) => {
    presignStarted = resolve;
  });
  fixture.storage.presignPart = async (request) => {
    presignStarted();
    await presignReleased;
    return originalPresign(request);
  };

  const signing = fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/parts`, {
      idempotencyKey: 'sign-presign-race-import',
      body: {
        part_number: 1,
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  await presignEntered;
  const claimed = await fixture.reportImports.claimCompletion(
    OWNER_A,
    importId,
    {
      state: 'completing',
      parts: [],
      startedAt: '2026-08-19T12:00:00.000Z',
      completedAt: null,
      storageVersionId: null,
      claimId: 'completion-winner',
      claimExpiresAt: '2026-08-19T12:01:00.000Z',
    },
    '2026-08-19T12:00:00.000Z',
  );
  assert.equal(claimed?.completion?.claimId, 'completion-winner');
  releasePresign();

  const response = await signing;
  assert.equal(response.statusCode, 409);
  assert.equal(json(response).code, 'completion_in_progress');
  const durable = await fixture.reportImports.get(OWNER_A, importId);
  assert.equal(durable?.completion?.claimId, 'completion-winner');
  assert.equal(durable?.signedParts['1'], undefined);
});

test('report completion recovers after S3 succeeds before session persistence', async () => {
  const fixture = makeFixture();
  const body = archive();
  const digest = createHash('sha256').update(body).digest('hex');
  const created = await fixture.handler(
    apiEvent('POST', '/api/imports/tfreport', {
      idempotencyKey: 'create-recoverable-import',
      body: {
        filename: 'recoverable.tfreport',
        content_type: 'application/zip',
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  const importId = String(json(created).import_id);
  await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/parts`, {
      idempotencyKey: 'sign-recoverable-import',
      body: {
        part_number: 1,
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  fixture.storage.recordPart('storage-1', {
    partNumber: 1,
    sizeBytes: body.byteLength,
    etag: '"recoverable"',
    checksumSha256: digest,
  });
  const originalPut = fixture.reportImports.put.bind(fixture.reportImports);
  let failAfterStorageCompletion = true;
  fixture.reportImports.put = async (session) => {
    if (failAfterStorageCompletion && session.status === 'processing') {
      failAfterStorageCompletion = false;
      throw new Error('simulated post-S3 DynamoDB failure');
    }
    await originalPut(session);
  };
  const completionBody = {
    parts: [
      {
        part_number: 1,
        size_bytes: body.byteLength,
        etag: '"recoverable"',
        checksum_sha256: digest,
      },
    ],
  };

  const interrupted = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/complete`, {
      idempotencyKey: 'complete-recoverable-import-1',
      body: completionBody,
    }),
  );
  assert.equal(interrupted.statusCode, 500);
  assert.equal(fixture.storage.completeCalls, 1);
  const journal = await fixture.reportImports.get(
    OWNER_A,
    asUploadId(importId),
  );
  assert.equal(journal?.status, 'uploading');
  assert.equal(journal?.completion?.state, 'completing');

  const recovered = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/complete`, {
      idempotencyKey: 'complete-recoverable-import-1',
      body: completionBody,
    }),
  );
  assert.equal(recovered.statusCode, 202);
  assert.equal(json(recovered).status, 'processing');
  assert.equal(fixture.storage.completeCalls, 1);
  assert.equal(fixture.reportImportDispatcher.dispatches.length, 1);
});

test('report completion retries storage when the first completion never committed', async () => {
  const fixture = makeFixture();
  const body = archive();
  const digest = createHash('sha256').update(body).digest('hex');
  const created = await fixture.handler(
    apiEvent('POST', '/api/imports/tfreport', {
      idempotencyKey: 'create-storage-retry-import',
      body: {
        filename: 'storage-retry.tfreport',
        content_type: 'application/zip',
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  const importId = String(json(created).import_id);
  await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/parts`, {
      idempotencyKey: 'sign-storage-retry-import',
      body: {
        part_number: 1,
        size_bytes: body.byteLength,
        checksum_sha256: digest,
      },
    }),
  );
  fixture.storage.recordPart('storage-1', {
    partNumber: 1,
    sizeBytes: body.byteLength,
    etag: '"storage-retry"',
    checksumSha256: digest,
  });
  fixture.storage.failNextCompletion = true;
  const completion = {
    parts: [
      {
        part_number: 1,
        size_bytes: body.byteLength,
        etag: '"storage-retry"',
        checksum_sha256: digest,
      },
    ],
  };

  const interrupted = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/complete`, {
      idempotencyKey: 'complete-storage-retry-import',
      body: completion,
    }),
  );
  assert.equal(interrupted.statusCode, 500);
  assert.equal(fixture.storage.completionAttempts, 1);
  assert.equal(fixture.storage.completeCalls, 0);

  const recovered = await fixture.handler(
    apiEvent('POST', `/api/imports/tfreport/${importId}/complete`, {
      idempotencyKey: 'complete-storage-retry-import',
      body: completion,
    }),
  );
  assert.equal(recovered.statusCode, 202);
  assert.equal(fixture.storage.completionAttempts, 2);
  assert.equal(fixture.storage.completeCalls, 1);
  assert.equal(fixture.reportImportDispatcher.dispatches.length, 1);
});

test('worker publishes imported versions and is idempotent', async () => {
  const bytes = archive();
  const session = processingSession(bytes);
  const store = new LeaseMemoryReportImportStore();
  await store.put(session);
  const objects = new MemoryObjects();
  const state = new MemoryState();
  const worker = new ReportImportWorker(
    store,
    {
      async get() {
        return sourceObject(session, bytes);
      },
    },
    new DurableReportImportCommitter(
      objects,
      state,
      () => new Date('2026-08-19T12:30:00.000Z'),
    ),
  );

  const completed = await worker.process(OWNER_A, session.importId);
  assert.equal(completed.status, 'completed');
  assert.equal(completed.result?.status, 'imported');
  assert.deepEqual(completed.result?.versions_added, ['run_123']);
  assert.equal(state.applications.length, 1);
  assert.equal(state.versions.length, 1);
  assert.ok(objects.values.size >= 6);

  const replay = await worker.process(OWNER_A, session.importId);
  assert.equal(replay.status, 'completed');
  assert.equal(state.applications.length, 1);
});

test('duplicate report deliveries are fenced by one atomic worker lease', async () => {
  const bytes = archive('run_race');
  const session = processingSession(bytes);
  const store = new LeaseMemoryReportImportStore();
  await store.put(session);
  let releaseSource!: () => void;
  const sourceReleased = new Promise<void>((resolve) => {
    releaseSource = resolve;
  });
  let sourceStarted!: () => void;
  const sourceEntered = new Promise<void>((resolve) => {
    sourceStarted = resolve;
  });
  let commits = 0;
  const committer = successfulCommitter(() => {
    commits += 1;
  });
  const source = {
    async get() {
      sourceStarted();
      await sourceReleased;
      return sourceObject(session, bytes);
    },
  };
  const first = new ReportImportWorker(store, source, committer).process(
    OWNER_A,
    session.importId,
  );
  await sourceEntered;

  await assert.rejects(
    new ReportImportWorker(store, source, committer).process(
      OWNER_A,
      session.importId,
    ),
    ReportImportLeaseUnavailableError,
  );
  releaseSource();
  const completed = await first;
  assert.equal(completed.status, 'completed');
  assert.equal(commits, 1);
});

test('report destination reservation remains stable across worker retries', async () => {
  const bytes = archive('run_retry');
  const session = processingSession(bytes);
  const store = new LeaseMemoryReportImportStore();
  await store.put(session);
  let prepareCalls = 0;
  const committedDestinations: string[] = [];
  const committer: ReportImportCommitter = {
    async prepareDestination() {
      prepareCalls += 1;
      return {
        mode: 'new',
        applicationId: `app_destination_${prepareCalls}` as never,
        name: 'Stable destination',
        importedAt: '2026-08-19T12:00:00.000Z',
      };
    },
    async commit(claimed) {
      committedDestinations.push(String(claimed.destination?.applicationId));
      if (committedDestinations.length === 1) {
        throw new Error('transient commit failure');
      }
      return successfulResult(
        String(claimed.destination?.applicationId),
        'run_retry',
      );
    },
  };
  const worker = new ReportImportWorker(
    store,
    {
      async get() {
        return sourceObject(session, bytes);
      },
    },
    committer,
  );

  await assert.rejects(
    worker.process(OWNER_A, session.importId),
    /transient commit failure/,
  );
  const reserved = await store.get(OWNER_A, session.importId);
  assert.equal(reserved?.destination?.applicationId, 'app_destination_1');
  const completed = await worker.process(OWNER_A, session.importId);

  assert.equal(completed.status, 'completed');
  assert.equal(prepareCalls, 1);
  assert.deepEqual(committedDestinations, [
    'app_destination_1',
    'app_destination_1',
  ]);
});

test('Dynamo report store uses conditional lease acquisition and fenced saves', async () => {
  const bytes = archive('run_dynamo_lease');
  const session = processingSession(bytes);
  const commands: Array<{ input: Record<string, unknown> }> = [];
  const lease: ReportImportWorkerLease = {
    leaseId: 'lease-1',
    acquiredAt: '2026-08-19T12:00:00.000Z',
    expiresAt: '2026-08-19T12:16:00.000Z',
  };
  const client = {
    async send(command: { input: Record<string, unknown> }) {
      commands.push(command);
      return commands.length === 1
        ? {
            Attributes: {
              session: { ...session, workerLease: lease },
            },
          }
        : {};
    },
  };
  const store = new DynamoReportImportStore('table', client as never);

  const claimed = await store.acquireProcessingLease(
    OWNER_A,
    session.importId,
    lease,
  );
  assert.equal(claimed?.workerLease?.leaseId, lease.leaseId);
  assert.match(
    String(commands[0]?.input.ConditionExpression),
    /attribute_not_exists.*expiresAt/,
  );
  assert.equal(await store.saveLeased(claimed!, lease.leaseId), true);
  assert.match(
    String(commands[1]?.input.ConditionExpression),
    /workerLease.*leaseId/,
  );
});

test('Dynamo report part signing is a merge update fenced against completion', async () => {
  const bytes = archive('run_dynamo_presign');
  const session = processingSession(bytes);
  session.status = 'uploading';
  const commands: Array<{ input: Record<string, unknown> }> = [];
  const client = {
    async send(command: { input: Record<string, unknown> }) {
      commands.push(command);
      return {
        Attributes: {
          session: {
            ...session,
            signedParts: {
              '1': {
                sizeBytes: bytes.byteLength,
                checksumSha256: session.checksumSha256,
                signedAt: '2026-08-19T12:01:00.000Z',
              },
            },
          },
        },
      };
    },
  };
  const store = new DynamoReportImportStore('table', client as never);

  const updated = await store.recordSignedPart(
    OWNER_A,
    session.importId,
    {
      partNumber: 1,
      sizeBytes: bytes.byteLength,
      checksumSha256: session.checksumSha256,
    },
    '2026-08-19T12:01:00.000Z',
  );

  assert.equal(updated?.signedParts['1']?.sizeBytes, bytes.byteLength);
  assert.match(
    String(commands[0]!.input['UpdateExpression']),
    /signedParts.*partNumber/,
  );
  assert.doesNotMatch(
    String(commands[0]!.input['UpdateExpression']),
    /#session\s*=\s*:session/,
  );
  assert.match(
    String(commands[0]!.input['ConditionExpression']),
    /attribute_not_exists.*completion/,
  );
});

function processingSession(bytes: Uint8Array): ReportImportSession {
  return {
    schemaVersion: 1,
    importId: asUploadId('upload_import'),
    ownerId: OWNER_A,
    filename: 'payments.tfreport',
    contentType: 'application/zip',
    sizeBytes: bytes.byteLength,
    checksumSha256: createHash('sha256').update(bytes).digest('hex'),
    bucket: 'bucket',
    key: 'source',
    kmsKeyId: 'kms-key',
    storageUploadId: 'storage',
    partSizeBytes: bytes.byteLength,
    partCount: 1,
    signedParts: {},
    completedParts: [],
    status: 'processing',
    result: null,
    failureCode: null,
    createdAt: '2026-08-19T12:00:00.000Z',
    updatedAt: '2026-08-19T12:00:00.000Z',
  };
}

function sourceObject(
  session: ReportImportSession,
  bytes: Uint8Array,
) {
  return {
    body: bytes,
    sizeBytes: bytes.byteLength,
    checksumSha256: createHash('sha256').update(bytes).digest('hex'),
    serverSideEncryption: 'aws:kms',
    kmsKeyId: 'kms-key',
    bucketKeyEnabled: true,
    metadata: {
      owner_id: OWNER_A,
      import_id: session.importId,
    },
  };
}

class MemoryObjects implements ReportImportObjectWriter {
  readonly values = new Map<string, Uint8Array>();

  async putImmutable(input: {
    key: string;
    body: Uint8Array;
    checksumSha256: string;
  }): Promise<void> {
    const existing = this.values.get(input.key);
    if (
      existing !== undefined &&
      createHash('sha256').update(existing).digest('hex') !==
        input.checksumSha256
    ) {
      throw new Error('immutable object conflict');
    }
    this.values.set(input.key, Uint8Array.from(input.body));
  }

  async get(key: string): Promise<Uint8Array> {
    const value = this.values.get(key);
    if (value === undefined) throw new Error(`missing ${key}`);
    return Uint8Array.from(value);
  }
}

class MemoryState implements ReportImportStateClient {
  readonly applications: Array<Record<string, unknown>> = [];
  readonly metadata = new Map<string, Record<string, unknown>>();
  readonly versions: Array<Record<string, unknown>> = [];
  applicationReport: Record<string, unknown> | null = null;

  async listApplications(): Promise<Array<Record<string, unknown>>> {
    return structuredClone(this.applications);
  }

  async getMetadata(
    _ownerId: typeof OWNER_A,
    applicationId: string,
  ): Promise<Record<string, unknown> | null> {
    return structuredClone(this.metadata.get(applicationId) ?? null);
  }

  async putMetadata(
    _ownerId: typeof OWNER_A,
    applicationId: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    this.metadata.set(applicationId, structuredClone(metadata));
  }

  async createApplication(item: Record<string, unknown>): Promise<void> {
    this.applications.push(structuredClone(item));
  }

  async getVersion(
    _ownerId: typeof OWNER_A,
    applicationId: string,
    versionId: string,
  ): Promise<Record<string, unknown> | null> {
    return (
      structuredClone(
        this.versions.find(
          (item) =>
            item.application_id === applicationId &&
            item.run_id === versionId,
        ),
      ) ?? null
    );
  }

  async putVersion(item: Record<string, unknown>): Promise<boolean> {
    if (
      this.versions.some(
        (existing) =>
          existing.application_id === item.application_id &&
          existing.run_id === item.run_id,
      )
    ) {
      return false;
    }
    this.versions.push(structuredClone(item));
    return true;
  }

  async listVersions(
    _ownerId: typeof OWNER_A,
    applicationId: string,
  ): Promise<Array<Record<string, unknown>>> {
    return structuredClone(
      this.versions.filter(
        (version) => version.application_id === applicationId,
      ),
    );
  }

  async putApplicationReport(item: Record<string, unknown>): Promise<void> {
    this.applicationReport = structuredClone(item);
  }
}

class LeaseMemoryReportImportStore extends InMemoryReportImportStore {
  readonly #leases = new Map<string, ReportImportWorkerLease>();

  async acquireProcessingLease(
    ownerId: typeof OWNER_A,
    importId: ReportImportSession['importId'],
    lease: ReportImportWorkerLease,
  ): Promise<ReportImportSession | null> {
    const key = `${ownerId}\0${importId}`;
    const held = this.#leases.get(key);
    if (held !== undefined && held.expiresAt > lease.acquiredAt) {
      return null;
    }
    this.#leases.set(key, structuredClone(lease));
    const session = await this.get(ownerId, importId);
    if (session?.status !== 'processing') {
      if (this.#leases.get(key)?.leaseId === lease.leaseId) {
        this.#leases.delete(key);
      }
      return null;
    }
    session.workerLease = structuredClone(lease);
    session.updatedAt = lease.acquiredAt;
    await super.put(session);
    return structuredClone(session);
  }

  async saveLeased(
    session: ReportImportSession,
    leaseId: string,
  ): Promise<boolean> {
    const key = `${session.ownerId}\0${session.importId}`;
    if (this.#leases.get(key)?.leaseId !== leaseId) return false;
    await super.put(session);
    if (session.workerLease === null) {
      this.#leases.delete(key);
    }
    return true;
  }
}

function successfulCommitter(onCommit: () => void): ReportImportCommitter {
  return {
    async prepareDestination() {
      return {
        mode: 'new',
        applicationId: 'app_race_destination' as never,
        name: 'Race destination',
        importedAt: '2026-08-19T12:00:00.000Z',
      };
    },
    async commit(session, report) {
      onCommit();
      return successfulResult(
        String(session.destination?.applicationId),
        report.versions[0]!.id,
      );
    },
  };
}

function successfulResult(applicationId: string, versionId: string) {
  return {
    bundle: 'payments.tfreport',
    status: 'imported' as const,
    folder_name: applicationId,
    versions_added: [versionId],
    versions_skipped: [],
    error: null,
  };
}
