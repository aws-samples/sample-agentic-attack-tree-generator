import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import {
  InMemoryIngestionIdempotencyStore,
  InMemoryObjectAdapter,
  InMemoryUploadManifestStore,
  IngestionWorker,
  S3Workspace,
  UploadNormalizer,
  createUploadManifest,
  sha256Hex,
  type IngestionJob,
  ExtractorRegistry,
} from '../src/index.js';

test('empty, unsupported, and unextractable uploads fail durably instead of becoming ready', async () => {
  const cases = [
    { name: 'empty.txt', bytes: Buffer.alloc(0), code: 'NO_USABLE_EVIDENCE' },
    { name: 'binary.bin', bytes: Buffer.from([0, 1, 2, 3]), code: 'NO_USABLE_EVIDENCE' },
    { name: 'report.doc', bytes: Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), code: 'OFFICE_ADAPTER_UNAVAILABLE' },
    { name: 'diagram.pdf', bytes: Buffer.from('%PDF-1.7\nfake\n'), code: 'OCR_ADAPTER_UNAVAILABLE' },
    { name: 'partial.zip', bytes: zipSync({
      'README.md': Buffer.from('The payments API uses a database.'),
      'diagram.pdf': Buffer.from('%PDF-1.7\nfake\n'),
    }), code: 'OCR_ADAPTER_UNAVAILABLE' },
  ];
  for (const item of cases) {
    const workspace = new S3Workspace(new InMemoryObjectAdapter(), 'kms-upload-key');
    const normalizer = new UploadNormalizer(workspace, { clock: sequentialClock() });
    const uploaded = await normalizer.storeOriginal(
      manifestFor(item.name, 'application/octet-stream', item.bytes.byteLength), item.bytes,
    );
    const manifests = new InMemoryUploadManifestStore();
    manifests.seed(uploaded);
    const worker = new IngestionWorker(manifests, new InMemoryIngestionIdempotencyStore(), normalizer);
    const result = await worker.handle(ingestionJob(uploaded.uploadId));
    assert.equal(result.status, 'failed', item.name);
    assert.equal(result.failureCode, item.code, item.name);
    assert.deepEqual(result.normalizedObjectIds, []);
    assert.equal((await manifests.get(uploaded))?.status, 'failed');
    assert.equal((await workspace.list({ scope: 'upload', ...uploaded, area: 'diagnostic' })).length, 1);
  }
});

test('low-confidence OCR is not promoted as reliable evidence', async () => {
  const workspace = new S3Workspace(new InMemoryObjectAdapter(), 'kms-upload-key');
  const normalizer = new UploadNormalizer(workspace, {
    extractors: new ExtractorRegistry({
      ocrAdapter: { async analyze() { return { pages: [{ pageNumber: 1, lines: [
        { lineNumber: 1, text: 'Possibly a database', confidence: 0.2 },
      ] }] }; } },
    }),
  });
  const bytes = Buffer.from('%PDF-1.7\nfake\n');
  const uploaded = await normalizer.storeOriginal(manifestFor('diagram.pdf', 'application/pdf', bytes.length), bytes);
  await assert.rejects(normalizer.normalize(uploaded), (error: unknown) =>
    error instanceof Error && 'code' in error && error.code === 'LOW_OCR_CONFIDENCE',
  );
});

test('normalization preserves originals and keeps authoritative threats separate', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-upload-key');
  const normalizer = new UploadNormalizer(workspace, { clock: sequentialClock() });
  const bytes = Buffer.from(
    '# Threats\n\n## Threat 1 - Injection\n**Threat Statement**: An attacker injects data.\n\n## Threat 2 - Access\n**Threat Statement**: An attacker bypasses access.\n',
  );
  const pending = manifestFor('threats.md', 'text/markdown', bytes.byteLength);
  const uploaded = await normalizer.storeOriginal(pending, bytes);
  const result = await normalizer.normalize(uploaded);

  assert.equal(result.manifest.status, 'ready');
  assert.equal(result.authoritativeThreatObjectIds.length, 1);
  assert.equal(result.detectionResults[0]!.threatInput.authoritative, true);
  assert.equal(
    await workspace.exists({
      scope: 'upload',
      ownerId: uploaded.ownerId,
      applicationId: uploaded.applicationId,
      uploadId: uploaded.uploadId,
      area: 'original',
      objectId: uploaded.sourceObjectId!,
    }),
    true,
  );
  const normalized = await workspace.list({
    scope: 'upload',
    ownerId: uploaded.ownerId,
    applicationId: uploaded.applicationId,
    uploadId: uploaded.uploadId,
    area: 'normalized',
  });
  assert.equal(normalized.length, 3);
  assert.equal(
    normalized.every((item) => item.metadata['input-class'] === 'authoritative-threat'),
    true,
  );
  assert.equal(
    normalized.some((item) => item.metadata['input-class'] === 'generated-threat'),
    false,
  );
  assert.deepEqual(
    result.manifest.normalizedObjectIds,
    normalized.map((item) => item.locator.objectId),
  );
  const diagnostics = await workspace.list({
    scope: 'upload',
    ownerId: uploaded.ownerId,
    applicationId: uploaded.applicationId,
    uploadId: uploaded.uploadId,
    area: 'diagnostic',
  });
  assert.equal(diagnostics.length, 1);
  assert.equal(
    result.manifest.normalizedObjectIds.includes(
      diagnostics[0]!.locator.objectId,
    ),
    false,
  );
});

test('archive normalization preserves archive and safe entry originals', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-upload-key');
  const normalizer = new UploadNormalizer(workspace, { clock: sequentialClock() });
  const archive = zipSync(
    {
      'src/index.ts': Buffer.from('export const handler = () => true;\n'),
      'README.md': Buffer.from('# App\n'),
    },
    { level: 0 },
  );
  const uploaded = await normalizer.storeOriginal(
    manifestFor('project.zip', 'application/zip', archive.byteLength),
    archive,
  );
  const result = await normalizer.normalize(uploaded);
  const originals = await workspace.list({
    scope: 'upload',
    ownerId: uploaded.ownerId,
    applicationId: uploaded.applicationId,
    uploadId: uploaded.uploadId,
    area: 'original',
  });
  assert.equal(originals.length, 3);
  assert.equal(result.detectionResults[0]!.extractor, 'safe-zip-v1');
  assert.equal(result.detectionResults.length, 3);
  assert.equal(result.normalizedArtifacts.length, 6);
});

test('queue worker completes once and returns duplicate for an idempotent retry', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-upload-key');
  const normalizer = new UploadNormalizer(workspace, { clock: sequentialClock() });
  const bytes = Buffer.from('# App\n\nUses Cognito and API Gateway.\n');
  const uploaded = await normalizer.storeOriginal(
    manifestFor('README.md', 'text/markdown', bytes.byteLength),
    bytes,
  );
  const manifests = new InMemoryUploadManifestStore();
  manifests.seed(uploaded);
  const worker = new IngestionWorker(
    manifests,
    new InMemoryIngestionIdempotencyStore(),
    normalizer,
  );
  const job = ingestionJob(uploaded.uploadId);
  const first = await worker.handle(job);
  const second = await worker.handle(job);

  assert.equal(first.status, 'completed');
  assert.equal(second.status, 'duplicate');
  assert.deepEqual(second.normalizedObjectIds, first.normalizedObjectIds);
  assert.equal(
    (
      await manifests.get({
        ownerId: uploaded.ownerId,
        applicationId: uploaded.applicationId,
        uploadId: uploaded.uploadId,
      })
    )!.status,
    'ready',
  );
});

test('queue worker records archive validation failures and retry state idempotently', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-upload-key');
  const normalizer = new UploadNormalizer(workspace, { clock: sequentialClock() });
  const malicious = zipSync({ '../escape.txt': Buffer.from('escape') }, { level: 0 });
  const uploaded = await normalizer.storeOriginal(
    manifestFor('malicious.zip', 'application/zip', malicious.byteLength),
    malicious,
  );
  const manifests = new InMemoryUploadManifestStore();
  manifests.seed(uploaded);
  const idempotency = new InMemoryIngestionIdempotencyStore();
  const worker = new IngestionWorker(manifests, idempotency, normalizer);
  const job = ingestionJob(uploaded.uploadId);

  const failed = await worker.handle(job);
  const repeated = await worker.handle(job);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.failureCode, 'UNSAFE_PATH');
  assert.deepEqual(repeated, failed);
  const stored = await manifests.get({
    ownerId: uploaded.ownerId,
    applicationId: uploaded.applicationId,
    uploadId: uploaded.uploadId,
  });
  assert.equal(stored!.status, 'failed');
  assert.equal(stored!.failureCode, 'UNSAFE_PATH');

  const retry = await worker.handle({ ...job, attempt: 2 });
  assert.equal(retry.status, 'failed');
  assert.equal(
    (
      await manifests.get({
        ownerId: uploaded.ownerId,
        applicationId: uploaded.applicationId,
        uploadId: uploaded.uploadId,
      })
    )!.attempt,
    2,
  );
});

test('idempotency leases keep live work queued and allow recovery after expiry', async () => {
  let now = new Date('2026-01-01T00:00:00.000Z');
  const idempotency = new InMemoryIngestionIdempotencyStore(30, () => now);
  const input = {
    ownerId: 'user-1',
    applicationId: 'app-1',
    idempotencyKey: 'ingest-upload-1',
    requestHash: sha256Hex('request'),
    attempt: 1,
  };
  assert.equal((await idempotency.begin(input)).state, 'acquired');
  assert.equal((await idempotency.begin(input)).state, 'in_progress');
  now = new Date('2026-01-01T00:00:31.000Z');
  assert.equal((await idempotency.begin(input)).state, 'acquired');
});

function manifestFor(filename: string, contentType: string, sizeBytes: number) {
  return createUploadManifest({
    ownerId: 'user-1',
    applicationId: 'app-1',
    uploadId: 'upload-1',
    filename,
    declaredContentType: contentType,
    declaredSizeBytes: sizeBytes,
    now: '2026-01-01T00:00:00.000Z',
  });
}

function ingestionJob(uploadId: string): IngestionJob {
  return {
    schemaVersion: 1,
    jobId: 'job-1',
    idempotencyKey: 'ingest-upload-1',
    ownerId: 'user-1',
    applicationId: 'app-1',
    uploadId,
    attempt: 1,
    enqueuedAt: '2026-01-01T00:00:00.000Z',
  };
}

function sequentialClock(): () => string {
  let second = 0;
  return () => `2026-01-01T00:00:${String(second++).padStart(2, '0')}.000Z`;
}
