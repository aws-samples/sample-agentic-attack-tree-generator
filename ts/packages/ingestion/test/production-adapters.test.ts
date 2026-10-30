import assert from 'node:assert/strict';
import test from 'node:test';
import {
  AwsTextractOcrAdapter,
  DynamoIngestionStore,
  createUploadManifest,
  loadIngestionEnvironment,
  sha256Hex,
} from '../src/index.js';
import {
  createSqsIngestionHandler,
  type IngestionJobProcessor,
} from '../src/lambda/worker.js';

test('environment loader requires hosted resources and parses safety limits', () => {
  assert.throws(() => loadIngestionEnvironment({}), /AWS_REGION/);
  const environment = loadIngestionEnvironment({
    AWS_REGION: 'eu-west-2',
    INGESTION_BUCKET: 'uploads',
    INGESTION_KMS_KEY_ID: 'kms-key',
    INGESTION_TABLE_NAME: 'state',
    INGESTION_TEXTRACT_ENABLED: 'false',
    INGESTION_ARCHIVE_DUPLICATE_POLICY: 'rename',
    INGESTION_ARCHIVE_MAX_FILES: '42',
  });
  assert.equal(environment.region, 'eu-west-2');
  assert.equal(environment.textractEnabled, false);
  assert.equal(environment.archiveLimits.duplicatePolicy, 'rename');
  assert.equal(environment.archiveLimits.maximumFiles, 42);
});

test('SQS Lambda handler reports only records that need queue retry', async () => {
  const seen: string[] = [];
  const processor: IngestionJobProcessor = {
    async handle(job) {
      seen.push(job.jobId);
      if (job.jobId === 'transient') {
        throw new Error('DynamoDB unavailable');
      }
      return {
        status: job.jobId === 'content-failure' ? 'failed' : 'completed',
        uploadId: job.uploadId,
        normalizedObjectIds: [],
        failureCode: job.jobId === 'content-failure' ? 'UNSAFE_PATH' : null,
      };
    },
  };
  const handler = createSqsIngestionHandler(async () => processor);
  const response = await handler({
    Records: [
      { messageId: 'm1', body: JSON.stringify(job('ok')) },
      { messageId: 'm2', body: JSON.stringify(job('content-failure')) },
      { messageId: 'm3', body: JSON.stringify(job('transient')) },
      { messageId: 'm4', body: 'not-json' },
    ],
  });
  assert.deepEqual(seen, ['ok', 'content-failure', 'transient']);
  assert.deepEqual(response.batchItemFailures, [
    { itemIdentifier: 'm3' },
    { itemIdentifier: 'm4' },
  ]);
});

test('Dynamo manifest adapter uses the shared control-plane PK/SK convention and CAS', async () => {
  const sent: FakeCommand[] = [];
  const client = {
    async send(command: FakeCommand) {
      sent.push(command);
      return {};
    },
  };
  const store = new DynamoIngestionStore(
    'state-table',
    client,
    { get: FakeGet, put: FakePut, update: FakeUpdate },
    60,
  );
  const manifest = createUploadManifest({
    ownerId: 'user-1',
    applicationId: 'app-1',
    uploadId: 'upload-1',
    filename: 'README.md',
    declaredContentType: 'text/markdown',
    declaredSizeBytes: 10,
    now: '2026-01-01T00:00:00.000Z',
  });
  await store.create(manifest);
  await store.put(
    { ...manifest, revision: 2, updatedAt: '2026-01-01T00:00:01.000Z' },
    manifest.revision,
  );
  const createInput = sent[0]!.input;
  const item = createInput['Item'] as Record<string, unknown>;
  assert.match(item['PK'] as string, /^OWNER#[A-Za-z0-9_-]+#APP#[A-Za-z0-9_-]+$/);
  assert.match(item['SK'] as string, /^UPLOAD#[A-Za-z0-9_-]+#MANIFEST$/);
  assert.equal(createInput['ConditionExpression'], 'attribute_not_exists(PK)');
  assert.match(sent[1]!.input['ConditionExpression'] as string, /revision/);
});

test('Dynamo idempotency updates alias the reserved ttl attribute', async () => {
  const requestHash = sha256Hex('request');
  const input = {
    ownerId: 'user-1',
    applicationId: 'app-1',
    idempotencyKey: 'ingest-upload-1',
    requestHash,
    attempt: 2,
  };
  const failedRetry = await idempotencyStoreWithResponses([
    conditionalFailure(),
    {
      Item: {
        idempotencyKey: input.idempotencyKey,
        requestHash,
        attempt: 1,
        status: 'failed',
        result: null,
        leaseExpiresAt: 1,
      },
    },
    {},
  ]);
  await failedRetry.store.begin(input);

  const expiredLease = await idempotencyStoreWithResponses([
    conditionalFailure(),
    {
      Item: {
        idempotencyKey: input.idempotencyKey,
        requestHash,
        attempt: 1,
        status: 'in_progress',
        result: null,
        leaseExpiresAt: 1,
      },
    },
    {},
  ]);
  await expiredLease.store.begin(input);

  const completion = await idempotencyStoreWithResponses([{}]);
  await completion.store.complete({
    ...input,
    result: {
      status: 'completed',
      uploadId: 'upload-1',
      normalizedObjectIds: ['object-1'],
      failureCode: null,
    },
  });

  const updates = [
    ...failedRetry.sent,
    ...expiredLease.sent,
    ...completion.sent,
  ].filter((command) => command instanceof FakeUpdate);
  assert.equal(updates.length, 3);
  for (const command of updates) {
    assert.match(command.input['UpdateExpression'] as string, /#ttl = :ttl/);
    assert.equal(
      (command.input['ExpressionAttributeNames'] as Record<string, string>)['#ttl'],
      'ttl',
    );
  }
});

test('Textract async PDF adapter derives its S3 key from a canonical locator', async () => {
  const sent: FakeCommand[] = [];
  const responses: Record<string, unknown>[] = [
    { JobId: 'job-1' },
    {
      JobStatus: 'SUCCEEDED',
      Blocks: [
        {
          BlockType: 'LINE',
          Text: 'Architecture',
          Confidence: 99,
          Page: 1,
        },
      ],
    },
  ];
  const client = {
    async send(command: FakeCommand) {
      sent.push(command);
      return responses.shift() ?? {};
    },
  };
  const adapter = new AwsTextractOcrAdapter(
    'upload-bucket',
    client,
    { detect: FakeDetect, start: FakeStart, get: FakeGet },
    { pollIntervalMs: 1, maximumWaitMs: 100 },
    async () => {},
  );
  const result = await adapter.analyze({
    bytes: Buffer.from('%PDF-1.7'),
    mediaType: 'application/pdf',
    filename: 'architecture.pdf',
    workspaceLocator: {
      scope: 'upload',
      ownerId: 'user-1',
      applicationId: 'app-1',
      uploadId: 'upload-1',
      area: 'original',
      objectId: 'source-1',
    },
  });
  const location = (
    sent[0]!.input['DocumentLocation'] as {
      S3Object: { Bucket: string; Name: string };
    }
  ).S3Object;
  assert.equal(location.Bucket, 'upload-bucket');
  assert.equal(
    location.Name,
    'v1/owners/user-1/applications/app-1/uploads/upload-1/original/source-1',
  );
  assert.equal(result.pages[0]!.lines[0]!.text, 'Architecture');
});

function job(jobId: string) {
  return {
    schemaVersion: 1 as const,
    jobId,
    idempotencyKey: `idempotency-${jobId}`,
    ownerId: 'user-1',
    applicationId: 'app-1',
    uploadId: 'upload-1',
    attempt: 1,
    enqueuedAt: '2026-01-01T00:00:00.000Z',
  };
}

class FakeCommand {
  public constructor(public readonly input: Record<string, unknown>) {}
}
class FakeGet extends FakeCommand {}
class FakePut extends FakeCommand {}
class FakeUpdate extends FakeCommand {}
class FakeDetect extends FakeCommand {}
class FakeStart extends FakeCommand {}

async function idempotencyStoreWithResponses(
  responses: Array<Record<string, unknown> | Error>,
) {
  const sent: FakeCommand[] = [];
  const client = {
    async send(command: FakeCommand) {
      sent.push(command);
      const response = responses.shift();
      if (response instanceof Error) {
        throw response;
      }
      return response ?? {};
    },
  };
  return {
    sent,
    store: new DynamoIngestionStore(
      'state-table',
      client,
      { get: FakeGet, put: FakePut, update: FakeUpdate },
      60,
      30,
      () => new Date('2026-01-01T00:00:00.000Z'),
    ),
  };
}

function conditionalFailure(): Error {
  return Object.assign(new Error('conditional write failed'), {
    name: 'ConditionalCheckFailedException',
  });
}

// Keep this import exercised in the production-adapter suite; idempotency
// records use lowercase SHA-256 digests in DynamoDB conditions.
assert.equal(sha256Hex('request').length, 64);
