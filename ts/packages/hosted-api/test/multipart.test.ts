import assert from 'node:assert/strict';
import { S3Client } from '@aws-sdk/client-s3';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { S3MultipartStorageAdapter } from '../src/aws/multipart.js';
import type {
  CompletedPart,
  MultipartInitiateRequest,
} from '../src/contracts.js';

const PART_BODIES = [
  Buffer.alloc(5 * 1024 * 1024, 0x61),
  Buffer.from('final multipart bytes'),
];
const PART_DIGESTS = PART_BODIES.map((body) =>
  createHash('sha256').update(body).digest('hex'),
);
const WHOLE_DIGEST = createHash('sha256')
  .update(Buffer.concat(PART_BODIES))
  .digest('hex');
const COMPOSITE_BASE64 = createHash('sha256')
  .update(
    Buffer.concat(
      PART_DIGESTS.map((checksum) => Buffer.from(checksum, 'hex')),
    ),
  )
  .digest('base64');
const COMPOSITE_CHECKSUM = `${COMPOSITE_BASE64}-${PART_BODIES.length}`;

const REQUEST: MultipartInitiateRequest = {
  bucket: 'artifacts',
  key: 'v1/owners/user/upload',
  contentType: 'application/pdf',
  sizeBytes: PART_BODIES.reduce((total, body) => total + body.byteLength, 0),
  checksumSha256: WHOLE_DIGEST,
  kmsKeyId: 'arn:aws:kms:eu-west-2:123456789012:key/test',
  metadata: {
    owner_id: 'owner',
    checksum_sha256: WHOLE_DIGEST,
  },
};
const PARTS: CompletedPart[] = PART_BODIES.map((body, index) => ({
  partNumber: index + 1,
  sizeBytes: body.byteLength,
  etag: `"etag-${index + 1}"`,
  checksumSha256: PART_DIGESTS[index]!,
}));

function completedHead() {
  return {
    ContentLength: REQUEST.sizeBytes,
    ContentType: REQUEST.contentType,
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: REQUEST.kmsKeyId,
    ChecksumSHA256: COMPOSITE_CHECKSUM,
    ChecksumType: 'COMPOSITE',
    Metadata: REQUEST.metadata,
    VersionId: 'version-1',
  };
}

test('multipart initiation explicitly selects SHA-256 composite checksums', async () => {
  const commands: Array<{ input: Record<string, unknown> }> = [];
  const adapter = new S3MultipartStorageAdapter({
    async send(command: { input: Record<string, unknown> }) {
      commands.push(command);
      return { UploadId: 'upload-id' };
    },
  } as never);

  assert.deepEqual(await adapter.initiate(REQUEST), {
    storageUploadId: 'upload-id',
  });
  assert.equal(commands[0]!.input['ChecksumAlgorithm'], 'SHA256');
  assert.equal(commands[0]!.input['ChecksumType'], 'COMPOSITE');
  assert.equal(commands[0]!.input['ServerSideEncryption'], 'aws:kms');
  assert.equal(commands[0]!.input['SSEKMSKeyId'], REQUEST.kmsKeyId);
});

test('part presigning binds the checksum as a required signed header', async () => {
  const adapter = new S3MultipartStorageAdapter(
    new S3Client({
      region: 'eu-west-2',
      credentials: {
        accessKeyId: 'AKIATEST',
        secretAccessKey: 'test-secret',
      },
    }),
  );
  const signature = await adapter.presignPart({
    ...REQUEST,
    storageUploadId: 'upload-id',
    partNumber: 1,
    partSizeBytes: PART_BODIES[0]!.byteLength,
    partChecksumSha256: PART_DIGESTS[0]!,
    expiresInSeconds: 300,
  });
  const url = new URL(signature.url);
  const signedHeaders = url.searchParams.get('X-Amz-SignedHeaders') ?? '';

  assert.match(signedHeaders, /(?:^|;)x-amz-checksum-sha256(?:;|$)/);
  assert.equal(url.searchParams.has('x-amz-checksum-sha256'), false);
  assert.equal(
    signature.headers['x-amz-checksum-sha256'],
    Buffer.from(PART_DIGESTS[0]!, 'hex').toString('base64'),
  );
});

test('completion sends part checksums and the S3 composite instead of the whole-file digest', async () => {
  const commands: Array<{ constructor: { name: string }; input: Record<string, unknown> }> = [];
  const adapter = new S3MultipartStorageAdapter({
    async send(command: {
      constructor: { name: string };
      input: Record<string, unknown>;
    }) {
      commands.push(command);
      return {
        ChecksumSHA256: COMPOSITE_CHECKSUM,
        ChecksumType: 'COMPOSITE',
        VersionId: 'version-1',
      };
    },
  } as never);

  assert.deepEqual(
    await adapter.complete({
      ...REQUEST,
      storageUploadId: 'upload-id',
      parts: PARTS,
    }),
    { versionId: 'version-1' },
  );
  const input = commands[0]!.input;
  assert.equal(commands[0]!.constructor.name, 'CompleteMultipartUploadCommand');
  assert.equal(input['ChecksumSHA256'], COMPOSITE_BASE64);
  assert.notEqual(
    input['ChecksumSHA256'],
    Buffer.from(WHOLE_DIGEST, 'hex').toString('base64'),
  );
  assert.equal(input['ChecksumType'], 'COMPOSITE');
  assert.equal(input['MpuObjectSize'], REQUEST.sizeBytes);
  assert.deepEqual(
    (input['MultipartUpload'] as {
      Parts: Array<{ ChecksumSHA256: string }>;
    }).Parts.map(({ ChecksumSHA256 }) => ChecksumSHA256),
    PART_DIGESTS.map((digest) =>
      Buffer.from(digest, 'hex').toString('base64'),
    ),
  );
});

test('completed multipart inspection verifies composite checksum, canonical metadata, encryption, and size', async () => {
  const commands: Array<{ input: Record<string, unknown> }> = [];
  const adapter = new S3MultipartStorageAdapter({
    async send(command: { input: Record<string, unknown> }) {
      commands.push(command);
      return completedHead();
    },
  } as never);

  assert.deepEqual(
    await adapter.inspectCompleted({ ...REQUEST, parts: PARTS }),
    { versionId: 'version-1' },
  );
  assert.equal(commands[0]!.input['ChecksumMode'], 'ENABLED');
});

test('completed multipart inspection distinguishes missing and mismatched objects', async () => {
  const missing = new S3MultipartStorageAdapter({
    async send() {
      const error = new Error('missing');
      error.name = 'NotFound';
      throw error;
    },
  } as never);
  assert.equal(
    await missing.inspectCompleted({ ...REQUEST, parts: PARTS }),
    null,
  );

  const mismatched = new S3MultipartStorageAdapter({
    async send() {
      return { ...completedHead(), ChecksumSHA256: `${COMPOSITE_BASE64}-1` };
    },
  } as never);
  await assert.rejects(
    mismatched.inspectCompleted({ ...REQUEST, parts: PARTS }),
    /does not match its durable constraints/,
  );
});

test('NoSuchUpload completion retries are accepted only when the final object verifies', async () => {
  const commands: string[] = [];
  const adapter = new S3MultipartStorageAdapter({
    async send(command: object) {
      commands.push(command.constructor.name);
      if (command.constructor.name === 'CompleteMultipartUploadCommand') {
        const error = new Error('already consumed');
        error.name = 'NoSuchUpload';
        throw error;
      }
      return completedHead();
    },
  } as never);

  assert.deepEqual(
    await adapter.complete({
      ...REQUEST,
      storageUploadId: 'upload-id',
      parts: PARTS,
    }),
    { versionId: 'version-1' },
  );
  assert.deepEqual(commands, [
    'CompleteMultipartUploadCommand',
    'HeadObjectCommand',
  ]);
});
