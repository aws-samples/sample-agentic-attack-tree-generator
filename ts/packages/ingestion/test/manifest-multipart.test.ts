import assert from 'node:assert/strict';
import test from 'node:test';
import {
  InvalidUploadTransitionError,
  MultipartVerificationError,
  createUploadManifest,
  retryFailedNormalization,
  sha256Base64,
  transitionUploadManifest,
  verifyMultipartCompletion,
} from '../src/index.js';

test('upload manifest enforces the state machine and explicit failure data', () => {
  const pending = createUploadManifest({
    ownerId: 'user-1',
    applicationId: 'app-1',
    uploadId: 'upload-1',
    filename: 'input.zip',
    declaredContentType: 'application/zip',
    declaredSizeBytes: 10,
    now: '2026-01-01T00:00:00.000Z',
  });
  const uploading = transitionUploadManifest(pending, 'uploading', {
    now: '2026-01-01T00:00:01.000Z',
  });
  assert.equal(uploading.revision, pending.revision + 1);
  const failed = transitionUploadManifest(uploading, 'failed', {
    failureCode: 'BAD_UPLOAD',
    failureReason: 'Invalid bytes',
    sourceObjectId: 'source-1',
    now: '2026-01-01T00:00:02.000Z',
  });
  assert.equal(failed.failureCode, 'BAD_UPLOAD');
  assert.throws(() => transitionUploadManifest(pending, 'ready'), InvalidUploadTransitionError);
  assert.throws(() => transitionUploadManifest(uploading, 'failed'), /require failureCode/);
  assert.equal(
    retryFailedNormalization(failed, '2026-01-01T00:00:03.000Z').status,
    'normalizing',
  );
});

test('multipart completion validates order, checksums, etags, and total size', () => {
  const firstChecksum = sha256Base64('first');
  const secondChecksum = sha256Base64('second');
  const expected = [
    { partNumber: 1, sizeBytes: 5, etag: 'etag1', checksumSha256: firstChecksum },
    { partNumber: 2, sizeBytes: 2, etag: 'etag2', checksumSha256: secondChecksum },
  ];
  const result = verifyMultipartCompletion(
    [
      { ...expected[0]!, etag: '"etag1"' },
      { ...expected[1]!, checksumSha256: Buffer.from('second').toString('hex').padEnd(64, '0') },
    ],
    {
      declaredSizeBytes: 7,
      minimumPartBytes: 5,
    },
  );
  assert.equal(result.totalSizeBytes, 7);
  assert.equal(result.parts[0]!.etag, 'etag1');
});

test('multipart completion rejects missing order, bad checksums, small parts, and size mismatch', () => {
  const checksum = sha256Base64('part');
  assert.throws(
    () =>
      verifyMultipartCompletion(
        [{ partNumber: 2, sizeBytes: 5, etag: 'etag', checksumSha256: checksum }],
        { declaredSizeBytes: 5, minimumPartBytes: 5 },
      ),
    (error: unknown) =>
      error instanceof MultipartVerificationError && error.code === 'INVALID_PART_ORDER',
  );
  assert.throws(
    () =>
      verifyMultipartCompletion(
        [
          { partNumber: 1, sizeBytes: 4, etag: 'etag1', checksumSha256: checksum },
          { partNumber: 2, sizeBytes: 1, etag: 'etag2', checksumSha256: checksum },
        ],
        { declaredSizeBytes: 5, minimumPartBytes: 5 },
      ),
    /below the minimum/,
  );
  assert.throws(
    () =>
      verifyMultipartCompletion(
        [{ partNumber: 1, sizeBytes: 5, etag: 'etag', checksumSha256: 'not-a-checksum' }],
        { declaredSizeBytes: 5 },
      ),
    /checksum/,
  );
  assert.throws(
    () =>
      verifyMultipartCompletion(
        [{ partNumber: 1, sizeBytes: 5, etag: 'etag', checksumSha256: checksum }],
        { declaredSizeBytes: 6 },
      ),
    /does not match declared size/,
  );
  assert.throws(
    () =>
      verifyMultipartCompletion(
        [{ partNumber: 1, sizeBytes: 5, etag: 'changed', checksumSha256: checksum }],
        {
          declaredSizeBytes: 5,
          expectedParts: [
            { partNumber: 1, sizeBytes: 5, etag: 'expected', checksumSha256: checksum },
          ],
        },
      ),
    /does not match the registered upload part/,
  );
});
