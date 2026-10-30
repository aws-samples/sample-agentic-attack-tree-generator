import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ImmutableObjectConflictError,
  InMemoryObjectAdapter,
  InvalidWorkspaceIdentifierError,
  S3Workspace,
  WorkspaceIntegrityError,
  canonicalObjectKey,
  type RunObjectLocator,
  type UploadObjectLocator,
} from '../src/index.js';

const upload: UploadObjectLocator = {
  scope: 'upload',
  ownerId: 'user-1',
  applicationId: 'app-1',
  uploadId: 'upload-1',
  area: 'original',
  objectId: 'source-1',
};

test('canonical keys are scoped and reject traversal and control characters', () => {
  assert.equal(
    canonicalObjectKey(upload),
    'v1/owners/user-1/applications/app-1/uploads/upload-1/original/source-1',
  );
  assert.throws(
    () => canonicalObjectKey({ ...upload, ownerId: '../other-user' }),
    InvalidWorkspaceIdentifierError,
  );
  assert.throws(
    () => canonicalObjectKey({ ...upload, objectId: 'source\u0000evil' }),
    InvalidWorkspaceIdentifierError,
  );
  assert.throws(
    () => canonicalObjectKey({ ...upload, uploadId: '%2Fadmin' }),
    InvalidWorkspaceIdentifierError,
  );
  assert.equal(canonicalObjectKey(upload).includes('customer filename.md'), false);
});

test('workspace writes, reads, lists, copies, and isolates logical scopes', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'arn:aws:kms:eu-west-2:123:key/test');
  const written = await workspace.write(upload, 'hello', {
    contentType: 'text/plain',
    immutable: true,
    metadata: { Filename: 'customer filename.md' },
  });
  assert.equal(written.created, true);
  assert.equal(await workspace.exists(upload), true);
  assert.equal(Buffer.from((await workspace.read(upload))!.body).toString('utf8'), 'hello');
  assert.deepEqual(
    (
      await workspace.list({
        scope: 'upload',
        ownerId: 'user-1',
        applicationId: 'app-1',
        uploadId: 'upload-1',
        area: 'original',
      })
    ).map((item) => item.locator.objectId),
    ['source-1'],
  );

  const otherOwner = { ...upload, ownerId: 'user-2' };
  assert.equal(await workspace.exists(otherOwner), false);
  assert.deepEqual(
    await workspace.list({
      scope: 'upload',
      ownerId: 'user-2',
      applicationId: 'app-1',
      uploadId: 'upload-1',
      area: 'original',
    }),
    [],
  );

  const destination: RunObjectLocator = {
    scope: 'run',
    ownerId: 'user-1',
    applicationId: 'app-1',
    runId: 'run-1',
    area: 'input',
    objectId: 'source-1',
  };
  const copied = await workspace.copy(upload, destination, { immutable: true });
  assert.equal(copied.sha256, written.sha256);
  assert.equal(Buffer.from((await workspace.read(destination))!.body).toString(), 'hello');
});

test('immutable writes are idempotent and reject content replacement', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-key');
  assert.equal(
    (await workspace.write(upload, 'same', { contentType: 'text/plain', immutable: true }))
      .created,
    true,
  );
  assert.equal(
    (await workspace.write(upload, 'same', { contentType: 'text/plain', immutable: true }))
      .created,
    false,
  );
  await assert.rejects(
    workspace.write(upload, 'different', { contentType: 'text/plain', immutable: true }),
    ImmutableObjectConflictError,
  );
});

test('all adapter writes and copies receive SSE-KMS and checksum parameters', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'arn:aws:kms:eu-west-2:123:key/upload');
  await workspace.write(upload, 'encrypted', {
    contentType: 'text/plain',
    immutable: true,
  });
  const destination = { ...upload, area: 'normalized' as const, objectId: 'text-1' };
  await workspace.copy(upload, destination, { immutable: true });

  assert.equal(adapter.putInputs[0]!.serverSideEncryption, 'aws:kms');
  assert.equal(adapter.putInputs[0]!.ssekmsKeyId.endsWith('/upload'), true);
  assert.match(adapter.putInputs[0]!.checksumSha256, /^[A-Za-z0-9+/]{43}=$/);
  assert.equal(adapter.copyInputs[0]!.serverSideEncryption, 'aws:kms');
  assert.equal(adapter.copyInputs[0]!.ifNoneMatch, '*');
});

test('workspace verifies content hashes on read', async () => {
  const adapter = new InMemoryObjectAdapter();
  const workspace = new S3Workspace(adapter, 'kms-key');
  await workspace.write(upload, 'original', { contentType: 'text/plain', immutable: true });
  adapter.corrupt(upload, Buffer.from('tampered'));
  await assert.rejects(workspace.read(upload), WorkspaceIntegrityError);
});
