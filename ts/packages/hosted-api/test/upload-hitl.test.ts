import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ApplicationId,
  HitlRequest,
  InteractionId,
} from '@threatforest/types';
import { runLeaseResourceId } from '@threatforest/control-plane';
import {
  HASH_A,
  HASH_B,
  OWNER_A,
  apiEvent,
  createApplication,
  createRun,
  json,
  makeFixture,
} from './support.js';

test('multipart sessions enforce bucket, key, checksum, size, content type, and KMS constraints', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const size = 6 * 1024 * 1024;
  const create = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'create-upload',
      body: {
        filename: 'architecture.pdf',
        content_type: 'application/pdf',
        size_bytes: size,
        checksum_sha256: HASH_A,
      },
    }),
  );
  assert.equal(create.statusCode, 201);
  const uploadId = json(create).upload_id as string;
  const initiated = fixture.storage.initiated[0]!;
  assert.equal(initiated.bucket, 'threatforest-artifacts');
  assert.match(
    initiated.key,
    new RegExp(
      `^v1/owners/${OWNER_A}/applications/${application.id}/uploads/${uploadId}/original/source-`,
    ),
  );
  assert.equal(initiated.contentType, 'application/pdf');
  assert.equal(initiated.sizeBytes, size);
  assert.equal(initiated.checksumSha256, HASH_A);
  assert.match(initiated.kmsKeyId, /arn:aws:kms:eu-west-2/);
  assert.equal(initiated.metadata.sha256, HASH_A);

  const wrongSize = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'wrong-part-size',
        body: {
          part_number: 1,
          size_bytes: size - 1,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  assert.equal(wrongSize.statusCode, 422);

  const signed = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'sign-part',
        body: {
          part_number: 1,
          size_bytes: size,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  assert.equal(signed.statusCode, 200);
  assert.equal(
    (json(signed).headers as Record<string, string>)['x-amz-checksum-sha256'],
    Buffer.from(HASH_B, 'hex').toString('base64'),
  );

  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const session = await fixture.uploadSessions.get(scope, uploadId as never);
  assert.ok(session);
  fixture.storage.recordPart(session.storageUploadId, {
    partNumber: 1,
    sizeBytes: size,
    etag: '"etag-wrong"',
    checksumSha256: HASH_A,
  });

  const mismatched = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-mismatch',
        body: {
          parts: [
            {
              part_number: 1,
              size_bytes: size,
              etag: '"etag-correct"',
              checksum_sha256: HASH_B,
            },
          ],
        },
      },
    ),
  );
  assert.equal(mismatched.statusCode, 409);
  assert.equal(json(mismatched).code, 'upload_constraint_mismatch');
  assert.equal(fixture.storage.completeCalls, 0);

  fixture.storage.recordPart(session.storageUploadId, {
    partNumber: 1,
    sizeBytes: size,
    etag: '"etag-correct"',
    checksumSha256: HASH_B,
  });
  const completed = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-valid',
        body: {
          parts: [
            {
              part_number: 1,
              size_bytes: size,
              etag: '"etag-correct"',
              checksum_sha256: HASH_B,
            },
          ],
        },
      },
    ),
  );
  assert.equal(completed.statusCode, 200);
  assert.equal(
    ((json(completed).manifest as Record<string, unknown>).status),
    'uploaded',
  );
  assert.equal(fixture.storage.completeCalls, 1);
  assert.deepEqual(fixture.normalization.dispatches, [
    {
      ownerId: OWNER_A,
      applicationId: application.id,
      uploadId,
    },
  ]);
});

test('upload completion recovers without completing S3 twice', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const size = 6 * 1024 * 1024;
  const created = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'create-recoverable-upload',
      body: {
        filename: 'recoverable.pdf',
        content_type: 'application/pdf',
        size_bytes: size,
        checksum_sha256: HASH_A,
      },
    }),
  );
  const uploadId = String(json(created).upload_id);
  await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'sign-recoverable-upload',
        body: {
          part_number: 1,
          size_bytes: size,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const session = await fixture.uploadSessions.get(scope, uploadId as never);
  assert.ok(session);
  fixture.storage.recordPart(session.storageUploadId, {
    partNumber: 1,
    sizeBytes: size,
    etag: '"recoverable"',
    checksumSha256: HASH_B,
  });
  const originalPut = fixture.uploadSessions.put.bind(fixture.uploadSessions);
  let failAfterStorageCompletion = true;
  fixture.uploadSessions.put = async (putScope, putSession) => {
    if (
      failAfterStorageCompletion &&
      putSession.manifest.status === 'uploaded'
    ) {
      failAfterStorageCompletion = false;
      throw new Error('simulated post-S3 DynamoDB failure');
    }
    await originalPut(putScope, putSession);
  };
  const completionBody = {
    parts: [
      {
        part_number: 1,
        size_bytes: size,
        etag: '"recoverable"',
        checksum_sha256: HASH_B,
      },
    ],
  };

  const interrupted = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-recoverable-upload-1',
        body: completionBody,
      },
    ),
  );
  assert.equal(interrupted.statusCode, 500);
  assert.equal(fixture.storage.completeCalls, 1);
  const journal = await fixture.uploadSessions.get(scope, uploadId as never);
  assert.equal(journal?.manifest.status, 'uploading');
  assert.equal(journal?.completion?.state, 'completing');

  const recovered = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-recoverable-upload-1',
        body: completionBody,
      },
    ),
  );
  assert.equal(recovered.statusCode, 200);
  assert.equal(
    (json(recovered).manifest as Record<string, unknown>).status,
    'uploaded',
  );
  assert.equal(fixture.storage.completeCalls, 1);
  assert.equal(fixture.normalization.dispatches.length, 1);
});

test('upload completion retries storage when the first completion never committed', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const size = 6 * 1024 * 1024;
  const created = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'create-storage-retry-upload',
      body: {
        filename: 'storage-retry.pdf',
        content_type: 'application/pdf',
        size_bytes: size,
        checksum_sha256: HASH_A,
      },
    }),
  );
  const uploadId = String(json(created).upload_id);
  await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'sign-storage-retry-upload',
        body: {
          part_number: 1,
          size_bytes: size,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  fixture.storage.recordPart('storage-1', {
    partNumber: 1,
    sizeBytes: size,
    etag: '"storage-retry"',
    checksumSha256: HASH_B,
  });
  fixture.storage.failNextCompletion = true;
  const body = {
    parts: [
      {
        part_number: 1,
        size_bytes: size,
        etag: '"storage-retry"',
        checksum_sha256: HASH_B,
      },
    ],
  };

  const interrupted = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-storage-retry-upload',
        body,
      },
    ),
  );
  assert.equal(interrupted.statusCode, 500);
  assert.equal(fixture.storage.completionAttempts, 1);
  assert.equal(fixture.storage.completeCalls, 0);

  const recovered = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      {
        idempotencyKey: 'complete-storage-retry-upload',
        body,
      },
    ),
  );
  assert.equal(recovered.statusCode, 200);
  assert.equal(fixture.storage.completionAttempts, 2);
  assert.equal(fixture.storage.completeCalls, 1);
  assert.equal(fixture.normalization.dispatches.length, 1);
});

test('upload completion lease rejects a competing idempotency key', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const size = 6 * 1024 * 1024;
  const created = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'create-racing-upload',
      body: {
        filename: 'racing.pdf',
        content_type: 'application/pdf',
        size_bytes: size,
        checksum_sha256: HASH_A,
      },
    }),
  );
  const uploadId = String(json(created).upload_id);
  await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'sign-racing-upload',
        body: {
          part_number: 1,
          size_bytes: size,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  fixture.storage.recordPart('storage-1', {
    partNumber: 1,
    sizeBytes: size,
    etag: '"racing"',
    checksumSha256: HASH_B,
  });
  const originalComplete = fixture.storage.complete.bind(fixture.storage);
  let releaseCompletion!: () => void;
  const completionReleased = new Promise<void>((resolve) => {
    releaseCompletion = resolve;
  });
  let completionStarted!: () => void;
  const completionEntered = new Promise<void>((resolve) => {
    completionStarted = resolve;
  });
  fixture.storage.complete = async (request) => {
    completionStarted();
    await completionReleased;
    return originalComplete(request);
  };
  const body = {
    parts: [
      {
        part_number: 1,
        size_bytes: size,
        etag: '"racing"',
        checksum_sha256: HASH_B,
      },
    ],
  };
  const first = fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      { idempotencyKey: 'complete-racing-upload-a', body },
    ),
  );
  await completionEntered;

  const competing = await fixture.handler(
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/complete`,
      { idempotencyKey: 'complete-racing-upload-b', body },
    ),
  );
  assert.equal(competing.statusCode, 409);
  assert.equal(json(competing).code, 'completion_in_progress');
  releaseCompletion();
  assert.equal((await first).statusCode, 200);
  assert.equal(fixture.storage.completionAttempts, 1);
});

test('a stale upload presign cannot overwrite a completion journal', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const size = 6 * 1024 * 1024;
  const created = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'create-presign-race-upload',
      body: {
        filename: 'presign-race.pdf',
        content_type: 'application/pdf',
        size_bytes: size,
        checksum_sha256: HASH_A,
      },
    }),
  );
  const uploadId = String(json(created).upload_id);
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
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
    apiEvent(
      'POST',
      `/api/applications/${application.id}/uploads/${uploadId}/parts`,
      {
        idempotencyKey: 'sign-presign-race-upload',
        body: {
          part_number: 1,
          size_bytes: size,
          checksum_sha256: HASH_B,
        },
      },
    ),
  );
  await presignEntered;
  const claimed = await fixture.uploadSessions.claimCompletion(
    scope,
    uploadId as never,
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
  const durable = await fixture.uploadSessions.get(
    scope,
    uploadId as never,
  );
  assert.equal(durable?.completion?.claimId, 'completion-winner');
  assert.equal(durable?.signedParts['1'], undefined);
});

test('unsafe upload names and cross-user upload sessions are rejected', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const unsafe = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      idempotencyKey: 'unsafe-upload',
      body: {
        filename: '../secrets.txt',
        content_type: 'text/plain',
        size_bytes: 10,
        checksum_sha256: HASH_A,
      },
    }),
  );
  assert.equal(unsafe.statusCode, 422);

  const crossUser = await fixture.handler(
    apiEvent('POST', `/api/applications/${application.id}/uploads`, {
      owner: 'user_b' as never,
      idempotencyKey: 'cross-user-upload',
      body: {
        filename: 'safe.txt',
        content_type: 'text/plain',
        size_bytes: 10,
        checksum_sha256: HASH_A,
      },
    }),
  );
  assert.equal(crossUser.statusCode, 404);
});

test('stale HITL revisions are rejected and explicit skip is durable', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const run = await fixture.services.runs.getRecord(OWNER_A, runId);
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const acquiredAt = fixture.clock.now().toISOString();
  const lease = await fixture.controlPlane.acquireLease({
    ...scope,
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'worker_1',
    acquired_at: acquiredAt,
    expires_at: new Date(
      fixture.clock.now().getTime() + 10 * 60 * 1000,
    ).toISOString(),
  });
  const interactionId = 'interaction_1' as InteractionId;
  const request = (revision: number): HitlRequest => ({
    schema_version: 1,
    ...scope,
    interaction_id: interactionId,
    run_id: runId,
    stage_id: 'threat_review',
    kind: 'threat_review',
    revision,
    fencing_token: lease.fencing_token,
    trace_id: run.trace_id,
    status: 'pending',
    reason: { threats: [] },
    transcript_artifact: null,
    created_at: new Date(
      fixture.clock.now().getTime() + revision * 1000,
    ).toISOString(),
    expires_at: null,
  });
  const guard = { ...lease, observed_at: fixture.clock.now().toISOString() };
  await fixture.controlPlane.createHitlRequest(request(1), guard);
  await fixture.controlPlane.createHitlRequest(request(2), guard);

  const stale = await fixture.handler(
    apiEvent(
      'POST',
      `/api/runs/${runId}/interactions/${interactionId}/respond`,
      {
        idempotencyKey: 'stale-response',
        body: { revision: 1, text: 'Approve' },
      },
    ),
  );
  assert.equal(stale.statusCode, 409);
  assert.equal(json(stale).code, 'stale_revision');

  const skipped = await fixture.handler(
    apiEvent(
      'POST',
      `/api/runs/${runId}/interactions/${interactionId}/skip`,
      {
        idempotencyKey: 'skip-response',
        body: { revision: 2 },
      },
    ),
  );
  assert.equal(skipped.statusCode, 200);
  assert.deepEqual(json(skipped), { ok: true });
  assert.equal(
    (
      await fixture.controlPlane.getHitlResponse(
        scope,
        interactionId,
        2,
      )
    )?.action,
    'skip',
  );
  assert.deepEqual(
    await fixture.controlPlane.listPendingHitl(scope, runId),
    [],
  );
  assert.deepEqual(fixture.orchestrator.continuations, [
    {
      scope,
      runId,
      traceId: run.trace_id,
    },
  ]);
});
