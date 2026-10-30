import assert from 'node:assert/strict';
import test from 'node:test';
import {
  HitlRequestSchema,
  HitlResponseSchema,
  HostedProgressEventSchema,
  HostedRunInputSchema,
  IdempotencyRecordSchema,
  LeaseSchema,
  UploadManifestSchema,
} from './hosted.js';

const now = '2026-08-19T12:00:00.000Z';
const hash = 'a'.repeat(64);

test('upload manifests accept multipart state and normalized artifacts', () => {
  const manifest = UploadManifestSchema.parse({
    schema_version: 1,
    owner_id: 'user_01',
    upload_id: 'upload_01',
    application_id: 'app_01',
    filename: 'architecture.pdf',
    content_type: 'application/pdf',
    size_bytes: 12,
    status: 'ready',
    parts: [{ part_number: 1, size_bytes: 12, etag: 'etag-1' }],
    source_artifact: {
      artifact_id: 'artifact_source',
      kind: 'source',
      version: 1,
      content_type: 'application/pdf',
      size_bytes: 12,
      sha256: hash,
      created_at: now,
    },
    normalized_artifacts: [],
    created_at: now,
    updated_at: now,
  });

  assert.equal(manifest.parts[0]?.part_number, 1);
  assert.equal(manifest.source_artifact?.artifact_id, 'artifact_source');
});

test('progress events require a monotonic sequence-compatible integer', () => {
  assert.throws(() =>
    HostedProgressEventSchema.parse({
      schema_version: 1,
      owner_id: 'user_01',
      application_id: 'app_01',
      run_id: 'run_01',
      sequence: -1,
      event_id: 'event_01',
      trace_id: '1234567890abcdef',
      type: 'stage_start',
      emitted_at: now,
    }),
  );
});

test('HITL responses are bound to interaction, run, and revision', () => {
  const request = HitlRequestSchema.parse({
    schema_version: 1,
    owner_id: 'user_01',
    application_id: 'app_01',
    interaction_id: 'interaction_01',
    run_id: 'run_01',
    stage_id: 'threat_review',
    kind: 'threat_review',
    revision: 3,
    fencing_token: 8,
    trace_id: '1234567890abcdef',
    status: 'pending',
    reason: { threats: [] },
    created_at: now,
  });
  const response = HitlResponseSchema.parse({
    schema_version: 1,
    owner_id: request.owner_id,
    application_id: request.application_id,
    interaction_id: request.interaction_id,
    run_id: request.run_id,
    revision: request.revision,
    action: 'skip',
    submitted_at: now,
  });

  assert.equal(response.revision, 3);
  assert.equal(response.text, null);
});

test('leases separate resource ownership from the active worker', () => {
  const lease = LeaseSchema.parse({
    schema_version: 1,
    owner_id: 'user_01',
    application_id: 'app_01',
    resource_id: 'run_01#scanner',
    lease_owner_id: 'runtime-worker-01',
    fencing_token: 4,
    acquired_at: now,
    expires_at: '2026-08-19T12:05:00.000Z',
  });

  assert.equal(lease.owner_id, 'user_01');
  assert.equal(lease.lease_owner_id, 'runtime-worker-01');
  assert.equal(lease.application_id, 'app_01');
});

test('idempotency records are scoped to a user and application', () => {
  const record = IdempotencyRecordSchema.parse({
    schema_version: 1,
    owner_id: 'user_01',
    application_id: 'app_01',
    key: 'start-run-request-01',
    operation: 'start_run',
    request_hash: hash,
    status: 'in_progress',
    created_at: now,
    expires_at: '2026-08-20T12:00:00.000Z',
  });

  assert.equal(record.owner_id, 'user_01');
  assert.equal(record.application_id, 'app_01');
  assert.throws(() =>
    IdempotencyRecordSchema.parse({
      ...record,
      owner_id: undefined,
    }),
  );
});

test('hosted run input accepts artifacts while preserving local path compatibility', () => {
  assert.equal(
    HostedRunInputSchema.parse({
      application_id: 'app_01',
      source_artifact_ids: ['artifact_01'],
    }).project_path,
    null,
  );
  assert.equal(
    HostedRunInputSchema.parse({
      application_id: 'app_01',
      project_path: '/tmp/local-app',
    }).source_artifact_ids.length,
    0,
  );
  assert.throws(() => HostedRunInputSchema.parse({ application_id: 'app_01' }));
});
