import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ApplicationId,
  ArtifactId,
  HitlRequest,
  HitlResponse,
  HostedProgressEvent,
  IdempotencyRecord,
  InteractionId,
  RunId,
  RunSettingsSnapshot,
  StageCheckpoint,
  UserId,
} from '@threatforest/types';
import { ControlPlaneError } from '../src/errors.js';
import { InMemoryControlPlane } from '../src/in-memory.js';
import { runLeaseResourceId } from '../src/keys.js';
import type {
  ApplicationRecord,
  ControlPlaneScope,
  LeaseGuard,
  RunRecord,
} from '../src/models.js';
import { reconstructRun } from '../src/reconstruct.js';

const hash = 'a'.repeat(64);
const traceId = '0123456789abcdef';
const start = '2026-08-19T12:00:00.000Z';
const ownerA = 'user_a' as UserId;
const ownerB = 'user_b' as UserId;
const applicationId = 'app_01' as ApplicationId;
const runId = 'run_01' as RunId;
const artifactId = 'artifact_01' as ArtifactId;

function scope(ownerId = ownerA): ControlPlaneScope {
  return { owner_id: ownerId, application_id: applicationId };
}

function application(ownerId = ownerA): ApplicationRecord {
  return {
    schema_version: 1,
    ...scope(ownerId),
    name: `Application for ${ownerId}`,
    description: null,
    revision: 1,
    created_at: start,
    updated_at: start,
  };
}

function run(ownerId = ownerA): RunRecord {
  return {
    schema_version: 1,
    ...scope(ownerId),
    run_id: runId,
    status: 'running',
    source_artifact_ids: [artifactId],
    threat_artifact_id: null,
    current_stage_id: 'scanner',
    trace_id: traceId,
    revision: 1,
    last_event_sequence: -1,
    created_at: start,
    updated_at: start,
    completed_at: null,
    error_code: null,
    error_message: null,
  };
}

async function seedRun(store: InMemoryControlPlane, ownerId = ownerA): Promise<LeaseGuard> {
  await store.createApplication(application(ownerId));
  await store.createRun(run(ownerId));
  const lease = await store.acquireLease({
    ...scope(ownerId),
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'worker_01',
    acquired_at: start,
    expires_at: '2026-08-19T12:10:00.000Z',
  });
  return { ...lease, observed_at: '2026-08-19T12:00:01.000Z' };
}

function event(sequence: number, ownerId = ownerA): HostedProgressEvent {
  return {
    schema_version: 1,
    ...scope(ownerId),
    run_id: runId,
    sequence,
    event_id: `event_${sequence}`,
    trace_id: traceId,
    type: 'stage_progress',
    stage: 'scanner',
    percentage: sequence * 10,
    message: `event ${sequence}`,
    payload: {},
    emitted_at: `2026-08-19T12:00:0${sequence}.000Z`,
  };
}

function checkpoint(fencingToken: number, status: StageCheckpoint['status']): StageCheckpoint {
  return {
    schema_version: 1,
    ...scope(),
    run_id: runId,
    stage_id: 'scanner',
    stage_version: 1,
    attempt: 1,
    fencing_token: fencingToken,
    idempotency_key: 'scanner_run_01',
    trace_id: traceId,
    status,
    input_artifacts: [],
    output_artifacts: [],
    model_id: 'anthropic.claude-sonnet',
    config_hash: hash,
    started_at: start,
    completed_at: status === 'completed' ? '2026-08-19T12:01:00.000Z' : null,
    error_code: null,
    error_message: null,
  };
}

function settingsSnapshot(): RunSettingsSnapshot {
  return {
    schema_version: 1,
    ...scope(),
    run_id: runId,
    provider: 'bedrock',
    model_id: 'anthropic.claude-sonnet',
    model_parameters: { temperature: 0.1 },
    frameworks: ['STRIDE', 'MITRE ATT&CK', 'PASTA'],
    embeddings_model: 'amazon.titan-embed-text-v2:0',
    config_hash: hash,
    created_at: start,
  };
}

function hitlRequest(revision: number, fencingToken: number): HitlRequest {
  return {
    schema_version: 1,
    ...scope(),
    interaction_id: 'interaction_01' as InteractionId,
    run_id: runId,
    stage_id: 'threat_review',
    kind: 'threat_review',
    revision,
    fencing_token: fencingToken,
    trace_id: traceId,
    status: 'pending',
    reason: { threats: [] },
    transcript_artifact: null,
    created_at: `2026-08-19T12:0${revision}:00.000Z`,
    expires_at: null,
  };
}

function response(revision: number, action: HitlResponse['action']): HitlResponse {
  return {
    schema_version: 1,
    ...scope(),
    interaction_id: 'interaction_01' as InteractionId,
    run_id: runId,
    revision,
    action,
    text: action === 'skip' ? null : 'Approved with edits',
    submitted_at: '2026-08-19T12:05:00.000Z',
  };
}

function hasCode(code: ControlPlaneError['code']): (error: unknown) => boolean {
  return (error) => error instanceof ControlPlaneError && error.code === code;
}

test('events append with a gap-free monotonic sequence and replay in order', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);

  await store.appendEvent(event(0), lease);
  await assert.rejects(store.appendEvent(event(2), lease), hasCode('conflict'));
  await store.appendEvent(event(1), lease);
  await assert.rejects(store.appendEvent(event(1), lease), hasCode('conflict'));

  assert.deepEqual(
    (await store.listEvents(scope(), runId)).map((item) => item.sequence),
    [0, 1],
  );
  assert.deepEqual(
    (await store.listEvents(scope(), runId, 0)).map((item) => item.sequence),
    [1],
  );
  assert.equal((await store.getRun(scope(), runId))?.last_event_sequence, 1);
});

test('durable records reconstruct a run without process-local workflow state', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);
  const snapshot = settingsSnapshot();
  const completed = checkpoint(lease.fencing_token, 'completed');

  await store.putApplicationSettings(
    {
      schema_version: 1,
      ...scope(),
      revision: 1,
      provider: snapshot.provider,
      model_id: snapshot.model_id,
      model_parameters: snapshot.model_parameters,
      frameworks: snapshot.frameworks,
      embeddings_model: snapshot.embeddings_model,
      config_hash: snapshot.config_hash,
      updated_at: start,
    },
    null,
  );
  await store.putRunSettingsSnapshot(snapshot);
  await store.putCheckpoint(completed, lease);
  await store.appendEvent(event(0), lease);
  await store.createHitlRequest(hitlRequest(1, lease.fencing_token), lease);

  const restored = await reconstructRun(store, scope(), runId);
  assert.equal(restored.run.run_id, runId);
  assert.equal(restored.settings.model_id, snapshot.model_id);
  assert.equal(restored.checkpoints[0]?.status, 'completed');
  assert.equal(restored.events[0]?.sequence, 0);
  assert.equal(restored.pending_interactions[0]?.revision, 1);

  await store.putRunSettingsSnapshot(snapshot);
  await assert.rejects(
    store.putRunSettingsSnapshot({ ...snapshot, model_id: 'different-model' }),
    hasCode('immutable_record'),
  );
  await assert.rejects(
    store.putCheckpoint({ ...completed, status: 'failed', completed_at: start }, lease),
    hasCode('immutable_record'),
  );
});

test('resume preserves checkpoints and event history while clearing stale control', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);
  await store.putCheckpoint(
    checkpoint(lease.fencing_token, 'completed'),
    lease,
  );
  await store.appendEvent(event(0), lease);
  await store.requestRunControl({
    ...scope(),
    run_id: runId,
    action: 'pause',
    requested_at: '2026-08-19T12:02:00.000Z',
  });
  const current = (await store.getRun(scope(), runId))!;
  await store.updateRun(
    {
      ...current,
      status: 'failed',
      revision: current.revision + 1,
      updated_at: '2026-08-19T12:03:00.000Z',
      error_code: 'STAGE_FAILED',
      error_message: 'scanner failed',
    },
    current.revision,
    lease,
  );

  const resumed = await store.resumeRun({
    ...scope(),
    run_id: runId,
    expected_revision: 2,
    expected_status: 'failed',
    resumed_at: '2026-08-19T12:04:00.000Z',
  });

  assert.equal(resumed.run_id, runId);
  assert.equal(resumed.status, 'queued');
  assert.equal(resumed.revision, 3);
  assert.equal(resumed.last_event_sequence, 0);
  assert.equal(resumed.error_code, null);
  assert.equal((await store.listCheckpoints(scope(), runId)).length, 1);
  assert.equal((await store.listEvents(scope(), runId)).length, 1);
  assert.equal(await store.getRunControl(scope(), runId), null);
});

test('only a durable manual pause can resume from awaiting_input', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);
  const current = (await store.getRun(scope(), runId))!;
  const paused = await store.updateRun(
    {
      ...current,
      status: 'awaiting_input',
      current_stage_id: 'scanner',
      revision: current.revision + 1,
      updated_at: '2026-08-19T12:02:00.000Z',
    },
    current.revision,
    lease,
  );
  await assert.rejects(
    store.resumeRun({
      ...scope(),
      run_id: runId,
      expected_revision: paused.revision,
      expected_status: 'awaiting_input',
      resumed_at: '2026-08-19T12:03:00.000Z',
    }),
    hasCode('conflict'),
  );

  await store.requestRunControl({
    ...scope(),
    run_id: runId,
    action: 'pause',
    requested_at: '2026-08-19T12:03:00.000Z',
  });
  const resumed = await store.resumeRun({
    ...scope(),
    run_id: runId,
    expected_revision: paused.revision,
    expected_status: 'awaiting_input',
    resumed_at: '2026-08-19T12:04:00.000Z',
  });
  assert.equal(resumed.status, 'queued');
  assert.equal(resumed.revision, paused.revision + 1);
  assert.equal(await store.getRunControl(scope(), runId), null);
});

test('a response for a stale HITL revision is rejected', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);
  await store.createHitlRequest(hitlRequest(1, lease.fencing_token), lease);
  await store.createHitlRequest(hitlRequest(2, lease.fencing_token), lease);

  await assert.rejects(store.respondToHitl(response(1, 'submit')), hasCode('stale_revision'));
  assert.equal(
    (await store.getHitlRequest(scope(), 'interaction_01' as InteractionId, 1))?.status,
    'superseded',
  );
  assert.equal((await store.getHitlRequest(scope(), 'interaction_01' as InteractionId))?.revision, 2);
});

test('explicit HITL skip is durable and only one response is accepted', async () => {
  const store = new InMemoryControlPlane();
  const lease = await seedRun(store);
  await store.createHitlRequest(hitlRequest(1, lease.fencing_token), lease);
  const skipped = response(1, 'skip');

  await store.respondToHitl(skipped);
  assert.deepEqual(
    await store.getHitlResponse(scope(), skipped.interaction_id, skipped.revision),
    skipped,
  );
  assert.equal(
    (await store.getHitlRequest(scope(), skipped.interaction_id, skipped.revision))?.status,
    'skipped',
  );
  assert.deepEqual(await store.listPendingHitl(scope(), runId), []);
  await assert.rejects(store.respondToHitl(skipped), hasCode('already_exists'));
});

test('owner and application scope prevents cross-user reads and writes', async () => {
  const store = new InMemoryControlPlane();
  const leaseA = await seedRun(store, ownerA);
  await store.createApplication(application(ownerB));

  assert.equal(await store.getRun(scope(ownerB), runId), null);
  assert.equal((await store.listApplications(ownerA)).length, 1);
  assert.equal((await store.listApplications(ownerB)).length, 1);
  await assert.rejects(
    store.appendEvent(event(0, ownerB), leaseA),
    hasCode('invalid_input'),
  );
  assert.deepEqual(await store.listEvents(scope(ownerB), runId), []);
});

test('lease fencing survives release and idempotency claims reject stale owners', async () => {
  const store = new InMemoryControlPlane();
  await store.createApplication(application());
  await store.createRun(run());
  const lease1 = await store.acquireLease({
    ...scope(),
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'worker_01',
    acquired_at: start,
    expires_at: '2026-08-19T12:01:00.000Z',
  });
  const lease2 = await store.acquireLease({
    ...scope(),
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'worker_02',
    acquired_at: '2026-08-19T12:01:00.000Z',
    expires_at: '2026-08-19T12:03:00.000Z',
  });
  assert.equal(lease2.fencing_token, 2);
  await assert.rejects(
    store.putCheckpoint(checkpoint(lease1.fencing_token, 'started'), {
      ...lease1,
      observed_at: '2026-08-19T12:00:30.000Z',
    }),
    hasCode('lease_lost'),
  );
  await store.releaseLease({
    ...scope(),
    resource_id: lease2.resource_id,
    lease_owner_id: lease2.lease_owner_id,
    fencing_token: lease2.fencing_token,
    released_at: '2026-08-19T12:02:00.000Z',
  });
  const lease3 = await store.acquireLease({
    ...scope(),
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'worker_03',
    acquired_at: '2026-08-19T12:02:00.000Z',
    expires_at: '2026-08-19T12:04:00.000Z',
  });
  assert.equal(lease3.fencing_token, 3);
  await store.putCheckpoint(checkpoint(lease3.fencing_token, 'started'), {
    ...lease3,
    observed_at: '2026-08-19T12:02:01.000Z',
  });

  const idempotency: IdempotencyRecord = {
    schema_version: 1,
    ...scope(),
    key: 'start_run_request_01',
    operation: 'start_run',
    request_hash: hash,
    status: 'in_progress',
    response_artifact: null,
    created_at: start,
    expires_at: '2026-08-20T12:00:00.000Z',
  };
  assert.equal((await store.claimIdempotency(idempotency, start)).acquired, true);
  assert.equal((await store.claimIdempotency(idempotency, start)).acquired, false);
  await assert.rejects(
    store.claimIdempotency({ ...idempotency, request_hash: 'b'.repeat(64) }, start),
    hasCode('conflict'),
  );
  const completed = await store.completeIdempotency({
    ...scope(),
    key: idempotency.key,
    request_hash: idempotency.request_hash,
    claim_created_at: idempotency.created_at,
    response_artifact: null,
  });
  assert.equal(completed.status, 'completed');
  assert.equal((await store.claimIdempotency(idempotency, start)).record.status, 'completed');
  await assert.rejects(
    store.failIdempotency({
      ...scope(),
      key: idempotency.key,
      request_hash: idempotency.request_hash,
      claim_created_at: '2026-08-19T11:59:00.000Z',
    }),
    hasCode('conflict'),
  );

  const retryable = {
    ...idempotency,
    key: 'retryable_request_01',
  };
  assert.equal((await store.claimIdempotency(retryable, start)).acquired, true);
  const failed = await store.failIdempotency({
    ...scope(),
    key: retryable.key,
    request_hash: retryable.request_hash,
    claim_created_at: retryable.created_at,
  });
  assert.equal(failed.status, 'failed');
  assert.equal(failed.expires_at, retryable.created_at);
  const retryObservedAt = '2026-08-19T12:00:01.000Z';
  assert.equal(
    (
      await store.claimIdempotency(
        {
          ...retryable,
          created_at: retryObservedAt,
          expires_at: '2026-08-20T12:00:01.000Z',
        },
        retryObservedAt,
      )
    ).acquired,
    true,
  );

  const pause = await store.requestRunControl({
    ...scope(),
    run_id: runId,
    action: 'pause',
    requested_at: '2026-08-19T12:00:02.000Z',
  });
  assert.equal(pause.action, 'pause');
  const stop = await store.requestRunControl({
    ...scope(),
    run_id: runId,
    action: 'stop',
    requested_at: '2026-08-19T12:00:03.000Z',
  });
  assert.equal(stop.action, 'stop');
  assert.equal((await store.getRunControl(scope(), runId))?.action, 'stop');
  const cannotDowngrade = await store.requestRunControl({
    ...scope(),
    run_id: runId,
    action: 'pause',
    requested_at: '2026-08-19T12:00:04.000Z',
  });
  assert.equal(cannotDowngrade.action, 'stop');
});
