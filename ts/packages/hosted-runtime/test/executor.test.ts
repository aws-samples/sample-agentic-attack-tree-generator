import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ArtifactRefSchema,
  HitlResponseSchema,
  type RunId,
} from '@threatforest/types';
import {
  ControlPlaneError,
  InMemoryControlPlane,
  runLeaseResourceId,
  type ControlPlaneStore,
} from '@threatforest/control-plane';
import { InMemoryArtifactStore } from '../src/artifacts.js';
import type {
  ArtifactStore,
  BoundaryResult,
  StageDefinition,
} from '../src/contracts.js';
import { DurableBoundaryExecutor } from '../src/executor.js';
import {
  applicationId,
  authenticatedContext,
  deterministicActorDeriver,
  ManualClock,
  parseResponse,
  principal,
  requestScope,
  runtimeHarness,
  ScriptedStageExecutor,
  seedApplication,
  startBody,
} from './helpers.js';

const plan = [
  { id: 'scanner', version: 1, hitlKind: null, usesModel: true },
  { id: 'scanner_review', version: 1, hitlKind: 'scanner_review', usesModel: false },
  { id: 'report', version: 1, hitlKind: null, usesModel: false },
] as const satisfies readonly StageDefinition[];

function hitlScript(): ScriptedStageExecutor {
  return new ScriptedStageExecutor({
    scanner_review: (context) =>
      context.response === null
        ? {
            status: 'awaiting_input',
            reason: { phase: 'scanner_review', message: 'Review scanner output' },
            transcript: { messages: [{ role: 'assistant', text: 'Review scanner output' }] },
          }
        : { status: 'completed' },
  });
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

test('completed stages survive process replacement and are not executed again', async () => {
  const store = new InMemoryControlPlane();
  const clock = new ManualClock();
  const artifacts = new InMemoryArtifactStore(clock);
  const scripted = hitlScript();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(store, owner.userId);
  const firstExecutor = new DurableBoundaryExecutor({
    store,
    artifactStore: artifacts,
    stageExecutor: scripted,
    stagePlan: plan,
    clock,
    workerId: 'worker-one',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(owner, applicationId);
  const first = await firstExecutor.startRun(
    scope,
    {
      applicationId,
      sourceArtifactIds: ['source_01'] as never,
      threatArtifactId: null,
      projectPath: null,
      threatFilePath: null,
      settings: startBody()['settings'] as never,
      idempotencyKey: 'replacement-test',
    },
    actorId,
  );
  assert.equal(first.boundary, 'awaiting_input');
  assert.equal(scripted.calls.filter((call) => call.stage.id === 'scanner').length, 1);

  await store.respondToHitl(
    HitlResponseSchema.parse({
      schema_version: 1,
      ...scope,
      interaction_id: first.interaction?.interaction_id,
      run_id: first.run.run_id,
      revision: first.interaction?.revision,
      action: 'submit',
      text: 'confirmed',
      submitted_at: clock.now().toISOString(),
    }),
  );
  const replacementExecutor = new DurableBoundaryExecutor({
    store,
    artifactStore: artifacts,
    stageExecutor: scripted,
    stagePlan: plan,
    clock,
    workerId: 'worker-two',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const resumed = await replacementExecutor.runUntilBoundary(
    scope,
    first.run.run_id,
    actorId,
  );

  assert.equal(resumed.boundary, 'completed');
  assert.equal(scripted.calls.filter((call) => call.stage.id === 'scanner').length, 1);
  assert.equal(scripted.calls.filter((call) => call.stage.id === 'scanner_review').length, 2);
  assert.equal(
    scripted.calls.filter((call) => call.stage.id === 'scanner_review')[1]?.hitlHistory.length,
    1,
  );
  assert.equal(scripted.calls.filter((call) => call.stage.id === 'report').length, 1);
  assert.deepEqual(
    (await store.listCheckpoints(scope, first.run.run_id))
      .filter((checkpoint) => checkpoint.status === 'completed')
      .map((checkpoint) => checkpoint.stage_id),
    ['report', 'scanner', 'scanner_review'].sort(),
  );
});

test('a stale HITL revision is rejected after a new durable round is created', async () => {
  const scripted = new ScriptedStageExecutor({
    scanner_review: (context) => {
      if (context.response === null || context.response.text === 'another-round') {
        return {
          status: 'awaiting_input',
          reason: { round: context.response === null ? 1 : 2 },
          transcript: { response: context.response?.text ?? null },
        };
      }
      return { status: 'completed' };
    },
  });
  const harness = runtimeHarness({
    stageExecutor: scripted,
    stagePlan: [plan[1]],
  });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);
  const started = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/start-run',
    context: authenticatedContext(),
    body: startBody({ idempotency_key: 'revision-test' }),
  });
  const first = parseResponse<BoundaryResult>(started.body);
  assert.equal(first.interaction?.revision, 1);

  const next = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/respond-hitl',
    context: authenticatedContext(),
    body: {
      application_id: applicationId,
      run_id: first.run.run_id,
      interaction_id: first.interaction?.interaction_id,
      revision: 1,
      action: 'submit',
      text: 'another-round',
    },
  });
  assert.equal(next.statusCode, 202);
  assert.equal(parseResponse<BoundaryResult>(next.body).interaction?.revision, 2);

  const stale = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/respond-hitl',
    context: authenticatedContext(),
    body: {
      application_id: applicationId,
      run_id: first.run.run_id,
      interaction_id: first.interaction?.interaction_id,
      revision: 1,
      action: 'submit',
      text: 'another-round',
    },
  });
  assert.equal(stale.statusCode, 409);
  assert.equal(parseResponse<{ error: string }>(stale.body).error, 'stale_revision');
});

test('explicit HITL skip is durable and resumes the pipeline', async () => {
  const scripted = hitlScript();
  const harness = runtimeHarness({ stageExecutor: scripted, stagePlan: [plan[1], plan[2]] });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);
  const started = parseResponse<BoundaryResult>(
    (
      await harness.runtime.handle({
        method: 'POST',
        path: '/invocations/start-run',
        context: authenticatedContext(),
        body: startBody({ idempotency_key: 'skip-test' }),
      })
    ).body,
  );
  const resumed = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/respond-hitl',
    context: authenticatedContext(),
    body: {
      application_id: applicationId,
      run_id: started.run.run_id,
      interaction_id: started.interaction?.interaction_id,
      revision: 1,
      action: 'skip',
      text: null,
    },
  });
  assert.equal(resumed.statusCode, 200);
  assert.equal(parseResponse<BoundaryResult>(resumed.body).boundary, 'completed');
  const reviewCall = scripted.calls.find((call) => call.response?.action === 'skip');
  assert.equal(reviewCall?.response?.text, null);
  const stored = await harness.store.getHitlResponse(
    requestScope(owner.userId),
    started.interaction!.interaction_id,
    1,
  );
  assert.equal(stored?.action, 'skip');
});

test('transcript artifacts are persisted before the HITL request is visible', async () => {
  const baseStore = new InMemoryControlPlane();
  const clock = new ManualClock();
  const baseArtifacts = new InMemoryArtifactStore(clock);
  const order: string[] = [];
  const artifacts: ArtifactStore = {
    async putTranscript(input) {
      order.push('artifact');
      return baseArtifacts.putTranscript(input);
    },
  };
  const store = new Proxy(baseStore, {
    get(target, property) {
      if (property === 'putCheckpoint') {
        return async (...args: Parameters<ControlPlaneStore['putCheckpoint']>) => {
          if (args[0].status === 'awaiting_input') {
            order.push('checkpoint');
          }
          return target.putCheckpoint(...args);
        };
      }
      if (property === 'createHitlRequest') {
        return async (...args: Parameters<ControlPlaneStore['createHitlRequest']>) => {
          const request = args[0];
          order.push('hitl');
          assert.notEqual(request.transcript_artifact, null);
          assert.equal(baseArtifacts.has(request.transcript_artifact!.artifact_id), true);
          return target.createHitlRequest(...args);
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as unknown as ControlPlaneStore;
  const owner = await principal();
  await seedApplication(baseStore, owner.userId);
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: artifacts,
    stageExecutor: hitlScript(),
    stagePlan: [plan[1]],
    clock,
    workerId: 'artifact-order-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(owner, applicationId);
  await executor.startRun(
    requestScope(owner.userId),
    {
      applicationId,
      sourceArtifactIds: ['source_01'] as never,
      threatArtifactId: null,
      projectPath: null,
      threatFilePath: null,
      settings: startBody()['settings'] as never,
      idempotencyKey: 'artifact-order',
    },
    actorId,
  );
  assert.deepEqual(order, ['artifact', 'checkpoint', 'hitl']);
});

test('an active executor applies a durable pause after completing its current stage', async () => {
  const store = new InMemoryControlPlane();
  const clock = new ManualClock();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(store, owner.userId);
  const stageStarted = deferred<RunId>();
  const releaseStage = deferred<void>();
  const scripted = new ScriptedStageExecutor({
    scanner: async (context) => {
      stageStarted.resolve(context.run.run_id);
      await releaseStage.promise;
      return { status: 'completed' };
    },
  });
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor: scripted,
    stagePlan: [plan[0], plan[2]],
    clock,
    workerId: 'active-pause-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(
    owner,
    applicationId,
  );
  const execution = executor.startRun(
    scope,
    {
      applicationId,
      sourceArtifactIds: ['source_01'] as never,
      threatArtifactId: null,
      projectPath: null,
      threatFilePath: null,
      settings: startBody()['settings'] as never,
      idempotencyKey: 'active-pause',
    },
    actorId,
  );
  const runId = await stageStarted.promise;

  const control = await executor.requestControl(
    scope,
    runId,
    actorId,
    'pause',
  );
  assert.equal(control.boundary, 'busy');
  assert.equal((await store.getRunControl(scope, runId))?.action, 'pause');
  assert.equal((await store.getRun(scope, runId))?.status, 'running');

  releaseStage.resolve();
  const result = await execution;
  assert.equal(result.boundary, 'awaiting_input');
  assert.equal(result.run.status, 'awaiting_input');
  assert.deepEqual(
    scripted.calls.map((call) => call.stage.id),
    ['scanner'],
  );
  assert.deepEqual(
    (await store.listCheckpoints(scope, runId))
      .filter((checkpoint) => checkpoint.status === 'completed')
      .map((checkpoint) => checkpoint.stage_id),
    ['scanner'],
  );
  assert.deepEqual(
    (await store.listEvents(scope, runId)).map((event) => event.type).slice(-2),
    ['stage_completed', 'run_paused'],
  );

  clock.advance(6 * 60_000);
  const paused = (await store.getRun(scope, runId))!;
  const resumed = await store.resumeRun({
    ...scope,
    run_id: runId,
    expected_revision: paused.revision,
    expected_status: 'awaiting_input',
    resumed_at: clock.now().toISOString(),
  });
  const replacement = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor: scripted,
    stagePlan: [plan[0], plan[2]],
    clock,
    workerId: 'active-pause-replacement',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const completed = await replacement.runUntilBoundary(
    scope,
    runId,
    actorId,
    undefined,
    resumed.revision,
  );
  assert.equal(completed.boundary, 'completed');
  assert.deepEqual(
    scripted.calls.map((call) => call.stage.id),
    ['scanner', 'report'],
  );
  assert.deepEqual(
    (await store.listEvents(scope, runId)).map((event) => event.type).slice(-5),
    [
      'run_paused',
      'run_resumed',
      'stage_started',
      'stage_completed',
      'run_completed',
    ],
  );
  assert.equal(await store.getRunControl(scope, runId), null);
});

test('a durable stop supersedes pause while a stage lease is active', async () => {
  const store = new InMemoryControlPlane();
  const clock = new ManualClock();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(store, owner.userId);
  const stageStarted = deferred<RunId>();
  const releaseStage = deferred<void>();
  const scripted = new ScriptedStageExecutor({
    scanner: async (context) => {
      stageStarted.resolve(context.run.run_id);
      await releaseStage.promise;
      return { status: 'completed' };
    },
  });
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor: scripted,
    stagePlan: [plan[0], plan[2]],
    clock,
    workerId: 'active-stop-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(
    owner,
    applicationId,
  );
  const execution = executor.startRun(
    scope,
    {
      applicationId,
      sourceArtifactIds: ['source_01'] as never,
      threatArtifactId: null,
      projectPath: null,
      threatFilePath: null,
      settings: startBody()['settings'] as never,
      idempotencyKey: 'active-stop',
    },
    actorId,
  );
  const runId = await stageStarted.promise;

  assert.equal(
    (await executor.requestControl(scope, runId, actorId, 'pause')).boundary,
    'busy',
  );
  clock.advance(1);
  assert.equal(
    (await executor.requestControl(scope, runId, actorId, 'stop')).boundary,
    'busy',
  );
  assert.equal((await store.getRunControl(scope, runId))?.action, 'stop');

  releaseStage.resolve();
  const result = await execution;
  assert.equal(result.boundary, 'failed');
  assert.equal(result.run.status, 'cancelled');
  assert.equal(result.run.completed_at, clock.now().toISOString());
  assert.deepEqual(
    scripted.calls.map((call) => call.stage.id),
    ['scanner'],
  );
  assert.deepEqual(
    (await store.listEvents(scope, runId)).map((event) => event.type).slice(-2),
    ['stage_completed', 'run_stopped'],
  );
  assert.equal(
    (await store.listEvents(scope, runId)).some(
      (event) => event.type === 'run_paused',
    ),
    false,
  );
});

test('lease loss fences completion and leaves the stage resumable', async () => {
  const store = new InMemoryControlPlane();
  const clock = new ManualClock();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(store, owner.userId);
  let runId: RunId | null = null;
  const scripted = new ScriptedStageExecutor({
    scanner: async (context) => {
      runId = context.run.run_id;
      clock.advance(61_000);
      await store.acquireLease({
        ...scope,
        resource_id: runLeaseResourceId(context.run.run_id),
        lease_owner_id: 'replacement-worker',
        acquired_at: clock.now().toISOString(),
        expires_at: new Date(clock.now().getTime() + 60_000).toISOString(),
      });
      return { status: 'completed' };
    },
  });
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor: scripted,
    stagePlan: [plan[0]],
    clock,
    workerId: 'stale-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(owner, applicationId);
  await assert.rejects(
    executor.startRun(
      scope,
      {
        applicationId,
        sourceArtifactIds: ['source_01'] as never,
        threatArtifactId: null,
        projectPath: null,
        threatFilePath: null,
        settings: startBody()['settings'] as never,
        idempotencyKey: 'lease-loss',
      },
      actorId,
    ),
    (error: unknown) => error instanceof ControlPlaneError && error.code === 'lease_lost',
  );
  assert.notEqual(runId, null);
  const checkpoints = await store.listCheckpoints(scope, runId!);
  assert.equal(checkpoints.some((checkpoint) => checkpoint.status === 'completed'), false);
  assert.equal((await store.getRun(scope, runId!))?.status, 'running');
});

test('a Dynamo checkpoint failure recovers the durable workspace receipt without re-executing the stage', async () => {
  const baseStore = new InMemoryControlPlane();
  const clock = new ManualClock();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(baseStore, owner.userId);
  let rejectCompletedCheckpoint = true;
  const store = new Proxy(baseStore, {
    get(target, property) {
      if (property === 'putCheckpoint') {
        return async (...args: Parameters<ControlPlaneStore['putCheckpoint']>) => {
          if (args[0].status === 'completed' && rejectCompletedCheckpoint) {
            rejectCompletedCheckpoint = false;
            throw new Error('injected Dynamo checkpoint failure');
          }
          return target.putCheckpoint(...args);
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as unknown as ControlPlaneStore;
  const checkpointArtifact = ArtifactRefSchema.parse({
    artifact_id: 'checkpoint_durable_receipt',
    kind: 'checkpoint',
    version: 1,
    content_type: 'application/vnd.threatforest.workspace-checkpoint+json',
    size_bytes: 42,
    sha256: 'a'.repeat(64),
    created_at: clock.now().toISOString(),
  });
  let executions = 0;
  let recoveries = 0;
  let runId: RunId | null = null;
  const stageExecutor = {
    async execute(context: Parameters<ScriptedStageExecutor['execute']>[0]) {
      executions += 1;
      runId = context.run.run_id;
      return {
        status: 'completed' as const,
        outputArtifacts: [checkpointArtifact],
      };
    },
    async recover() {
      recoveries += 1;
      return {
        status: 'completed' as const,
        outputArtifacts: [checkpointArtifact],
      };
    },
  };
  const actorId = await deterministicActorDeriver.deriveActorId(
    owner,
    applicationId,
  );
  const first = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor,
    stagePlan: [plan[0]],
    clock,
    workerId: 'checkpoint-failure-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });

  await assert.rejects(
    first.startRun(
      scope,
      {
        applicationId,
        sourceArtifactIds: ['source_01'] as never,
        threatArtifactId: null,
        projectPath: null,
        threatFilePath: null,
        settings: startBody()['settings'] as never,
        idempotencyKey: 'checkpoint-failure',
      },
      actorId,
    ),
    /injected Dynamo checkpoint failure/,
  );
  assert.notEqual(runId, null);
  assert.deepEqual(
    (await baseStore.listCheckpoints(scope, runId!)).map(
      (checkpoint) => checkpoint.status,
    ),
    ['started'],
  );

  const replacement = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor,
    stagePlan: [plan[0]],
    clock,
    workerId: 'checkpoint-recovery-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const result = await replacement.runUntilBoundary(scope, runId!, actorId);
  assert.equal(result.boundary, 'completed');
  assert.equal(executions, 1);
  assert.equal(recoveries, 1);
  assert.equal(
    (await baseStore.listCheckpoints(scope, runId!))[0]?.status,
    'completed',
  );
});

test('graceful shutdown cancellation leaves the active checkpoint resumable', async () => {
  const store = new InMemoryControlPlane();
  const clock = new ManualClock();
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(store, owner.userId);
  const cancellation = new Error('runtime is shutting down');
  const controller = new AbortController();
  let runId: RunId | null = null;
  const executor = new DurableBoundaryExecutor({
    store,
    artifactStore: new InMemoryArtifactStore(clock),
    stageExecutor: new ScriptedStageExecutor({
      scanner: (context) => {
        runId = context.run.run_id;
        controller.abort(cancellation);
        throw cancellation;
      },
    }),
    stagePlan: [plan[0]],
    clock,
    workerId: 'shutdown-worker',
    leaseDurationMs: 60_000,
    leaseHeartbeatMs: 10_000,
  });
  const actorId = await deterministicActorDeriver.deriveActorId(owner, applicationId);
  await assert.rejects(
    executor.startRun(
      scope,
      {
        applicationId,
        sourceArtifactIds: ['source_01'] as never,
        threatArtifactId: null,
        projectPath: null,
        threatFilePath: null,
        settings: startBody()['settings'] as never,
        idempotencyKey: 'shutdown-cancel',
      },
      actorId,
      controller.signal,
    ),
    (error: unknown) => error === cancellation,
  );
  assert.notEqual(runId, null);
  const checkpoints = await store.listCheckpoints(scope, runId!);
  assert.equal(checkpoints.some((checkpoint) => checkpoint.status === 'failed'), false);
  assert.equal(checkpoints.some((checkpoint) => checkpoint.status === 'started'), true);
  assert.equal((await store.getRun(scope, runId!))?.status, 'running');
});

test('events are gap-free, ordered, and not duplicated by an idempotent replay', async () => {
  const harness = runtimeHarness({
    stagePlan: [
      plan[0],
      { id: 'threat', version: 1, hitlKind: null, usesModel: true },
      plan[2],
    ],
  });
  const owner = await principal();
  const scope = requestScope(owner.userId);
  await seedApplication(harness.store, owner.userId);
  const actorId = await deterministicActorDeriver.deriveActorId(owner, applicationId);
  const input = {
    applicationId,
    sourceArtifactIds: ['source_01'] as never,
    threatArtifactId: null,
    projectPath: null,
    threatFilePath: null,
    settings: startBody()['settings'] as never,
    idempotencyKey: 'event-order',
  };
  const first = await harness.executor.startRun(scope, input, actorId);
  const before = await harness.store.listEvents(scope, first.run.run_id);
  await harness.executor.startRun(scope, input, actorId);
  const after = await harness.store.listEvents(scope, first.run.run_id);

  assert.deepEqual(
    before.map((event) => event.sequence),
    before.map((_, index) => index),
  );
  assert.deepEqual(
    before.map((event) => event.type),
    [
      'stage_started',
      'stage_completed',
      'stage_started',
      'stage_completed',
      'stage_started',
      'stage_completed',
      'run_completed',
    ],
  );
  assert.deepEqual(after, before);
  assert.equal(new Set(before.map((event) => event.event_id)).size, before.length);
});
