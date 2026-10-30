import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  HitlResponseSchema,
  RunIdSchema,
  RunSettingsSnapshotSchema,
  UserIdSchema,
  type RunId,
  type UserId,
} from '@threatforest/types';
import {
  InMemoryControlPlane,
  runLeaseResourceId,
} from '@threatforest/control-plane';
import {
  AgentCoreRuntimeUserPrincipalResolver,
  CognitoJwtPrincipalResolver,
  KmsHmacActorIdDeriver,
  VerifiedCognitoPrincipalResolver,
} from '../src/identity.js';
import { AgentCoreApprovedFeedbackMemory } from '../src/memory.js';
import { createAgentCoreNodeServer, listen } from '../src/node-server.js';
import { loadProductionConfig } from '../src/production.js';
import { AgentCoreHttpRuntime } from '../src/runtime.js';
import type { BoundaryResult, RuntimeHttpRequest } from '../src/contracts.js';
import {
  applicationId,
  authenticatedContext,
  deterministicActorDeriver,
  issuer,
  parseResponse,
  principal,
  principalResolver,
  requestScope,
  runtimeHarness,
  ScriptedStageExecutor,
  seedApplication,
  startBody,
} from './helpers.js';

const oneStage = [
  { id: 'scanner', version: 1, hitlKind: null, usesModel: true },
] as const;

async function executeAndWait(runtime: AgentCoreHttpRuntime, request: RuntimeHttpRequest) {
  const response = await runtime.handle(request);
  if (parseResponse<Partial<BoundaryResult>>(response.body).boundary !== 'busy') return response;
  await runtime.drain();
  const body = request.body as Record<string, unknown>;
  const current = await runtime.handle({
    ...request, path: '/invocations/get-run',
    body: { application_id: body['application_id'], run_id: body['run_id'] },
  });
  const { run } = parseResponse<BoundaryResult>(current.body);
  return runtime.handle({ ...request, body: { ...body, dispatch_generation: run.revision } });
}

async function seedQueuedRun(
  store: InMemoryControlPlane,
  ownerId: UserId,
  value: string,
): Promise<RunId> {
  const runId = RunIdSchema.parse(value);
  const createdAt = '2026-08-19T12:00:00.000Z';
  await store.createRun({
    schema_version: 1,
    ...requestScope(ownerId),
    run_id: runId,
    status: 'queued',
    source_artifact_ids: [ArtifactIdSchema.parse('source_01')],
    threat_artifact_id: null,
    current_stage_id: null,
    trace_id: '0123456789abcdef0123456789abcdef',
    revision: 1,
    last_event_sequence: -1,
    created_at: createdAt,
    updated_at: createdAt,
    completed_at: null,
    error_code: null,
    error_message: null,
  });
  await store.putRunSettingsSnapshot(
    RunSettingsSnapshotSchema.parse({
      schema_version: 1,
      ...requestScope(ownerId),
      run_id: runId,
      provider: 'bedrock',
      model_id: 'eu.anthropic.claude-sonnet',
      aws_region: 'eu-west-2',
      model_parameters: { temperature: 0 },
      frameworks: ['STRIDE', 'MITRE ATT&CK', 'PASTA'],
      embeddings_model: 'amazon.titan-embed-text-v2:0',
      config_hash: 'a'.repeat(64),
      created_at: createdAt,
    }),
  );
  return runId;
}

test('background execution responds promptly, stays busy, and ignores duplicate polls', async () => {
  let release!: () => void;
  let markStarted!: () => void;
  const started = new Promise<void>(resolve => { markStarted = resolve; });
  const hold = new Promise<void>(resolve => { release = resolve; });
  const scripted = new ScriptedStageExecutor({
    scanner: async () => { markStarted(); await hold; return { status: 'completed' }; },
  });
  const harness = runtimeHarness({ stagePlan: oneStage, stageExecutor: scripted });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);
  const runId = await seedQueuedRun(harness.store, owner.userId, 'run_background');
  const request = {
    method: 'POST', path: '/invocations', context: authenticatedContext(),
    body: { operation: 'execute_run', application_id: applicationId, run_id: runId, dispatch_generation: 1 },
  };
  try {
    const response = await harness.runtime.handle(request);
    assert.equal(response.statusCode, 202);
    assert.equal(parseResponse<BoundaryResult>(response.body).boundary, 'busy');
    await started;
    assert.deepEqual(parseResponse((await harness.runtime.handle({ method: 'GET', path: '/ping' })).body), { status: 'HealthyBusy' });
    const run = (await harness.store.getRun(requestScope(owner.userId), runId))!;
    const duplicate = await harness.runtime.handle({ ...request, body: { ...request.body, dispatch_generation: run.revision } });
    assert.equal(parseResponse<BoundaryResult>(duplicate.body).boundary, 'busy');
    assert.equal(scripted.calls.length, 1);
  } finally {
    release();
    await harness.runtime.drain();
  }
  assert.deepEqual(parseResponse((await harness.runtime.handle({ method: 'GET', path: '/ping' })).body), { status: 'Healthy' });
  assert.equal((await harness.store.getRun(requestScope(owner.userId), runId))?.status, 'completed');
});

test('verified identity scopes runs and body identity fields are never trusted', async () => {
  const store = new InMemoryControlPlane();
  const harness = runtimeHarness({ store, stagePlan: oneStage });
  const ownerA = await principal('subject-a');
  const ownerB = await principal('subject-b');
  await seedApplication(store, ownerA.userId);
  await seedApplication(store, ownerB.userId);

  const started = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/start-run',
    context: authenticatedContext('subject-a'),
    body: startBody(),
  });
  assert.equal(started.statusCode, 200);
  const runId = parseResponse<BoundaryResult>(started.body).run.run_id;

  const crossUser = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/get-run',
    context: authenticatedContext('subject-b'),
    body: { application_id: applicationId, run_id: runId },
  });
  assert.equal(crossUser.statusCode, 404);

  const ownerInjection = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/get-run',
    context: authenticatedContext('subject-b'),
    body: {
      application_id: applicationId,
      run_id: runId,
      owner_id: ownerA.userId,
    },
  });
  assert.equal(ownerInjection.statusCode, 400);

  const actorInjection = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/start-run',
    context: authenticatedContext('subject-a'),
    body: startBody({ actor_id: 'attacker-selected' }),
  });
  assert.equal(actorInjection.statusCode, 400);
});

test('start-run is idempotent and rejects key reuse with different input', async () => {
  const scripted = new ScriptedStageExecutor();
  const harness = runtimeHarness({ stageExecutor: scripted, stagePlan: oneStage });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);
  const request = {
    method: 'POST',
    path: '/invocations/start-run',
    context: authenticatedContext(),
    body: startBody(),
  };

  const first = await harness.runtime.handle(request);
  const second = await harness.runtime.handle(request);
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(
    parseResponse<BoundaryResult>(first.body).run.run_id,
    parseResponse<BoundaryResult>(second.body).run.run_id,
  );
  assert.equal(scripted.calls.length, 1);

  const conflicting = await harness.runtime.handle({
    ...request,
    body: startBody({
      settings: {
        ...(startBody()['settings'] as Record<string, unknown>),
        model_id: 'different-model',
      },
    }),
  });
  assert.equal(conflicting.statusCode, 409);
});

test('KMS-HMAC actor IDs are stable, scoped, and do not contain Cognito subjects', async () => {
  const seen: Uint8Array[] = [];
  const deriver = new KmsHmacActorIdDeriver({
    keyId: 'alias/threatforest-actor-hmac',
    client: {
      async generateMac(input): Promise<Uint8Array> {
        seen.push(input.message);
        return new Uint8Array(
          await crypto.subtle.digest('SHA-256', input.message),
        );
      },
    },
  });
  const owner = await principal('sensitive-cognito-subject');
  const first = await deriver.deriveActorId(owner, applicationId);
  const second = await deriver.deriveActorId(owner, applicationId);
  const other = await deriver.deriveActorId(owner, ApplicationIdSchema.parse('app_other'));

  assert.equal(first, second);
  assert.notEqual(first, other);
  assert.equal(first.includes(owner.subject), false);
  assert.equal(seen.length, 3);
});

test('the Cognito resolver does not decode an unverified Authorization header', async () => {
  const resolver = new VerifiedCognitoPrincipalResolver({ expectedIssuer: issuer });
  await assert.rejects(
    resolver.resolve({
      method: 'POST',
      path: '/invocations/get-run',
      headers: { authorization: 'Bearer header.payload.signature' },
      body: {},
    }),
    { name: 'AuthenticationError' },
  );
});

test('the production Cognito resolver verifies the forwarded Bearer token', async () => {
  const resolver = await CognitoJwtPrincipalResolver.create({
    userPoolId: 'eu-west-2_test',
    clientId: 'client-id',
    verifier: {
      async verify(token): Promise<unknown> {
        assert.equal(token, 'verified-token');
        return { sub: 'subject-a', iss: issuer, token_use: 'access' };
      },
    },
  });
  const resolved = await resolver.resolve({
    method: 'POST',
    path: '/invocations/get-run',
    headers: { authorization: 'Bearer verified-token' },
    body: {},
  });
  assert.equal(resolved.subject, 'subject-a');
  assert.equal(resolved.issuer, issuer);
});

test('the AgentCore runtime-user resolver accepts only its allowlisted identity header', async () => {
  const resolver = new AgentCoreRuntimeUserPrincipalResolver();
  const runtimeUserId = UserIdSchema.parse('cog_runtime_user_01');
  const resolved = await resolver.resolve({
    method: 'POST',
    path: '/invocations',
    headers: {
      'X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserId': runtimeUserId,
      authorization: 'Bearer untrusted-and-ignored',
    },
    body: { owner_id: 'body-selected-owner' },
  });

  assert.equal(resolved.userId, runtimeUserId);
  assert.equal(resolved.subject, runtimeUserId);
  assert.equal(resolved.issuer, 'urn:threatforest:cognito-upstream');
  assert.equal(
    resolved.claims['identity_source'],
    'agentcore-runtime-custom-user-id',
  );
  await assert.rejects(
    resolver.resolve({
      method: 'POST',
      path: '/invocations',
      headers: {
        authorization: 'Bearer untrusted',
        'x-amzn-bedrock-agentcore-runtime-user-id': runtimeUserId,
      },
    }),
    { name: 'AuthenticationError' },
  );
  await assert.rejects(
    resolver.resolve({
      method: 'POST',
      path: '/invocations',
      headers: {
        'x-amzn-bedrock-agentcore-runtime-custom-userid': '../invalid-user',
      },
    }),
    { name: 'AuthenticationError' },
  );
});

test('runtime authentication diagnostics never log header values', async () => {
  const harness = runtimeHarness({ stagePlan: oneStage });
  const messages: unknown[][] = [];
  const runtime = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver: new AgentCoreRuntimeUserPrincipalResolver(),
    actorIdDeriver: deterministicActorDeriver,
    clock: harness.clock,
    logger: {
      error: (...args: unknown[]) => {
        messages.push(args);
      },
    },
  });
  const response = await runtime.handle({
    method: 'post',
    path: '/invocations',
    headers: {
      Authorization: 'Bearer secret-token',
      'X-Amzn-Bedrock-AgentCore-Runtime-User-Id': '../invalid-secret-user',
      'X-Amzn-Bedrock-AgentCore-Runtime-Custom-UserId':
        '../invalid-secret-principal',
      'X-Custom-Request': 'secret-custom-value',
    },
    body: { operation: 'execute_run' },
  });

  assert.equal(response.statusCode, 401);
  assert.equal(messages.length, 1);
  const serialized = String(messages[0]?.[0]);
  assert.deepEqual(JSON.parse(serialized), {
    level: 'warn',
    event: 'runtime_authentication_failed',
    method: 'POST',
    path: '/invocations',
    header_names: [
      'authorization',
      'x-amzn-bedrock-agentcore-runtime-custom-userid',
      'x-amzn-bedrock-agentcore-runtime-user-id',
      'x-custom-request',
    ],
    runtime_user_header_present: true,
    runtime_principal_header_present: true,
    authorization_header_present: true,
  });
  assert.equal(serialized.includes('secret-token'), false);
  assert.equal(serialized.includes('invalid-secret-user'), false);
  assert.equal(serialized.includes('invalid-secret-principal'), false);
  assert.equal(serialized.includes('secret-custom-value'), false);
});

test('execute_run uses AgentCore runtime-user identity and cannot cross owner scope', async () => {
  const scripted = new ScriptedStageExecutor();
  const harness = runtimeHarness({
    stageExecutor: scripted,
    stagePlan: oneStage,
  });
  const owner = UserIdSchema.parse('cog_runtime_owner_a');
  const otherOwner = UserIdSchema.parse('cog_runtime_owner_b');
  await seedApplication(harness.store, owner);
  const runId = await seedQueuedRun(harness.store, owner, 'run_agentcore_execute');
  const runtime = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver: new AgentCoreRuntimeUserPrincipalResolver(),
    actorIdDeriver: deterministicActorDeriver,
    clock: harness.clock,
    logger: { error: () => {} },
  });

  const executed = await executeAndWait(runtime, {
    method: 'POST',
    path: '/invocations',
    headers: {
      'x-amzn-bedrock-agentcore-runtime-custom-userid': owner,
    },
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: runId,
      dispatch_generation: 1,
    },
  });
  assert.equal(executed.statusCode, 200);
  const result = parseResponse<BoundaryResult>(executed.body);
  assert.equal(result.boundary, 'completed');
  assert.equal(result.run.owner_id, owner);
  assert.equal(result.run.status, 'completed');
  assert.equal(scripted.calls.length, 1);
  assert.equal(scripted.calls[0]?.scope.owner_id, owner);

  const crossOwner = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers: {
      'x-amzn-bedrock-agentcore-runtime-custom-userid': otherOwner,
    },
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: runId,
      dispatch_generation: 1,
    },
  });
  assert.equal(crossOwner.statusCode, 404);

  const injectedOwner = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers: {
      'x-amzn-bedrock-agentcore-runtime-custom-userid': otherOwner,
    },
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: runId,
      dispatch_generation: 1,
      owner_id: owner,
    },
  });
  assert.equal(injectedOwner.statusCode, 400);
});

test('execute_run rejects a stale dispatch after same-run resume without executing a stage', async () => {
  const scripted = new ScriptedStageExecutor();
  const harness = runtimeHarness({
    stageExecutor: scripted,
    stagePlan: oneStage,
  });
  const owner = UserIdSchema.parse('cog_runtime_stale_dispatch_owner');
  await seedApplication(harness.store, owner);
  const runId = await seedQueuedRun(
    harness.store,
    owner,
    'run_agentcore_stale_dispatch',
  );
  const scope = requestScope(owner);
  const initial = await harness.store.getRun(scope, runId);
  assert.ok(initial);
  const resourceId = runLeaseResourceId(runId);
  const lease = await harness.store.acquireLease({
    ...scope,
    resource_id: resourceId,
    lease_owner_id: 'stale-dispatch-test',
    acquired_at: harness.clock.now().toISOString(),
    expires_at: new Date(
      harness.clock.now().getTime() + 60_000,
    ).toISOString(),
  });
  const failed = await harness.store.updateRun(
    {
      ...initial,
      status: 'failed',
      revision: initial.revision + 1,
      completed_at: harness.clock.now().toISOString(),
      error_code: 'test_failure',
      error_message: 'test failure before resume',
    },
    initial.revision,
    {
      ...scope,
      resource_id: resourceId,
      lease_owner_id: lease.lease_owner_id,
      fencing_token: lease.fencing_token,
      observed_at: harness.clock.now().toISOString(),
    },
  );
  await harness.store.releaseLease({
    ...scope,
    resource_id: resourceId,
    lease_owner_id: lease.lease_owner_id,
    fencing_token: lease.fencing_token,
    released_at: harness.clock.now().toISOString(),
  });
  const resumed = await harness.store.resumeRun({
    ...scope,
    run_id: runId,
    expected_revision: failed.revision,
    expected_status: 'failed',
    resumed_at: harness.clock.now().toISOString(),
  });
  assert.equal(resumed.run_id, runId);
  assert.equal(resumed.revision, 3);
  const runtime = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver: new AgentCoreRuntimeUserPrincipalResolver(),
    actorIdDeriver: deterministicActorDeriver,
    clock: harness.clock,
    logger: { error: () => {} },
  });

  const response = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers: {
      'x-amzn-bedrock-agentcore-runtime-custom-userid': owner,
    },
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: runId,
      dispatch_generation: initial.revision,
    },
  });

  assert.equal(response.statusCode, 409);
  assert.equal(
    parseResponse<{ error: string }>(response.body).error,
    'stale_dispatch',
  );
  assert.equal(scripted.calls.length, 0);
  assert.equal((await harness.store.getRun(scope, runId))?.revision, 3);
  assert.equal((await harness.store.getRun(scope, runId))?.status, 'queued');
});

test('execute_run keeps durable HITL progress when the best-effort Memory write fails', async () => {
  const memoryCalls: Array<Record<string, unknown>> = [];
  const memoryErrors: unknown[][] = [];
  const memory = new AgentCoreApprovedFeedbackMemory({
    memoryId: 'ThreatForestMemory-1234567890',
    client: {
      async createEvent(input): Promise<void> {
        memoryCalls.push(input);
        throw new Error('transient memory failure');
      },
    },
  });
  const scripted = new ScriptedStageExecutor({
    review: (context) =>
      context.response === null
        ? {
            status: 'awaiting_input',
            reason: { question: 'approve?' },
            transcript: { question: 'approve?' },
          }
        : { status: 'completed' },
  });
  const harness = runtimeHarness({
    stageExecutor: scripted,
    stagePlan: [
      { id: 'review', version: 1, hitlKind: 'mapping_review', usesModel: false },
    ],
  });
  const owner = UserIdSchema.parse('cog_runtime_hitl_owner');
  await seedApplication(harness.store, owner);
  const runtime = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver: new AgentCoreRuntimeUserPrincipalResolver(),
    actorIdDeriver: deterministicActorDeriver,
    memory,
    clock: harness.clock,
    logger: {
      error(...values: unknown[]) {
        memoryErrors.push(values);
      },
    },
  });
  const headers = {
    'x-amzn-bedrock-agentcore-runtime-custom-userid': owner,
  };
  const startedResponse = await runtime.handle({
    method: 'POST',
    path: '/invocations/start-run',
    headers,
    body: startBody({ idempotency_key: 'hosted-hitl-memory' }),
  });
  const started = parseResponse<BoundaryResult>(startedResponse.body);
  assert.equal(started.boundary, 'awaiting_input');
  assert.ok(started.interaction);
  await harness.store.respondToHitl(
    HitlResponseSchema.parse({
      schema_version: 1,
      ...requestScope(owner),
      interaction_id: started.interaction.interaction_id,
      run_id: started.run.run_id,
      revision: started.interaction.revision,
      action: 'submit',
      text: 'Use the corrected hosted mapping',
      submitted_at: harness.clock.now().toISOString(),
    }),
  );
  const executeRequest = {
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: started.run.run_id,
      dispatch_generation: started.run.revision,
    },
  };

  const completed = await executeAndWait(runtime, executeRequest);
  const result = parseResponse<BoundaryResult>(completed.body);
  assert.equal(completed.statusCode, 200);
  assert.equal(result.boundary, 'completed');
  assert.equal(
    scripted.calls.filter((call) => call.response !== null).length,
    1,
  );
  assert.equal(memoryCalls.length, 1);
  assert.equal(memoryCalls[0]?.['actorId'], result.actor_id);
  assert.deepEqual(memoryCalls[0]?.['metadata'], {
    application_id: { stringValue: applicationId },
    run_id: { stringValue: started.run.run_id },
    stage_id: { stringValue: 'review' },
    interaction_kind: { stringValue: 'mapping_review' },
    action: { stringValue: 'submit' },
  });
  assert.equal(memoryErrors.length, 1);
  assert.deepEqual(JSON.parse(String(memoryErrors[0]?.[0])), {
    level: 'error',
    event: 'agentcore_memory_write_failed',
    operation: 'record_approved_feedback',
    application_id: applicationId,
    run_id: started.run.run_id,
    interaction_id: started.interaction.interaction_id,
    revision: started.interaction.revision,
  });
  assert.match(String(memoryErrors[0]?.[1]), /transient memory failure/);
});

test('control_run durably pauses and stops without duplicate control events', async () => {
  const scripted = new ScriptedStageExecutor();
  const harness = runtimeHarness({
    stageExecutor: scripted,
    stagePlan: oneStage,
  });
  const owner = UserIdSchema.parse('cog_runtime_control_owner');
  await seedApplication(harness.store, owner);
  const pausedRunId = await seedQueuedRun(
    harness.store,
    owner,
    'run_agentcore_pause',
  );
  const stoppedRunId = await seedQueuedRun(
    harness.store,
    owner,
    'run_agentcore_stop',
  );
  const runtime = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver: new AgentCoreRuntimeUserPrincipalResolver(),
    actorIdDeriver: deterministicActorDeriver,
    clock: harness.clock,
    logger: { error: () => {} },
  });
  const headers = {
    'x-amzn-bedrock-agentcore-runtime-custom-userid': owner,
  };
  const pauseRequest = {
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'control_run',
      application_id: applicationId,
      run_id: pausedRunId,
      action: 'pause',
    },
  };

  const paused = await runtime.handle(pauseRequest);
  assert.equal(paused.statusCode, 202);
  assert.equal(
    parseResponse<BoundaryResult>(paused.body).run.status,
    'awaiting_input',
  );
  assert.equal(scripted.calls.length, 0);

  const duplicatePause = await runtime.handle(pauseRequest);
  assert.equal(duplicatePause.statusCode, 202);
  assert.equal(
    (await harness.store.getRunControl(requestScope(owner), pausedRunId))
      ?.action,
    'pause',
  );
  const pauseEvents = await harness.store.listEvents(
    requestScope(owner),
    pausedRunId,
  );
  assert.deepEqual(
    pauseEvents.filter((event) => event.type === 'run_paused').map((event) => event.sequence),
    [0],
  );

  const resumed = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: pausedRunId,
      dispatch_generation: parseResponse<BoundaryResult>(paused.body).run.revision,
    },
  });
  assert.equal(
    parseResponse<BoundaryResult>(resumed.body).boundary,
    'awaiting_input',
  );
  assert.equal(scripted.calls.length, 0);

  const stopped = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'control_run',
      application_id: applicationId,
      run_id: stoppedRunId,
      action: 'stop',
    },
  });
  const stoppedResult = parseResponse<BoundaryResult>(stopped.body);
  assert.equal(stopped.statusCode, 200);
  assert.equal(stoppedResult.boundary, 'failed');
  assert.equal(stoppedResult.run.status, 'cancelled');
  assert.equal(stoppedResult.run.completed_at, harness.clock.now().toISOString());

  const executeStopped = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'execute_run',
      application_id: applicationId,
      run_id: stoppedRunId,
      dispatch_generation: stoppedResult.run.revision,
    },
  });
  assert.equal(
    parseResponse<BoundaryResult>(executeStopped.body).run.status,
    'cancelled',
  );
  assert.equal(scripted.calls.length, 0);

  const invalidAction = await runtime.handle({
    method: 'POST',
    path: '/invocations',
    headers,
    body: {
      operation: 'control_run',
      application_id: applicationId,
      run_id: stoppedRunId,
      action: 'resume',
    },
  });
  assert.equal(invalidAction.statusCode, 400);
});

test('approved feedback is written to application-scoped AgentCore Memory', async () => {
  const calls: Array<Record<string, unknown>> = [];
  const memory = new AgentCoreApprovedFeedbackMemory({
    memoryId: 'ThreatForestMemory-1234567890',
    client: {
      async createEvent(input): Promise<void> {
        calls.push(input);
      },
    },
  });
  const owner = await principal();
  const harness = runtimeHarness({
    stageExecutor: new ScriptedStageExecutor({
      review: (context) =>
        context.response === null
          ? {
              status: 'awaiting_input',
              reason: { question: 'approve?' },
              transcript: { question: 'approve?' },
            }
          : { status: 'completed' },
    }),
    stagePlan: [
      { id: 'review', version: 1, hitlKind: 'mapping_review', usesModel: false },
    ],
  });
  await seedApplication(harness.store, owner.userId);
  const runtimeWithMemory = new AgentCoreHttpRuntime({
    store: harness.store,
    executor: harness.executor,
    principalResolver,
    actorIdDeriver: {
      deriveActorId: () => Promise.resolve('tf_actor_application_scope'),
    },
    memory,
    clock: harness.clock,
    logger: { error: () => {} },
  });
  const started = parseResponse<BoundaryResult>(
    (
      await runtimeWithMemory.handle({
        method: 'POST',
        path: '/invocations/start-run',
        context: authenticatedContext(),
        body: startBody({ idempotency_key: 'memory-test' }),
      })
    ).body,
  );
  await runtimeWithMemory.handle({
    method: 'POST',
    path: '/invocations/respond-hitl',
    context: authenticatedContext(),
    body: {
      application_id: applicationId,
      run_id: started.run.run_id,
      interaction_id: started.interaction?.interaction_id,
      revision: 1,
      action: 'submit',
      text: 'Use the corrected mapping',
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.['actorId'], 'tf_actor_application_scope');
  assert.equal(calls[0]?.['sessionId'], started.run.run_id);
  assert.equal(typeof calls[0]?.['clientToken'], 'string');
});

test('the production config requires every encrypted state dependency', () => {
  const config = loadProductionConfig({
    AWS_REGION: 'eu-west-2',
    THREATFOREST_STATE_TABLE: 'state-table',
    THREATFOREST_ARTIFACT_BUCKET: 'artifact-bucket',
    THREATFOREST_ARTIFACT_KMS_KEY_ARN: 'arn:aws:kms:eu-west-2:123:key/artifacts',
    THREATFOREST_ACTOR_HMAC_KEY_ARN: 'arn:aws:kms:eu-west-2:123:key/hmac',
    THREATFOREST_MEMORY_ID: 'ThreatForestMemory-1234567890',
    THREATFOREST_MODEL_SECRET_PREFIX: 'threatforest/test/users',
    THREATFOREST_COGNITO_USER_POOL_ID: 'eu-west-2_pool',
    THREATFOREST_COGNITO_CLIENT_ID: 'client-a,client-b',
  });
  assert.equal(config.port, 8080);
  assert.equal(config.principalMode, 'runtime_user_id');
  assert.deepEqual(config.cognitoClientIds, ['client-a', 'client-b']);
  const runtimeUserConfig = loadProductionConfig({
    AWS_REGION: 'eu-west-2',
    THREATFOREST_STATE_TABLE: 'state-table',
    THREATFOREST_ARTIFACT_BUCKET: 'artifact-bucket',
    THREATFOREST_ARTIFACT_KMS_KEY_ARN:
      'arn:aws:kms:eu-west-2:123:key/artifacts',
    THREATFOREST_ACTOR_HMAC_KEY_ARN:
      'arn:aws:kms:eu-west-2:123:key/hmac',
    THREATFOREST_MEMORY_ID: 'ThreatForestMemory-1234567890',
    THREATFOREST_MODEL_SECRET_PREFIX: 'threatforest/test/users',
  });
  assert.equal(runtimeUserConfig.cognitoUserPoolId, null);
  assert.deepEqual(runtimeUserConfig.cognitoClientIds, []);
  assert.equal(
    runtimeUserConfig.workspaceRoot,
    '/tmp/threatforest-ingestion',
  );
  assert.throws(
    () =>
      loadProductionConfig({
        THREATFOREST_PRINCIPAL_MODE: 'cognito_jwt',
        THREATFOREST_STATE_TABLE: 'state-table',
        THREATFOREST_ARTIFACT_BUCKET: 'artifact-bucket',
        THREATFOREST_ARTIFACT_KMS_KEY_ARN:
          'arn:aws:kms:eu-west-2:123:key/artifacts',
        THREATFOREST_ACTOR_HMAC_KEY_ARN:
          'arn:aws:kms:eu-west-2:123:key/hmac',
        THREATFOREST_MEMORY_ID: 'ThreatForestMemory-1234567890',
        THREATFOREST_MODEL_SECRET_PREFIX: 'threatforest/test/users',
      }),
    /Cognito principal mode requires/,
  );
  assert.throws(
    () =>
      loadProductionConfig({
        THREATFOREST_STATE_TABLE: 'state-table',
      }),
    /missing required environment variable/,
  );
});

test('/ping is available without authentication and the Node server composes', async () => {
  const harness = runtimeHarness({ stagePlan: oneStage });
  const server = createAgentCoreNodeServer({ runtime: harness.runtime });
  assert.equal(server.listenerCount('request'), 1);
  const response = await harness.runtime.handle({
    method: 'GET',
    path: '/ping',
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(parseResponse(response.body), { status: 'Healthy' });
});

test('/invocations streams JSON-safe heartbeats before long-running work completes', async () => {
  let markStarted!: () => void;
  let finishWork!: () => void;
  let workCompleted = false;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const work = new Promise<void>((resolve) => {
    finishWork = resolve;
  });
  const runtime = {
    async handle() {
      markStarted();
      await work;
      workCompleted = true;
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        },
        body: JSON.stringify({ boundary: 'completed' }),
      };
    },
  } as unknown as AgentCoreHttpRuntime;
  const server = createAgentCoreNodeServer({
    runtime,
    invocationHeartbeatMs: 25,
  });
  const address = await listen(server, 0, '127.0.0.1');

  try {
    const pendingResponse = fetch(
      `http://127.0.0.1:${address.port}/invocations`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      },
    );
    await started;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const response = await Promise.race([
      pendingResponse,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error('invocation headers were not flushed')),
          500,
        );
      }),
    ]);
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
    assert.equal(response.status, 200);
    assert.ok(response.body);
    const reader = response.body.getReader();
    const first = await reader.read();
    assert.equal(first.done, false);
    assert.match(new TextDecoder().decode(first.value), /^\n+$/);
    assert.equal(workCompleted, false);
    const busy = await fetch(`http://127.0.0.1:${address.port}/ping`);
    assert.deepEqual(await busy.json(), { status: 'HealthyBusy' });

    const second = await reader.read();
    assert.equal(second.done, false);
    assert.match(new TextDecoder().decode(second.value), /^\n+$/);
    assert.equal(workCompleted, false);

    finishWork();
    const chunks: Uint8Array[] = [];
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      chunks.push(chunk.value);
    }
    const body = Buffer.concat(chunks).toString('utf8');
    assert.deepEqual(JSON.parse(body), { boundary: 'completed' });
    const healthy = await fetch(`http://127.0.0.1:${address.port}/ping`);
    assert.deepEqual(await healthy.json(), { status: 'Healthy' });
  } finally {
    finishWork();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }
});

test('list-events paginates strictly after the requested sequence', async () => {
  const harness = runtimeHarness({
    stagePlan: [
      ...oneStage,
      { id: 'report', version: 1, hitlKind: null, usesModel: false },
    ],
  });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);
  const started = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/start-run',
    context: authenticatedContext(),
    body: startBody(),
  });
  const runId = parseResponse<BoundaryResult>(started.body).run.run_id as RunId;
  const listed = await harness.runtime.handle({
    method: 'POST',
    path: '/invocations/list-events',
    context: authenticatedContext(),
    body: { application_id: applicationId, run_id: runId, after_sequence: 1 },
  });
  const events = parseResponse<{ events: Array<{ sequence: number }> }>(listed.body).events;
  assert.ok(events.length > 0);
  assert.ok(events.every((event) => event.sequence > 1));
});
