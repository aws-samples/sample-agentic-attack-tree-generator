import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DEFAULT_TTP_FRAMEWORK_IDS,
  HitlRequestSchema,
  MatchStepsRequestSchema,
  type Application,
  type ApplicationId,
  type ArtifactId,
} from '@threatforest/types';
import { HostedMcpServices } from '../src/mcp.js';
import {
  BUSINESS_CONTEXT,
  OWNER_A,
  OWNER_B,
  apiEvent,
  createApplication,
  createRun,
  json,
  makeFixture,
} from './support.js';

test('source selection is application scoped and exposes only ready artifacts', async () => {
  const fixture = makeFixture();
  const app = await createApplication(fixture);
  fixture.artifacts.setReady(
    { owner_id: OWNER_A, application_id: app.id as ApplicationId },
    ['source_ready'] as ArtifactId[],
  );
  const path = `/api/applications/${app.id}/sources`;
  const response = await fixture.handler(apiEvent('GET', path));
  assert.equal(response.statusCode, 200);
  assert.deepEqual(json(response).sources, [{
    artifact_id: 'source_ready', filename: 'Uploaded source', created_at: '',
  }]);
  assert.equal((await fixture.handler(apiEvent('GET', path, { owner: OWNER_B }))).statusCode, 404);
});

test('deleting an application leaves its owned runs readable and stoppable', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const removed = await fixture.handler(apiEvent('DELETE', `/api/applications/by-id/${application.id}`, {
    idempotencyKey: 'delete-active-application',
  }));
  assert.equal(removed.statusCode, 200);
  assert.equal((await fixture.handler(apiEvent('GET', `/api/applications/by-id/${application.id}`))).statusCode, 404);

  const run = await fixture.handler(apiEvent('GET', `/api/runs/${runId}`));
  assert.equal(run.statusCode, 200);
  assert.equal(json(run).run_id, runId);
  assert.equal(json(run).status, 'pending');
  assert.equal(json(run).display_name, 'Payments 1 · 19 Aug 2026, 12:00:00 UTC');
  const stopped = await fixture.handler(apiEvent('POST', `/api/runs/${runId}/stop`, {
    idempotencyKey: 'stop-orphaned-run',
  }));
  assert.equal(stopped.statusCode, 200);
  assert.deepEqual(json(stopped), { status: 'stop_requested' });
  assert.equal((await fixture.controlPlane.getRunControl({
    owner_id: OWNER_A, application_id: application.id as ApplicationId,
  }, runId))?.action, 'stop');
  assert.equal(fixture.orchestrator.controls.at(-1)?.runId, runId);

  for (const method of ['GET', 'POST']) {
    const path = `/api/runs/${runId}${method === 'POST' ? '/stop' : ''}`;
    const response = await fixture.handler(apiEvent(method, path, {
      owner: OWNER_B, idempotencyKey: `other-owner-${method}`,
    }));
    assert.equal(response.statusCode, 404);
  }
});

test('run lookup does not treat application storage failures as deletion', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  fixture.metadata.get = async () => { throw new Error('Storage unavailable'); };
  const response = await fixture.handler(apiEvent('GET', `/api/runs/${runId}`));
  assert.equal(response.statusCode, 500);
});

test('HTTP boundary requires both origin verification and Cognito sub', async () => {
  const fixture = makeFixture();
  const body = {
    owner_id: OWNER_B,
    name: 'Spoofed owner',
    project_path: '/logical/source',
    business_context: BUSINESS_CONTEXT,
  };

  const missingOrigin = await fixture.handler(
    apiEvent('POST', '/api/applications', {
      origin: null,
      idempotencyKey: 'missing-origin',
      body,
    }),
  );
  assert.equal(missingOrigin.statusCode, 403);
  assert.equal(json(missingOrigin).code, 'forbidden');

  const missingAuth = await fixture.handler(
    apiEvent('POST', '/api/applications', {
      owner: null,
      idempotencyKey: 'missing-auth',
      body,
    }),
  );
  assert.equal(missingAuth.statusCode, 401);

  const created = await fixture.handler(
    apiEvent('POST', '/api/applications', {
      idempotencyKey: 'ignore-client-owner',
      body,
    }),
  );
  assert.equal(created.statusCode, 201);
  const listA = await fixture.handler(apiEvent('GET', '/api/applications'));
  const listB = await fixture.handler(
    apiEvent('GET', '/api/applications', { owner: OWNER_B }),
  );
  assert.equal((json(listA).applications as unknown[]).length, 1);
  assert.equal((json(listB).applications as unknown[]).length, 0);
});

test('REST API v1 authorizer claims work, while principalId fallback and limits do not bypass validation', async () => {
  const fixture = makeFixture();
  const restResponse = await fixture.handler({
    httpMethod: 'GET',
    path: '/api/applications',
    headers: {
      'x-threatforest-origin-verify':
        'origin-secret-at-least-32-characters',
    },
    requestContext: {
      requestId: 'rest-request',
      authorizer: { claims: { sub: OWNER_A } },
    },
  });
  assert.equal(restResponse.statusCode, 200);
  assert.deepEqual(json(restResponse), { applications: [] });

  const principalOnly = await fixture.handler({
    httpMethod: 'GET',
    path: '/api/applications',
    headers: {
      'x-threatforest-origin-verify':
        'origin-secret-at-least-32-characters',
    },
    requestContext: {
      requestId: 'principal-only',
      authorizer: { principalId: OWNER_A },
    },
  });
  assert.equal(principalOnly.statusCode, 401);

  const longRoute = await fixture.handler(
    apiEvent('GET', `/api/${'x'.repeat(5000)}`),
  );
  assert.equal(longRoute.statusCode, 414);

  const largeBody = apiEvent('POST', '/api/config/test', {
    body: { provider: 'AWS Bedrock', model_id: 'x'.repeat(1024 * 1024) },
  });
  const tooLarge = await fixture.handler(largeBody);
  assert.equal(tooLarge.statusCode, 413);
});

test('application and configuration responses preserve browser envelopes', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);

  assert.equal(application.name, 'Payments 1');
  assert.equal(application.slug, 'payments-1');
  assert.equal(application.project_path, '/logical/payments');
  assert.deepEqual(application.business_context, BUSINESS_CONTEXT);
  assert.equal(application.run_dir_name, application.id);

  const list = await fixture.handler(apiEvent('GET', '/api/applications'));
  assert.equal(list.statusCode, 200);
  const summary = (json(list).applications as Array<Record<string, unknown>>)[0]!;
  assert.equal(summary.id, application.id);
  assert.equal(summary.version_count, 0);
  assert.equal(summary.description, BUSINESS_CONTEXT.description);

  const config = await fixture.handler(apiEvent('GET', '/api/config'));
  assert.deepEqual(Object.keys(json(config)).sort(), [
    'api_key_configured',
    'aws_profile',
    'aws_region',
    'default_browse_path',
    'embeddings_model',
    'model_id',
    'model_provider',
  ]);
  const providers = await fixture.handler(apiEvent('GET', '/api/config/providers'));
  assert.ok((json(providers).providers as string[]).includes('AWS Bedrock'));
  const frameworks = await fixture.handler(apiEvent('GET', '/api/config/frameworks'));
  assert.deepEqual(
    Object.keys(json(frameworks).frameworks as object),
    DEFAULT_TTP_FRAMEWORK_IDS,
  );

  const saved = await fixture.handler(
    apiEvent('POST', '/api/config/save', {
      idempotencyKey: 'save-config',
      headers: { 'x-threatforest-application-id': application.id },
      body: {
        provider: 'AWS Bedrock',
        model_id: 'global.anthropic.claude-opus-4-8',
        aws_profile: 'must-not-be-used',
      },
    }),
  );
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(json(saved), {
    success: true,
    message: 'Configuration saved successfully.',
  });
  const appConfig = await fixture.handler(
    apiEvent('GET', '/api/config', {
      headers: { 'x-threatforest-application-id': application.id },
    }),
  );
  assert.equal(json(appConfig).model_id, 'global.anthropic.claude-opus-4-8');
  assert.equal(json(appConfig).aws_profile, null);
  assert.equal(json(appConfig).aws_region, 'eu-west-2');

  const external = await fixture.handler(
    apiEvent('POST', '/api/config/save', {
      idempotencyKey: 'save-external-config',
      headers: { 'x-threatforest-application-id': application.id },
      body: {
        provider: 'OpenAI',
        model_id: 'gpt-4o',
        aws_region: 'eu-west-1',
        api_key: 'write-only-provider-key',
      },
    }),
  );
  assert.equal(external.statusCode, 200);
  assert.deepEqual(fixture.providerCredentials.writes, [
    { ownerId: OWNER_A, provider: 'OpenAI' },
  ]);
  const externalConfig = await fixture.handler(
    apiEvent('GET', '/api/config', {
      headers: { 'x-threatforest-application-id': application.id },
    }),
  );
  assert.equal(json(externalConfig).model_provider, 'OpenAI');
  assert.equal(json(externalConfig).aws_region, 'eu-west-1');
  assert.equal(json(externalConfig).api_key_configured, true);
  assert.equal('api_key' in json(externalConfig), false);
});

test('cross-user and cross-application reads are denied without existence leakage', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);

  const crossUser = await fixture.handler(
    apiEvent('GET', `/api/applications/by-id/${application.id}`, {
      owner: OWNER_B,
    }),
  );
  assert.equal(crossUser.statusCode, 404);

  const crossUserConfig = await fixture.handler(
    apiEvent('GET', '/api/config', {
      owner: OWNER_B,
      headers: { 'x-threatforest-application-id': application.id },
    }),
  );
  assert.equal(crossUserConfig.statusCode, 404);

  const other = await createApplication(fixture, OWNER_A, 'create-other');
  const runId = await createRun(fixture, application);
  const run = await fixture.services.runs.getRecord(OWNER_A, runId);
  assert.notEqual(run.application_id, other.id);
  const inaccessible = await fixture.controlPlane.getRun(
    { owner_id: OWNER_A, application_id: other.id as ApplicationId },
    runId,
  );
  assert.equal(inaccessible, null);
});

test('run lifecycle responses retain the existing run envelopes', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);

  assert.equal(fixture.orchestrator.dispatches.length, 1);
  const runSettings = await fixture.controlPlane.getRunSettingsSnapshot(
    { owner_id: OWNER_A, application_id: application.id as ApplicationId },
    runId,
  );
  assert.deepEqual(runSettings?.frameworks, DEFAULT_TTP_FRAMEWORK_IDS);
  assert.equal(runSettings?.aws_region, 'eu-west-2');
  assert.deepEqual(runSettings?.business_context, BUSINESS_CONTEXT);
  assert.equal(runSettings?.business_context_updated_at, application.updated_at);
  assert.deepEqual(
    MatchStepsRequestSchema.parse({
      steps: ['Exfiltrate payment data.'],
      frameworks: runSettings?.frameworks,
    }).frameworks,
    DEFAULT_TTP_FRAMEWORK_IDS,
  );
  const get = await fixture.handler(apiEvent('GET', `/api/runs/${runId}`));
  assert.equal(get.statusCode, 200);
  const state = json(get);
  assert.equal(state.run_id, runId);
  assert.equal(state.status, 'pending');
  assert.equal((state.config as Record<string, unknown>).app_id, application.id);

  const list = await fixture.handler(
    apiEvent('GET', '/api/runs', { query: { status: 'pending,running' } }),
  );
  assert.equal((json(list).runs as unknown[]).length, 1);

  const pause = await fixture.handler(
    apiEvent('POST', `/api/runs/${runId}/pause`, {
      idempotencyKey: 'pause-run',
    }),
  );
  assert.deepEqual(json(pause), { status: 'pause_requested' });
  assert.equal(fixture.orchestrator.controls[0]?.runId, runId);
  assert.equal(
    (
      await fixture.controlPlane.getRunControl(
        { owner_id: OWNER_A, application_id: application.id as ApplicationId },
        runId,
      )
    )?.action,
    'pause',
  );

  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const lease = await fixture.controlPlane.acquireLease({
    ...scope,
    resource_id: `run:${runId}`,
    lease_owner_id: 'pause-test-worker',
    acquired_at: fixture.clock.now().toISOString(),
    expires_at: new Date(
      fixture.clock.now().getTime() + 10 * 60_000,
    ).toISOString(),
  });
  const beforePause = (await fixture.controlPlane.getRun(scope, runId))!;
  await fixture.controlPlane.updateRun(
    {
      ...beforePause,
      status: 'awaiting_input',
      revision: beforePause.revision + 1,
      updated_at: fixture.clock.now().toISOString(),
    },
    beforePause.revision,
    { ...lease, observed_at: fixture.clock.now().toISOString() },
  );
  const resume = await fixture.handler(
    apiEvent('POST', `/api/runs/${runId}/resume`, {
      idempotencyKey: 'resume-paused-run',
    }),
  );
  assert.equal(resume.statusCode, 202);
  assert.deepEqual(json(resume), { new_run_id: runId });
  assert.equal((await fixture.controlPlane.getRun(scope, runId))?.status, 'queued');
  assert.equal(await fixture.controlPlane.getRunControl(scope, runId), null);
});

test('each run snapshots business context and later application edits cannot change an existing run', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const firstId = await createRun(fixture, application);
  const scope = { owner_id: OWNER_A, application_id: application.id as ApplicationId };
  const first = await fixture.controlPlane.getRunSettingsSnapshot(scope, firstId);
  const changed = { ...BUSINESS_CONTEXT, description: 'Availability is essential to clinical care.', data_sensitivity: 'phi' };
  const update = await fixture.handler(apiEvent('PATCH', `/api/applications/by-id/${application.id}`, {
    idempotencyKey: 'update-context', body: { business_context: changed },
  }));
  assert.equal(update.statusCode, 200);
  const secondId = await createRun(fixture, application);
  const second = await fixture.controlPlane.getRunSettingsSnapshot(scope, secondId);
  assert.deepEqual((await fixture.controlPlane.getRunSettingsSnapshot(scope, firstId))?.business_context, BUSINESS_CONTEXT);
  assert.deepEqual(second?.business_context, changed);
  assert.notEqual(first?.config_hash, second?.config_hash);
});

test('run logs retain owner isolation and return the normalized observability envelope', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);

  const logs = await fixture.handler(
    apiEvent('GET', `/api/runs/${runId}/logs`),
  );
  assert.equal(logs.statusCode, 200);
  assert.deepEqual(json(logs), {
    run_id: runId,
    entries: [],
    next_token: null,
    source: 'agentcore_cloudwatch',
  });

  const otherUser = await fixture.handler(
    apiEvent('GET', `/api/runs/${runId}/logs`, { owner: OWNER_B }),
  );
  assert.equal(otherUser.statusCode, 404);
});

test('failed runs resume in place without losing durable progress', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const lease = await fixture.controlPlane.acquireLease({
    ...scope,
    resource_id: `run:${runId}`,
    lease_owner_id: 'test-worker',
    acquired_at: '2026-08-19T12:00:00.000Z',
    expires_at: '2026-08-19T12:10:00.000Z',
  });
  const current = (await fixture.controlPlane.getRun(scope, runId))!;
  await fixture.controlPlane.updateRun(
    {
      ...current,
      status: 'failed',
      revision: current.revision + 1,
      updated_at: '2026-08-19T12:01:00.000Z',
      error_code: 'FAILED',
      error_message: 'test failure',
    },
    current.revision,
    { ...lease, observed_at: '2026-08-19T12:01:00.000Z' },
  );
  const resumed = await fixture.handler(
    apiEvent('POST', `/api/runs/${runId}/resume`, {
      idempotencyKey: 'resume-in-place',
    }),
  );
  assert.equal(resumed.statusCode, 202);
  assert.deepEqual(json(resumed), { new_run_id: runId });
  assert.equal(fixture.ids.runCounter, 1);
  assert.equal(fixture.orchestrator.dispatches.at(-1)?.run.run_id, runId);
  assert.equal((await fixture.controlPlane.getRun(scope, runId))?.revision, 3);
});

test('failed atomic run creation leaves no ghost run-index entry', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const applicationId = application.id as ApplicationId;
  const artifact = 'artifact_source' as ArtifactId;
  fixture.artifacts.setReady(
    { owner_id: OWNER_A, application_id: applicationId },
    [artifact],
  );
  fixture.controlPlane.createRunDispatch = async () => {
    throw new Error('injected atomic create failure');
  };

  const response = await fixture.handler(
    apiEvent('POST', '/api/runs', {
      idempotencyKey: 'failed-atomic-run-create',
      body: {
        app_id: applicationId,
        project_path: application.project_path,
        threat_source: 'auto',
        threat_file_path: null,
        frameworks: [...DEFAULT_TTP_FRAMEWORK_IDS],
        resume_run_dir: null,
        skip_nodes: [],
        source_artifact_ids: [artifact],
      },
    }),
  );

  assert.equal(response.statusCode, 500);
  assert.deepEqual(await fixture.runIndex.list(OWNER_A), []);
  assert.equal(await fixture.runIndex.locate(OWNER_A, 'run_1' as never), null);
  assert.equal(
    await fixture.controlPlane.getRun(
      { owner_id: OWNER_A, application_id: applicationId },
      'run_1' as never,
    ),
    null,
  );
});

test('resume cannot bypass a pending HITL response', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  const lease = await fixture.controlPlane.acquireLease({
    ...scope,
    resource_id: `run:${runId}`,
    lease_owner_id: 'pending-hitl-worker',
    acquired_at: fixture.clock.now().toISOString(),
    expires_at: new Date(
      fixture.clock.now().getTime() + 10 * 60_000,
    ).toISOString(),
  });
  const current = (await fixture.controlPlane.getRun(scope, runId))!;
  await fixture.controlPlane.createHitlRequest(
    HitlRequestSchema.parse({
      schema_version: 1,
      ...scope,
      interaction_id: 'interaction_pending',
      run_id: runId,
      stage_id: 'threat_review',
      kind: 'threat_review',
      revision: 1,
      fencing_token: lease.fencing_token,
      trace_id: current.trace_id,
      status: 'pending',
      reason: { message: 'Review threats' },
      transcript_artifact: null,
      created_at: fixture.clock.now().toISOString(),
      expires_at: null,
    }),
    { ...lease, observed_at: fixture.clock.now().toISOString() },
  );
  await fixture.controlPlane.updateRun(
    {
      ...current,
      status: 'awaiting_input',
      current_stage_id: 'threat_review',
      revision: current.revision + 1,
      updated_at: fixture.clock.now().toISOString(),
    },
    current.revision,
    { ...lease, observed_at: fixture.clock.now().toISOString() },
  );

  const response = await fixture.handler(
    apiEvent('POST', `/api/runs/${runId}/resume`, {
      idempotencyKey: 'cannot-skip-pending-hitl',
    }),
  );
  assert.equal(response.statusCode, 409);
  assert.match(String(json(response).detail), /awaiting a human response/);
  assert.equal(
    (await fixture.controlPlane.getRun(scope, runId))?.status,
    'awaiting_input',
  );
});

test('mutations are idempotent and reject key reuse with different input', async () => {
  const fixture = makeFixture();
  const event = apiEvent('POST', '/api/applications', {
    idempotencyKey: 'stable-create-key',
    body: {
      name: 'Idempotent App',
      project_path: '/logical/idempotent',
      business_context: BUSINESS_CONTEXT,
    },
  });
  const first = await fixture.handler(event);
  const second = await fixture.handler({
    ...event,
    requestContext: {
      ...event.requestContext,
      requestId: 'a-different-request-id',
    },
  });
  assert.equal(first.statusCode, 201);
  assert.equal(second.statusCode, 201);
  assert.deepEqual(json(second), json(first));
  assert.equal(fixture.ids.applicationCounter, 1);

  const conflict = await fixture.handler(
    apiEvent('POST', '/api/applications', {
      idempotencyKey: 'stable-create-key',
      body: {
        name: 'Different App',
        project_path: '/logical/different',
        business_context: BUSINESS_CONTEXT,
      },
    }),
  );
  assert.equal(conflict.statusCode, 409);
  assert.equal(json(conflict).code, 'conflict');
});

test('version data, report metadata, and filesystem-only hosted behavior are explicit', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const scope = {
    owner_id: OWNER_A,
    application_id: application.id as ApplicationId,
  };
  fixture.versionsStore.seed(
    scope,
    {
      id: '20260819_120000',
      run_date: '2026-08-19T12:00:00.000Z',
      status: 'complete',
      threat_count: 2,
      high_severity_count: 1,
      categories: ['Spoofing'],
      display_name: '',
      run_id: 'run_report',
    },
    {
      threats: [{ id: 'threat-1' }],
      run_metadata: { model_id: 'claude', frameworks: ['STRIDE'] },
    },
    {
      contentType: 'application/zip',
      filename: 'payments.tfreport',
      redirectUrl: 'https://downloads.example/report',
      metadata: { artifact_id: 'artifact_report', size_bytes: 1234 },
    },
  );

  const versions = await fixture.handler(
    apiEvent('GET', `/api/applications/${application.id}/versions`),
  );
  assert.equal((json(versions).versions as unknown[]).length, 1);
  assert.equal(
    (json(versions).versions as { display_name: string }[])[0]!.display_name,
    `${application.name} · 19 Aug 2026, 12:00:00 UTC`,
  );
  const data = await fixture.handler(
    apiEvent(
      'GET',
      `/api/applications/${application.id}/versions/20260819_120000/data`,
    ),
  );
  assert.equal(
    ((json(data).run_metadata as Record<string, unknown>).model_id),
    'claude',
  );
  const metadata = await fixture.handler(
    apiEvent(
      'GET',
      `/api/applications/${application.id}/versions/20260819_120000/report/metadata`,
    ),
  );
  assert.equal(
    ((json(metadata).report as Record<string, unknown>).artifact_id),
    'artifact_report',
  );

  const browse = await fixture.handler(
    apiEvent('GET', '/api/filesystem/browse', { query: { path: '/' } }),
  );
  assert.equal(browse.statusCode, 410);
  assert.equal(json(browse).code, 'filesystem_endpoint_unavailable');
});

test('MCP functions delegate to the same application/run/HITL services', async () => {
  const fixture = makeFixture();
  const mcp = new HostedMcpServices({
    applications: fixture.services.applications,
    runs: fixture.services.runs,
    hitl: fixture.services.hitl,
  });
  const created = await mcp.createApplication(OWNER_A, 'mcp-create', {
    name: 'MCP App',
    project_path: '/logical/mcp',
    business_context: BUSINESS_CONTEXT,
  });
  const application = created.value as Application;
  const fromHttp = await fixture.handler(
    apiEvent('GET', `/api/applications/by-id/${application.id}`),
  );
  assert.equal(json(fromHttp).name, 'MCP App');
});
