import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runLeaseResourceId } from '@threatforest/control-plane';
import type {
  Application,
  ApplicationId,
  ArtifactId,
  HitlRequest,
  InteractionId,
  RunId,
} from '@threatforest/types';
import { z } from 'zod';
import {
  readHostedMcpLambdaEnvironment,
  type HostedMcpLambdaEnvironment,
} from '../src/composition.js';
import {
  createAgentCoreMcpHandler,
  type AgentCoreLambdaContext,
  type AgentCoreMcpResponse,
  type McpStructuredLogger,
} from '../src/lambda/mcp-tools.js';
import {
  AGENTCORE_MCP_TOOL_PREFIX,
  MCP_TOOL_NAMES,
} from '../src/mcp-contracts.js';
import { HostedMcpServices } from '../src/mcp.js';
import {
  BUSINESS_CONTEXT,
  OWNER_A,
  OWNER_B,
  makeFixture,
} from './support.js';

const GATEWAY_ID = 'gateway-0123456789';
const TARGET_ID = 'target-0123456789';

class RecordingLogger implements McpStructuredLogger {
  readonly infoMessages: string[] = [];
  readonly warnMessages: string[] = [];
  readonly errorMessages: string[] = [];

  info(message: string): void {
    this.infoMessages.push(message);
  }

  warn(message: string): void {
    this.warnMessages.push(message);
  }

  error(message: string): void {
    this.errorMessages.push(message);
  }
}

function context(
  toolName: string,
  overrides: Record<string, unknown> = {},
): AgentCoreLambdaContext {
  return {
    awsRequestId: 'lambda-request-1',
    clientContext: {
      custom: {
        bedrockAgentCoreMessageVersion: '1.0',
        bedrockAgentCoreAwsRequestId: 'agentcore-request-1',
        bedrockAgentCoreMcpMessageId: 'mcp-message-1',
        bedrockAgentCoreGatewayId: GATEWAY_ID,
        bedrockAgentCoreTargetId: TARGET_ID,
        bedrockAgentCoreToolName: `${AGENTCORE_MCP_TOOL_PREFIX}${toolName}`,
        ...overrides,
      },
    },
  };
}

function handlerFor(
  fixture: ReturnType<typeof makeFixture>,
  options: {
    environment?: HostedMcpLambdaEnvironment;
    logger?: McpStructuredLogger;
  } = {},
) {
  return createAgentCoreMcpHandler({
    services: new HostedMcpServices({
      applications: fixture.services.applications,
      runs: fixture.services.runs,
      hitl: fixture.services.hitl,
    }),
    environment: options.environment ?? {
      gatewayId: GATEWAY_ID,
      targetId: TARGET_ID,
    },
    logger: options.logger ?? new RecordingLogger(),
  });
}

async function invoke(
  handler: ReturnType<typeof handlerFor>,
  toolName: string,
  event: unknown,
  invocationContext = context(toolName),
): Promise<AgentCoreMcpResponse> {
  return handler(event, invocationContext);
}

function result(response: AgentCoreMcpResponse): unknown {
  if (!response.ok) {
    assert.fail(JSON.stringify(response.error));
  }
  return response.result;
}

test('AgentCore handler dispatches every application, run, and HITL tool', async () => {
  const fixture = makeFixture();
  const logger = new RecordingLogger();
  const handler = handlerFor(fixture, { logger });
  const called = new Set<string>();
  const call = async (toolName: string, event: unknown) => {
    const response = await invoke(handler, toolName, event);
    if (response.ok) called.add(response.tool);
    return result(response);
  };

  assert.deepEqual(
    await call('list_applications', { owner_id: OWNER_A }),
    { applications: [] },
  );

  const createInput = {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-create-app',
    name: 'AgentCore App',
    project_path: '/logical/agentcore',
    business_context: BUSINESS_CONTEXT,
  };
  const created = (await call(
    'create_application',
    createInput,
  )) as {
    status: number;
    value: Application;
  };
  assert.equal(created.status, 201);
  assert.equal(created.value.name, 'AgentCore App');
  const application = created.value;

  const replayed = await call('create_application', createInput);
  assert.deepEqual(replayed, created);
  assert.equal(fixture.ids.applicationCounter, 1);

  const fetched = await call('get_application', {
    owner_id: OWNER_A,
    application_id: application.id,
  });
  assert.equal((fetched as Application).id, application.id);

  const updated = (await call('update_application', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-update-app',
    application_id: application.id,
    name: 'AgentCore App Updated',
  })) as { value: Application };
  assert.equal(updated.value.name, 'AgentCore App Updated');

  const listedApplications = await call('list_applications', {
    owner_id: OWNER_A,
  });
  assert.equal(
    (listedApplications as { applications: unknown[] }).applications.length,
    1,
  );

  const artifactId = 'artifact_source' as ArtifactId;
  const applicationId = application.id as ApplicationId;
  fixture.artifacts.setReady(
    { owner_id: OWNER_A, application_id: applicationId },
    [artifactId],
  );
  const started = (await call('start_run', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-start-run',
    app_id: application.id,
    source_artifact_ids: [artifactId],
  })) as { status: number; value: { run_id: RunId } };
  assert.equal(started.status, 202);
  const runId = started.value.run_id;

  const fetchedRun = await call('get_run', {
    owner_id: OWNER_A,
    run_id: runId,
  });
  assert.equal(
    (
      fetchedRun as {
        state: { run_id: RunId };
      }
    ).state.run_id,
    runId,
  );

  const listedRuns = await call('list_runs', {
    owner_id: OWNER_A,
    statuses: ['pending'],
  });
  assert.equal((listedRuns as { runs: unknown[] }).runs.length, 1);

  const paused = await call('pause_run', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-pause-run',
    run_id: runId,
  });
  assert.deepEqual((paused as { value: unknown }).value, {
    status: 'pause_requested',
  });

  const stopped = await call('stop_run', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-stop-run',
    run_id: runId,
  });
  assert.deepEqual((stopped as { value: unknown }).value, {
    status: 'stop_requested',
  });

  const scope = { owner_id: OWNER_A, application_id: applicationId };
  const lease = await fixture.controlPlane.acquireLease({
    ...scope,
    resource_id: runLeaseResourceId(runId),
    lease_owner_id: 'mcp-test-worker',
    acquired_at: fixture.clock.now().toISOString(),
    expires_at: new Date(
      fixture.clock.now().getTime() + 10 * 60 * 1000,
    ).toISOString(),
  });
  const beforeFailure = (await fixture.controlPlane.getRun(scope, runId))!;
  await fixture.controlPlane.updateRun(
    {
      ...beforeFailure,
      status: 'failed',
      revision: beforeFailure.revision + 1,
      updated_at: fixture.clock.now().toISOString(),
      error_code: 'TEST_FAILURE',
      error_message: 'Retry this run.',
    },
    beforeFailure.revision,
    { ...lease, observed_at: fixture.clock.now().toISOString() },
  );

  const resumed = await call('resume_run', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-resume-run',
    run_id: runId,
  });
  assert.deepEqual((resumed as { value: unknown }).value, {
    new_run_id: runId,
  });

  const resumedRun = (await fixture.controlPlane.getRun(scope, runId))!;
  const interaction = (
    interactionId: InteractionId,
  ): HitlRequest => ({
    schema_version: 1,
    ...scope,
    interaction_id: interactionId,
    run_id: runId,
    stage_id: 'threat_review',
    kind: 'threat_review',
    revision: 1,
    fencing_token: lease.fencing_token,
    trace_id: resumedRun.trace_id,
    status: 'pending',
    reason: { threats: [] },
    transcript_artifact: null,
    created_at: fixture.clock.now().toISOString(),
    expires_at: null,
  });
  const guard = {
    ...lease,
    observed_at: fixture.clock.now().toISOString(),
  };
  const respondInteractionId = 'interaction_respond' as InteractionId;
  const skipInteractionId = 'interaction_skip' as InteractionId;
  await fixture.controlPlane.createHitlRequest(
    interaction(respondInteractionId),
    guard,
  );
  await fixture.controlPlane.createHitlRequest(
    interaction(skipInteractionId),
    guard,
  );

  const pending = await call('list_pending_interactions', {
    owner_id: OWNER_A,
    run_id: runId,
  });
  assert.equal((pending as unknown[]).length, 2);

  const responded = await call('respond_to_interaction', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-respond-hitl',
    run_id: runId,
    interaction_id: respondInteractionId,
    revision: 1,
    text: 'Approve the reviewed threat set.',
  });
  assert.deepEqual((responded as { value: unknown }).value, { ok: true });

  const skipped = await call('skip_interaction', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-skip-hitl',
    run_id: runId,
    interaction_id: skipInteractionId,
    revision: 1,
  });
  assert.deepEqual((skipped as { value: unknown }).value, { ok: true });

  const deleted = await call('delete_application', {
    owner_id: OWNER_A,
    idempotency_key: 'mcp-delete-app',
    application_id: application.id,
  });
  assert.equal(
    ((deleted as { value: { success: boolean } }).value).success,
    true,
  );

  assert.deepEqual(
    [...called].sort(),
    [...MCP_TOOL_NAMES].sort(),
  );
  assert.ok(logger.infoMessages.length >= MCP_TOOL_NAMES.length * 2);
  assert.deepEqual(
    JSON.parse(logger.infoMessages[0]!) as Record<string, unknown>,
    {
      level: 'info',
      event: 'mcp_tool_started',
      service: 'threatforest-agentcore-mcp',
      tool: 'list_applications',
      agentCoreRequestId: 'agentcore-request-1',
      mcpMessageId: 'mcp-message-1',
      lambdaRequestId: 'lambda-request-1',
    },
  );
});

test('AgentCore handler enforces owner isolation through hosted services', async () => {
  const fixture = makeFixture();
  const handler = handlerFor(fixture);
  const created = result(
    await invoke(handler, 'create_application', {
      owner_id: OWNER_A,
      idempotency_key: 'owner-a-create',
      name: 'Owner A App',
      project_path: '/owner-a',
      business_context: BUSINESS_CONTEXT,
    }),
  ) as { value: Application };

  const denied = await invoke(handler, 'get_application', {
    owner_id: OWNER_B,
    application_id: created.value.id,
  });
  assert.deepEqual(denied, {
    ok: false,
    error: {
      status: 404,
      code: 'not_found',
      message: `Unknown application: ${created.value.id}`,
    },
  });
  assert.deepEqual(
    result(
      await invoke(handler, 'list_applications', {
        owner_id: OWNER_B,
      }),
    ),
    { applications: [] },
  );
});

test('AgentCore metadata validates gateway, optional target, and exact tool prefix', async () => {
  const fixture = makeFixture();
  const configured = handlerFor(fixture);

  const wrongGateway = await invoke(
    configured,
    'list_applications',
    { owner_id: OWNER_A },
    context('list_applications', {
      bedrockAgentCoreGatewayId: 'another-gateway',
    }),
  );
  assert.equal(wrongGateway.ok, false);
  if (!wrongGateway.ok) assert.equal(wrongGateway.error.status, 400);

  const wrongTarget = await invoke(
    configured,
    'list_applications',
    { owner_id: OWNER_A },
    context('list_applications', {
      bedrockAgentCoreTargetId: 'another-target',
    }),
  );
  assert.equal(wrongTarget.ok, false);
  if (!wrongTarget.ok) {
    assert.match(wrongTarget.error.message, /target ID/);
  }

  const production = handlerFor(fixture, {
    environment: { gatewayId: GATEWAY_ID },
  });
  assert.equal(
    (
      await invoke(
        production,
        'list_applications',
        { owner_id: OWNER_A },
        context('list_applications', {
          bedrockAgentCoreTargetId: 'deployed-target-id',
        }),
      )
    ).ok,
    true,
  );

  const missingTarget = await invoke(
    production,
    'list_applications',
    { owner_id: OWNER_A },
    context('list_applications', {
      bedrockAgentCoreTargetId: undefined,
    }),
  );
  assert.equal(missingTarget.ok, false);
  if (!missingTarget.ok) {
    assert.match(missingTarget.error.message, /TargetId is required/);
  }

  const wrongPrefix = await configured(
    { owner_id: OWNER_A },
    context('list_applications', {
      bedrockAgentCoreToolName: 'OtherTarget___list_applications',
    }),
  );
  assert.deepEqual(wrongPrefix, {
    ok: false,
    error: {
      status: 400,
      code: 'invalid_tool_name',
      message: `AgentCore tool name must start with ${AGENTCORE_MCP_TOOL_PREFIX}.`,
    },
  });

  const unknown = await invoke(
    configured,
    'not_a_tool',
    { owner_id: OWNER_A },
  );
  assert.deepEqual(unknown, {
    ok: false,
    error: {
      status: 400,
      code: 'unknown_tool',
      message: 'Unknown AgentCore tool: not_a_tool',
    },
  });
});

test('AgentCore handler rejects malformed context and strict schema violations', async () => {
  const fixture = makeFixture();
  const handler = handlerFor(fixture);

  const missingContext = await handler(
    { owner_id: OWNER_A },
    { awsRequestId: 'lambda-request' },
  );
  assert.equal(missingContext.ok, false);
  if (!missingContext.ok) {
    assert.match(missingContext.error.message, /clientContext\.custom/);
  }

  const unsupportedVersion = await invoke(
    handler,
    'list_applications',
    { owner_id: OWNER_A },
    context('list_applications', {
      bedrockAgentCoreMessageVersion: '2.0',
    }),
  );
  assert.equal(unsupportedVersion.ok, false);
  if (!unsupportedVersion.ok) {
    assert.match(unsupportedVersion.error.message, /message version/);
  }

  const unknownField = await invoke(handler, 'list_applications', {
    owner_id: OWNER_A,
    injected_owner: OWNER_B,
  });
  assert.equal(unknownField.ok, false);
  if (!unknownField.ok) {
    assert.equal(unknownField.error.status, 422);
    assert.equal(unknownField.error.code, 'invalid_input');
  }

  const missingIdempotency = await invoke(handler, 'create_application', {
    owner_id: OWNER_A,
    name: 'Missing key',
    project_path: '/',
    business_context: BUSINESS_CONTEXT,
  });
  assert.equal(missingIdempotency.ok, false);
  if (!missingIdempotency.ok) {
    assert.equal(missingIdempotency.error.status, 422);
  }
});

test('AgentCore handler sanitizes internal failures and retains details in structured logs', async () => {
  const fixture = makeFixture();
  const logger = new RecordingLogger();
  fixture.services.applications.list = async () => {
    throw new Error('database password was exposed');
  };
  const handler = handlerFor(fixture, { logger });

  const response = await invoke(handler, 'list_applications', {
    owner_id: OWNER_A,
  });
  assert.deepEqual(response, {
    ok: false,
    error: {
      status: 500,
      code: 'internal_error',
      message: 'Internal server error.',
    },
  });
  assert.doesNotMatch(JSON.stringify(response), /database password/);
  assert.equal(logger.errorMessages.length, 1);
  const logged = JSON.parse(logger.errorMessages[0]!) as Record<
    string,
    unknown
  >;
  assert.equal(logged.event, 'mcp_tool_failed');
  assert.equal(logged.errorMessage, 'database password was exposed');
});

const SchemaDefinitionSchema: z.ZodType = z.lazy(() =>
  z
    .strictObject({
      type: z.enum([
        'object',
        'string',
        'number',
        'integer',
        'boolean',
        'array',
      ]),
      description: z.string().optional(),
      properties: z.record(z.string(), SchemaDefinitionSchema).optional(),
      required: z.array(z.string()).optional(),
      items: SchemaDefinitionSchema.optional(),
    })
    .superRefine((value, issue) => {
      if (value.type === 'object' && value.items !== undefined) {
        issue.addIssue({
          code: 'custom',
          message: 'object schemas cannot define items',
        });
      }
      if (value.type === 'array' && value.items === undefined) {
        issue.addIssue({
          code: 'custom',
          message: 'array schemas must define items',
        });
      }
    }),
);

const ToolDefinitionSchema = z.strictObject({
  name: z.string().min(1),
  description: z.string().min(1),
  inputSchema: SchemaDefinitionSchema,
  outputSchema: SchemaDefinitionSchema.optional(),
});

test('mcp-tools.json is a valid ToolDefinition array aligned with the handler registry', async () => {
  const contents = await readFile(
    new URL('../mcp-tools.json', import.meta.url),
    'utf8',
  );
  const definitions = z.array(ToolDefinitionSchema).parse(
    JSON.parse(contents) as unknown,
  );
  const names = definitions.map((definition) => definition.name);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual(names.sort(), [...MCP_TOOL_NAMES].sort());
  const mutationNames = new Set([
    'create_application',
    'update_application',
    'delete_application',
    'start_run',
    'pause_run',
    'stop_run',
    'resume_run',
    'respond_to_interaction',
    'skip_interaction',
  ]);
  for (const definition of definitions) {
    assert.equal(
      (definition.inputSchema as { type: string }).type,
      'object',
    );
    const required = new Set(
      (definition.inputSchema as { required?: string[] }).required ?? [],
    );
    assert.ok(required.has('owner_id'));
    assert.equal(
      required.has('idempotency_key'),
      mutationNames.has(definition.name),
    );
  }
});

test('MCP Lambda environment requires gateway ID and omits target ID in production mode', () => {
  assert.deepEqual(
    readHostedMcpLambdaEnvironment({
      AGENTCORE_GATEWAY_ID: GATEWAY_ID,
    }),
    { gatewayId: GATEWAY_ID },
  );
  assert.deepEqual(
    readHostedMcpLambdaEnvironment({
      AGENTCORE_GATEWAY_ID: GATEWAY_ID,
      AGENTCORE_TARGET_ID: TARGET_ID,
    }),
    { gatewayId: GATEWAY_ID, targetId: TARGET_ID },
  );
  assert.throws(
    () => readHostedMcpLambdaEnvironment({}),
    /AGENTCORE_GATEWAY_ID environment variable is required/,
  );
});
