import assert from 'node:assert/strict';
import test from 'node:test';
import type { BoundaryResult, StageDefinition } from '../src/contracts.js';
import {
  createAgentCoreHostedTelemetry,
  evaluationSessionId,
  type HostedTelemetryEvent,
  type OpenTelemetryApiLike,
} from '../src/telemetry.js';
import {
  applicationId,
  authenticatedContext,
  parseResponse,
  runtimeHarness,
  ScriptedStageExecutor,
  seedApplication,
  startBody,
  principal,
} from './helpers.js';

test('AgentCore telemetry emits matching OTEL spans and structured records', () => {
  const logs: string[] = [];
  const spans: Array<{
    name: string;
    attributes: unknown;
    status: number | null;
    ended: boolean;
  }> = [];
  const openTelemetry: OpenTelemetryApiLike = {
    trace: {
      getTracer(name, version) {
        assert.equal(
          name,
          'opentelemetry.instrumentation.threatforest.hosted-runtime',
        );
        assert.equal(version, '1.0.0');
        return {
          startSpan(spanName, options) {
            const span = {
              name: spanName,
              attributes: options.attributes,
              status: null as number | null,
              ended: false,
            };
            spans.push(span);
            return {
              setStatus: ({ code }) => {
                span.status = code;
              },
              end: () => {
                span.ended = true;
              },
            };
          },
        };
      },
    },
    SpanStatusCode: { OK: 1, ERROR: 2 },
  };
  const telemetry = createAgentCoreHostedTelemetry({
    logger: { log: (line) => logs.push(String(line)) },
    openTelemetry,
  });
  const attributes = {
    'threatforest.application.id': 'app_test',
    'threatforest.run.id': 'run_test',
    'threatforest.run.outcome': 'completed',
    'threatforest.run.completed': true,
  } as const;

  telemetry.record({
    spanName: 'threatforest.run.completed',
    status: 'ok',
    attributes,
  });

  const evaluation = {
    'session.id': 'run_test',
    'gen_ai.conversation.id': 'run_test',
    'gen_ai.operation.name': 'invoke_agent',
    'gen_ai.task.input':
      'Generate an evidence-grounded threat model using the configured frameworks with configured provider/configured model.',
    'gen_ai.task.output':
      'Threat model generation completed and the durable report and quality metrics were published.',
    'agentcore.invocation.user_prompt':
      'Generate an evidence-grounded threat model using the configured frameworks with configured provider/configured model.',
    'agentcore.invocation.agent_response':
      'Threat model generation completed and the durable report and quality metrics were published.',
  } as const;
  assert.deepEqual(spans, [
    {
      name: 'threatforest.run.completed',
      attributes: { ...attributes, ...evaluation },
      status: 1,
      ended: true,
    },
  ]);
  assert.deepEqual(JSON.parse(logs[0]!), {
    level: 'info',
    event: 'threatforest.telemetry',
    instrumentation_scope:
      'opentelemetry.instrumentation.threatforest.hosted-runtime',
    span_name: 'threatforest.run.completed',
    attributes: { ...attributes, ...evaluation },
  });
});

test('structured telemetry remains available without an OTEL SDK', () => {
  const logs: string[] = [];
  const telemetry = createAgentCoreHostedTelemetry({
    logger: { log: (line) => logs.push(String(line)) },
    openTelemetry: null,
  });

  assert.doesNotThrow(() => {
    telemetry.record({
      spanName: 'threatforest.stage.failed',
      status: 'error',
      attributes: {
        'threatforest.run.id': 'run_test',
        'threatforest.run.outcome': 'failed',
      },
    });
  });
  assert.deepEqual(JSON.parse(logs[0]!), {
    level: 'error',
    event: 'threatforest.telemetry',
    instrumentation_scope:
      'opentelemetry.instrumentation.threatforest.hosted-runtime',
    span_name: 'threatforest.stage.failed',
    attributes: {
      'threatforest.run.id': 'run_test',
      'threatforest.run.outcome': 'failed',
      'session.id': 'run_test',
      'gen_ai.conversation.id': 'run_test',
    },
  });
});

test('AgentCore evaluation spans classify stages without exporting source content', () => {
  const spans: Array<{
    attributes: Readonly<Record<string, unknown>>;
  }> = [];
  const telemetry = createAgentCoreHostedTelemetry({
    logger: { log: () => {} },
    openTelemetry: {
      trace: {
        getTracer() {
          return {
            startSpan(_name, options) {
              spans.push(options);
              return {
                setStatus: () => {},
                end: () => {},
              };
            },
          };
        },
      },
    },
  });

  telemetry.record({
    spanName: 'threatforest.stage.completed',
    status: 'ok',
    attributes: {
      'threatforest.run.id': 'run_test',
      'threatforest.run.outcome': 'completed',
      'threatforest.stage.id': 'ttp_mapping',
    },
  });

  assert.deepEqual(spans[0]?.attributes, {
    'threatforest.run.id': 'run_test',
    'threatforest.run.outcome': 'completed',
    'threatforest.stage.id': 'ttp_mapping',
    'session.id': 'run_test',
    'gen_ai.conversation.id': 'run_test',
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.tool.name': 'ttp_mapping',
    'gen_ai.tool.call.arguments':
      'Execute the durable threat-model pipeline stage with its persisted run context.',
    'gen_ai.tool.call.result': 'Stage outcome: completed.',
  });
  assert.doesNotMatch(JSON.stringify(spans), /source|prompt|transcript/i);
});

test('output quality uses a bounded evaluation session and relevant summary', () => {
  const appliedAttributes: Array<[string, unknown]> = [];
  const spans: Array<{
    attributes: Readonly<Record<string, unknown>>;
  }> = [];
  const telemetry = createAgentCoreHostedTelemetry({
    logger: { log: () => {} },
    openTelemetry: {
      trace: {
        getTracer() {
          return {
            startSpan(_name, options) {
              spans.push(options);
              return {
                setAttribute(name, value) {
                  appliedAttributes.push([name, value]);
                },
                setStatus: () => {},
                end: () => {},
              };
            },
          };
        },
      },
    },
  });

  telemetry.record({
    spanName: 'threatforest.run.output_quality',
    status: 'ok',
    attributes: {
      'threatforest.run.id': 'run_test',
      'threatforest.model.provider': 'AWS Bedrock',
      'threatforest.model.id': 'global.anthropic.claude-sonnet-4-6',
      'threatforest.ttp.frameworks': ['attack', 'atlas', 'wiz'],
      'threatforest.threat.count': 8,
      'threatforest.threat.high_severity_count': 3,
      'threatforest.threat.categories': ['Spoofing', 'Tampering'],
      'threatforest.quality.gate_passed': true,
      'threatforest.ttp.decision_coverage': 1,
      'threatforest.ttp.accepted_coverage': 0.75,
      'threatforest.ttp.abstention_rate': 0.25,
      'threatforest.mitigation.coverage': 1,
      'threatforest.mitigation.evidence_coverage': 0.875,
    },
  });

  const sessionId = evaluationSessionId('run_test');
  assert.equal(spans[0]?.attributes['session.id'], sessionId);
  assert.equal(
    spans[0]?.attributes['threatforest.evaluation.ready'],
    true,
  );
  assert.equal(
    spans[0]?.attributes['gen_ai.operation.name'],
    'invoke_agent',
  );
  assert.match(
    String(spans[0]?.attributes['gen_ai.task.output']),
    /Published 8 threats, including 3 high-severity threats/,
  );
  assert.match(
    String(spans[0]?.attributes['gen_ai.task.output']),
    /accepted mapping coverage was 75%/,
  );
  assert.deepEqual(appliedAttributes, [
    ['session.id', sessionId],
    ['gen_ai.conversation.id', sessionId],
  ]);
});

test('durable execution records run, stage, HITL, and completion boundaries without content', async () => {
  const recorded: HostedTelemetryEvent[] = [];
  const telemetry = {
    record: (event: HostedTelemetryEvent) => recorded.push(event),
  };
  const plan = [
    {
      id: 'review',
      version: 1,
      hitlKind: 'mapping_review',
      usesModel: false,
    },
    {
      id: 'report',
      version: 1,
      hitlKind: null,
      usesModel: true,
    },
  ] as const satisfies readonly StageDefinition[];
  const stageExecutor = new ScriptedStageExecutor({
    review: (context) =>
      context.response === null
        ? {
            status: 'awaiting_input',
            reason: { message: 'sensitive review reason' },
            transcript: { text: 'sensitive transcript content' },
          }
        : { status: 'completed' },
  });
  const harness = runtimeHarness({
    telemetry,
    stageExecutor,
    stagePlan: plan,
  });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);

  const started = parseResponse<BoundaryResult>(
    (
      await harness.runtime.handle({
        method: 'POST',
        path: '/invocations/start-run',
        context: authenticatedContext(),
        body: startBody({ idempotency_key: 'telemetry-hitl' }),
      })
    ).body,
  );
  assert.equal(started.boundary, 'awaiting_input');

  const resumed = parseResponse<BoundaryResult>(
    (
      await harness.runtime.handle({
        method: 'POST',
        path: '/invocations/respond-hitl',
        context: authenticatedContext(),
        body: {
          application_id: applicationId,
          run_id: started.run.run_id,
          interaction_id: started.interaction?.interaction_id,
          revision: started.interaction?.revision,
          action: 'submit',
          text: 'sensitive human response',
        },
      })
    ).body,
  );
  assert.equal(resumed.boundary, 'completed');

  assert.deepEqual(
    recorded.map(({ spanName }) => spanName),
    [
      'threatforest.run.started',
      'threatforest.stage.started',
      'threatforest.hitl.requested',
      'threatforest.hitl.response_received',
      'threatforest.stage.completed',
      'threatforest.stage.started',
      'threatforest.stage.completed',
      'threatforest.run.completed',
    ],
  );
  const completion = recorded.at(-1);
  assert.equal(completion?.status, 'ok');
  assert.deepEqual(completion?.attributes, {
    'threatforest.application.id': applicationId,
    'threatforest.run.id': resumed.run.run_id,
    'threatforest.run.correlation_id': resumed.run.trace_id,
    'threatforest.model.provider': 'bedrock',
    'threatforest.model.id': 'eu.anthropic.claude-sonnet',
    'threatforest.ttp.frameworks': ['STRIDE', 'MITRE ATT&CK', 'PASTA'],
    'threatforest.run.outcome': 'completed',
    'gen_ai.provider.name': 'bedrock',
    'gen_ai.request.model': 'eu.anthropic.claude-sonnet',
    'threatforest.run.completed': true,
  });

  await harness.executor.runUntilBoundary(
    {
      owner_id: owner.userId,
      application_id: applicationId,
    },
    resumed.run.run_id,
    resumed.actor_id,
  );
  assert.equal(
    recorded.filter(({ spanName }) => spanName === 'threatforest.run.completed').length,
    1,
  );

  const serialized = JSON.stringify(recorded);
  assert.doesNotMatch(serialized, /subject-a/);
  assert.doesNotMatch(serialized, /sensitive/);
  assert.doesNotMatch(serialized, /source_01/);
  assert.doesNotMatch(serialized, /temperature/);
});

test('failed stages report a bounded outcome without the exception message', async () => {
  const recorded: HostedTelemetryEvent[] = [];
  const harness = runtimeHarness({
    telemetry: {
      record: (event) => recorded.push(event),
    },
    stageExecutor: new ScriptedStageExecutor({
      scanner: () => {
        throw new Error('sensitive provider response');
      },
    }),
    stagePlan: [
      {
        id: 'scanner',
        version: 1,
        hitlKind: null,
        usesModel: true,
      },
    ],
  });
  const owner = await principal();
  await seedApplication(harness.store, owner.userId);

  const result = parseResponse<BoundaryResult>(
    (
      await harness.runtime.handle({
        method: 'POST',
        path: '/invocations/start-run',
        context: authenticatedContext(),
        body: startBody({ idempotency_key: 'telemetry-failure' }),
      })
    ).body,
  );

  assert.equal(result.boundary, 'failed');
  const failure = recorded.find(
    ({ spanName }) => spanName === 'threatforest.stage.failed',
  );
  assert.equal(failure?.status, 'error');
  assert.equal(failure?.attributes['threatforest.run.outcome'], 'failed');
  assert.equal(failure?.attributes['threatforest.error.code'], 'Error');
  assert.doesNotMatch(JSON.stringify(recorded), /sensitive provider response/);
});
