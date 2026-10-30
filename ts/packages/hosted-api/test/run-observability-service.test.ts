import assert from 'node:assert/strict';
import test from 'node:test';
import { FilterLogEventsCommand } from '@aws-sdk/client-cloudwatch-logs';
import type { ApplicationId, RunId, UserId } from '@threatforest/types';
import type { RunRecord } from '@threatforest/control-plane';
import { RunObservabilityService } from '../src/run-observability-service.js';

const OWNER = 'user_observability' as UserId;
const RUN = 'run_observability' as RunId;
const APP = 'app_observability' as ApplicationId;
const run: RunRecord = {
  schema_version: 1, owner_id: OWNER, application_id: APP, run_id: RUN,
  status: 'completed', source_artifact_ids: [], threat_artifact_id: null,
  current_stage_id: null, trace_id: 'trace', revision: 1, last_event_sequence: 0,
  created_at: '2026-09-15T00:00:00.000Z', updated_at: '2026-09-15T10:00:00.000Z',
  completed_at: '2026-09-15T10:00:00.000Z', error_code: null, error_message: null,
};

function event(message: Record<string, unknown>, timestamp = 1_789_472_590_000) {
  return { eventId: String(timestamp), timestamp, message: JSON.stringify(message) };
}

test('completed-run queries stop after delivery allowance and preserve explicit pagination windows', async () => {
  const endTimes: number[] = [];
  const service = new RunObservabilityService({
    region: 'eu-west-2',
    runs: { getRecord: async () => run },
    client: {
      async send(command) {
        assert.ok(command instanceof FilterLogEventsCommand);
        endTimes.push(command.input.endTime!);
        return { events: [] };
      },
    },
  });
  const response = await service.list(OWNER, RUN);
  assert.equal(response.window_end, '2026-09-15T10:15:00.000Z');
  await service.list(OWNER, RUN, { until: '2026-09-16T10:00:00.000Z', nextToken: 'continuation' });
  assert.deepEqual(endTimes, [
    Date.parse('2026-09-15T10:15:00.000Z'),
    Date.parse('2026-09-16T10:00:00.000Z'),
  ]);
});

test('normalizes legacy AgentCore model, tool and response spans using verified ancestry', async () => {
  let ownershipChecks = 0;
  const service = new RunObservabilityService({
    region: 'eu-west-2',
    runs: {
      async getRecord(ownerId, runId) {
        ownershipChecks += 1;
        assert.equal(ownerId, OWNER);
        assert.equal(runId, RUN);
        return run;
      },
    },
    client: {
      async send() {
        return {
          events: [
            event({
              traceId: 'trace-1',
              spanId: 'agent-1',
              name: 'invoke_agent Scanner',
              startTimeUnixNano: '1789472587086000000',
              endTimeUnixNano: '1789472877969000000',
              durationNano: '290883000000',
              attributes: {
                'threatforest.run.id': RUN,
                'gen_ai.agent.id': 'scanner',
                'gen_ai.agent.name': 'Scanner',
                'gen_ai.request.model': 'global.anthropic.claude-sonnet-4-6',
                'gen_ai.usage.input_tokens': 4000,
                'gen_ai.usage.output_tokens': 500,
                system_prompt: 'must not be returned',
              },
              events: [
                {
                  name: 'gen_ai.choice',
                  attributes: {
                    message: JSON.stringify([
                      { text: 'Repository analysis completed with three trust boundaries.' },
                    ]),
                  },
                },
              ],
              status: { code: 'OK' },
            }),
            event({
              traceId: 'trace-1',
              spanId: 'tool-1',
              parentSpanId: 'agent-1',
              name: 'execute_tool sandboxed_file_read',
              startTimeUnixNano: '1789472592247000000',
              endTimeUnixNano: '1789472592439000000',
              durationNano: '192000000',
              attributes: {
                'gen_ai.tool.name': 'sandboxed_file_read',
                'gen_ai.tool.status': 'success',
              },
              events: [
                {
                  name: 'gen_ai.tool.message',
                  attributes: {
                    content: JSON.stringify({
                      path:
                        '/tmp/threatforest/owners/owner/applications/app/runs/run/engine/state/scanner_context.json',
                      authorization: 'Bearer secret',
                    }),
                  },
                },
              ],
              status: { code: 'OK' },
            }),
            event({
              traceId: 'trace-1',
              spanId: 'model-1',
              parentSpanId: 'agent-1',
              name: 'chat',
              startTimeUnixNano: '1789472587088000000',
              endTimeUnixNano: '1789472592245000000',
              durationNano: '5157000000',
              attributes: {
                'aws.genai.span_kind': 'LLM',
                'gen_ai.request.model': 'global.anthropic.claude-sonnet-4-6',
                'gen_ai.usage.input_tokens': 4221,
                'gen_ai.usage.output_tokens': 505,
              },
              status: { code: 'OK' },
            }),
          ],
        };
      },
    },
  });

  const response = await service.list(OWNER, RUN);
  assert.equal(ownershipChecks, 1);
  assert.equal(response.entries.length, 3);

  const tool = response.entries.find((entry) => entry.category === 'tool');
  assert.equal(tool?.stage, 'scanner');
  assert.match(tool?.summary ?? '', /engine\/state\/scanner_context\.json/);
  assert.doesNotMatch(JSON.stringify(tool?.details), /Bearer secret/);
  assert.doesNotMatch(JSON.stringify(tool?.details), /\/tmp\/threatforest/);

  const model = response.entries.find((entry) => entry.category === 'model');
  assert.equal(model?.details.input_tokens, 4221);
  assert.equal(model?.details.output_tokens, 505);

  const agent = response.entries.find((entry) => entry.category === 'agent');
  assert.match(agent?.summary ?? '', /three trust boundaries/);
  assert.doesNotMatch(JSON.stringify(response), /must not be returned/);
  assert.doesNotMatch(JSON.stringify(agent?.details), /must not be returned/);
});

test('turns a failed tool span into a bounded error entry', async () => {
  const service = new RunObservabilityService({
    region: 'eu-west-2',
    runs: { getRecord: async () => run },
    client: {
      async send() {
        return {
          events: [
            event({
              traceId: 'trace-error',
              spanId: 'tool-error',
              name: 'execute_tool sandboxed_file_read',
              startTimeUnixNano: '1789472592247000000',
              endTimeUnixNano: '1789472592439000000',
              durationNano: '192000000',
              attributes: {
                'gen_ai.tool.name': 'sandboxed_file_read',
                'gen_ai.tool.status': 'error',
                'threatforest.run.id': RUN,
              },
              status: {
                code: 'ERROR',
                message:
                  "ENOENT: stat '/tmp/threatforest/owners/x/applications/y/runs/z/engine/state/context.json'",
              },
            }),
          ],
          nextToken: 'next-page',
        };
      },
    },
  });

  const response = await service.list(OWNER, RUN);
  assert.equal(response.next_token, 'next-page');
  assert.equal(response.entries[0]?.status, 'error');
  assert.doesNotMatch(response.entries[0]?.summary ?? '', /\/tmp\/threatforest/);
});

function execution(id: string, attributes: Record<string, unknown> = {}) {
  return {
    traceId: 'trace-live', spanId: id, name: 'threatforest.execution',
    startTimeUnixNano: '1789472592247000000', endTimeUnixNano: '1789472592248000000',
    attributes: {
      'threatforest.run.id': RUN, 'threatforest.owner.id': OWNER, 'threatforest.application.id': APP,
      'threatforest.stage.id': 'parallel_pipeline', 'threatforest.execution.id': id,
      'threatforest.execution.task_id': 'mitigation-t2', 'threatforest.execution.task_name': 'Mitigation · THR-2',
      'threatforest.execution.invocation_id': 'invocation-2', 'threatforest.execution.operation_id': 'model-2',
      'threatforest.execution.category': 'model', 'threatforest.execution.title': 'Model response',
      'threatforest.execution.status': 'completed', 'threatforest.execution.sequence': 2,
      'threatforest.execution.content': JSON.stringify([
        { kind: 'reasoning', text: 'Tenant identity must scope the lookup.', truncated: false },
        { kind: 'response', text: '{"mitigation":"Use tenant-scoped lookup","api_key":"hidden-key"}', truncated: false },
      ]),
      ...attributes,
    },
  };
}
function serviceWith(spans: Record<string, unknown>[]) {
  return new RunObservabilityService({
    region: 'eu-west-2', runs: { getRecord: async () => run },
    client: { async send() { return { events: spans.map((span) => event(span)) }; } },
  });
}

test('custom events preserve phase, worker, exposed reasoning and response without needing a parent page', async () => {
  const response = await serviceWith([execution('response'), execution('request', {
    'threatforest.execution.sequence': 1, 'threatforest.execution.status': 'running',
    'threatforest.execution.title': 'Model request',
    'threatforest.execution.content': JSON.stringify([{ kind: 'request', role: 'user', text: 'Check mitigation coverage.' }]),
  })]).list(OWNER, RUN);
  assert.deepEqual(response.entries.map((entry) => entry.id), ['request', 'response']);
  const entry = response.entries[1]!;
  assert.equal(entry.stage, 'parallel_pipeline');
  assert.equal(entry.agent_name, 'Mitigation · THR-2');
  assert.equal(entry.invocation_id, 'invocation-2');
  assert.deepEqual(entry.content?.map((block) => block.kind), ['reasoning', 'response']);
  assert.doesNotMatch(JSON.stringify(response), /hidden-key/);
  assert.equal(response.entries[0]?.completed_at, null);
  assert.equal(response.entries[0]?.content?.[0]?.role, 'user');
});

test('rejects cross-run, cross-owner, cross-application and text-only run ID matches', async () => {
  const unscoped = execution('mention-only');
  Reflect.deleteProperty(unscoped.attributes, 'threatforest.run.id');
  unscoped.attributes['threatforest.execution.content'] = JSON.stringify([{ kind: 'response', text: `Mention of ${RUN}` }]);
  const response = await serviceWith([
    execution('valid'), unscoped,
    execution('wrong-run', { 'threatforest.run.id': 'another-run' }),
    execution('wrong-owner', { 'threatforest.owner.id': 'another-owner' }),
    execution('wrong-app', { 'threatforest.application.id': 'another-app' }),
    { ...execution('cycle-a'), parentSpanId: 'cycle-b' },
    { ...execution('cycle-b'), parentSpanId: 'cycle-a' },
    { ...execution('child'), parentSpanId: 'wrong-owner' },
  ]).list(OWNER, RUN);
  assert.deepEqual(response.entries.map((entry) => entry.id), ['valid']);
});

test('preserves both file-write arguments and tool results and parses latest OTel message envelopes', async () => {
  const response = await serviceWith([{
    traceId: 'trace', spanId: 'tool', name: 'execute_tool store_mitigations',
    attributes: { 'threatforest.run.id': RUN, 'gen_ai.tool.name': 'store_mitigations' },
    events: [
      null,
      { name: 'gen_ai.tool.message', attributes: { content: JSON.stringify({ path: 'mitigations.json', content: { attack_step_id: 'S1' } }) } },
      { name: 'gen_ai.choice', attributes: { message: JSON.stringify([{ text: '{"stored":1}' }]) } },
    ],
  }, {
    traceId: 'trace', spanId: 'model', name: 'chat', attributes: { 'threatforest.run.id': RUN },
    events: [{
      name: 'gen_ai.client.inference.operation.details', attributes: {
        'gen_ai.input.messages': JSON.stringify([
          { role: 'system', parts: [{ type: 'text', content: 'hidden-system' }] },
          { role: 'user', parts: [{ type: 'text', content: 'Review payment processing.' }] },
        ]),
        'gen_ai.output.messages': JSON.stringify([
          { role: 'assistant', parts: [
            { type: 'reasoning', content: 'Payment integrity is the business priority.' },
            { type: 'text', content: '{"priority":"integrity"}' },
          ] },
        ]),
      },
    }],
  }]).list(OWNER, RUN);
  const tool = response.entries.find((entry) => entry.category === 'tool')!;
  assert.deepEqual(JSON.parse(tool.content![0]!.text), { path: 'mitigations.json', content: { attack_step_id: 'S1' } });
  assert.equal(JSON.parse(tool.content![1]!.text).stored, 1);
  const model = response.entries.find((entry) => entry.category === 'model')!;
  assert.deepEqual(model.content?.map((block) => block.kind), ['request', 'reasoning', 'response']);
  assert.doesNotMatch(JSON.stringify(response), /hidden-system/);
});

test('checks ownership before CloudWatch and validates pagination time bounds', async () => {
  let reads = 0;
  const denied = new RunObservabilityService({
    region: 'eu-west-2', runs: { async getRecord() { throw new Error('not found'); } },
    client: { async send() { reads++; return {}; } },
  });
  await assert.rejects(denied.list(OWNER, RUN), /not found/);
  assert.equal(reads, 0);
  const service = serviceWith([]);
  await assert.rejects(service.list(OWNER, RUN, { since: 'invalid' }), /valid ISO/);
  await assert.rejects(service.list(OWNER, RUN, { since: '2026-09-16T12:00:00Z', until: '2026-09-16T11:00:00Z' }), /later than/);
});

test('returns empty pages with cursors intact and fixes the CloudWatch time window', async () => {
  let input: Record<string, unknown> = {};
  const service = new RunObservabilityService({
    region: 'eu-west-2', runs: { getRecord: async () => run },
    client: { async send(command) {
      input = command.input as Record<string, unknown>;
      return { events: [], nextToken: 'page-2' };
    } },
  });
  const until = '2026-09-16T12:00:00.000Z';
  const response = await service.list(OWNER, RUN, { until, nextToken: 'page-1' });
  assert.equal(input.startTime, Date.parse(run.created_at));
  assert.equal(input.endTime, Date.parse(until));
  assert.equal(input.nextToken, 'page-1');
  assert.equal(input.limit, 100);
  assert.equal(response.window_end, until);
  assert.equal(response.next_token, 'page-2');
  assert.equal(response.entries.length, 0);
});
