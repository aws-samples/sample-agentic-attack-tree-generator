import assert from 'node:assert/strict';
import test from 'node:test';
import { Agent, Model, tool, type ModelStreamEvent, type BaseModelConfig } from '@strands-agents/sdk';
import type { Attributes } from '@opentelemetry/api';
import { z } from 'zod';
import { observeAgent, observeOperation, withExecutionObservability, executionTraceAttributes } from './execution-observability.js';

class ScriptedModel extends Model {
  calls = 0;
  constructor(private readonly script: (call: number) => AsyncIterable<ModelStreamEvent>) { super(); }
  updateConfig(_config: BaseModelConfig): void {}
  getConfig(): BaseModelConfig { return { modelId: 'offline-observability-test' }; }
  stream(): AsyncIterable<ModelStreamEvent> { return this.script(++this.calls); }
}
const scope = (record: (attributes: Attributes) => void, runId = 'run_one') => ({
  ownerId: `owner_${runId}`, applicationId: `app_${runId}`, runId, correlationId: `trace_${runId}`,
  stage: 'parallel_pipeline', attempt: 2, record,
});
const title = (event: Attributes) => event['threatforest.execution.title'];
const content = (event: Attributes) => JSON.parse(String(event['threatforest.execution.content'])) as Array<{ kind: string; text: string }>;

async function* response(text: string): AsyncIterable<ModelStreamEvent> {
  yield { type: 'modelMessageStartEvent', role: 'assistant' };
  yield { type: 'modelContentBlockStartEvent' };
  yield { type: 'modelContentBlockDeltaEvent', delta: { type: 'textDelta', text } };
  yield { type: 'modelContentBlockStopEvent' };
  yield { type: 'modelMessageStopEvent', stopReason: 'endTurn' };
  yield { type: 'modelMetadataEvent', usage: { inputTokens: 42, outputTokens: 12, totalTokens: 54 } };
}

test('real SDK hooks emit requests before model completion and retain response, reasoning and usage', async () => {
  const events: Attributes[] = [];
  const model = new ScriptedModel(async function* () {
    assert.deepEqual(events.map(title), ['Agent request', 'Model request']);
    assert.equal(content(events[0]!)[0]?.text, 'Analyze the tenant boundary.');
    assert.equal(events[0]!['threatforest.execution.invocation_id'], events[1]!['threatforest.execution.invocation_id']);
    yield { type: 'modelMessageStartEvent', role: 'assistant' };
    yield { type: 'modelContentBlockStartEvent' };
    yield { type: 'modelContentBlockDeltaEvent', delta: {
      type: 'reasoningContentDelta', text: 'The tenant lookup determines the trust boundary.', signature: 'hidden-signature',
    } };
    yield { type: 'modelContentBlockStopEvent' };
    yield { type: 'modelContentBlockStartEvent' };
    yield { type: 'modelContentBlockDeltaEvent', delta: { type: 'textDelta', text: '{"finding":"missing tenant guard"}' } };
    yield { type: 'modelContentBlockStopEvent' };
    yield { type: 'modelMessageStopEvent', stopReason: 'endTurn' };
    yield { type: 'modelMetadataEvent', usage: { inputTokens: 42, outputTokens: 12, totalTokens: 54 } };
  });
  await withExecutionObservability(scope((event) => events.push(event)), async () => {
    const agent = observeAgent(new Agent({ model, printer: false, systemPrompt: 'hidden-system-prompt' }), 'tree-t1', 'Attack tree · THR-1');
    await agent.invoke('Analyze the tenant boundary.');
  });
  assert.deepEqual(events.map(title), ['Agent request', 'Model request', 'Model response', 'Agent response']);
  assert.deepEqual(content(events[2]!).map((block) => block.kind), ['reasoning', 'response']);
  assert.equal(events[2]!['gen_ai.usage.input_tokens'], 42);
  assert.equal(events[3]!['threatforest.execution.status'], 'completed');
  assert.ok(events.every((event) => event['threatforest.stage.id'] === 'parallel_pipeline'));
  assert.ok(events.every((event) => event['threatforest.execution.task_id'] === 'tree-t1'));
  assert.doesNotMatch(JSON.stringify(events), /hidden-system-prompt|hidden-signature/);
});

test('captures real tool input/result and a second model call without inventing reasoning', async () => {
  const events: Attributes[] = [];
  const read = tool({ name: 'read_evidence', description: 'Read evidence', inputSchema: z.object({ path: z.string() }),
    callback: ({ path }) => ({ path, line: 25, excerpt: 'return findByTenant(tenantId, id)', password: 'hidden-password' }),
  });
  const model = new ScriptedModel(async function* (call) {
    if (call > 1) { yield* response('Evidence verified.'); return; }
    yield { type: 'modelMessageStartEvent', role: 'assistant' };
    yield { type: 'modelContentBlockStartEvent', start: { type: 'toolUseStart', toolUseId: 'read-1', name: 'read_evidence' } };
    yield { type: 'modelContentBlockDeltaEvent', delta: { type: 'toolUseInputDelta', input: '{"path":"src/tenant.ts"}' } };
    yield { type: 'modelContentBlockStopEvent' };
    yield { type: 'modelMessageStopEvent', stopReason: 'toolUse' };
  });
  await withExecutionObservability(scope((event) => events.push(event)), async () => {
    await observeAgent(new Agent({ model, tools: [read], printer: false }), 'mitigation-t1', 'Mitigation · THR-1').invoke('Verify source evidence.');
  });
  const start = events.find((event) => title(event) === 'Tool use')!;
  const end = events.find((event) => title(event) === 'Tool result')!;
  assert.match(content(start)[0]!.text, /src\/tenant\.ts/);
  assert.match(content(end)[0]!.text, /findByTenant/);
  assert.equal(start['threatforest.execution.operation_id'], end['threatforest.execution.operation_id']);
  assert.equal(events.filter((event) => title(event) === 'Model request').length, 2);
  assert.doesNotMatch(JSON.stringify(events), /hidden-password/);
  assert.ok(events.flatMap(content).every((block) => block.kind !== 'reasoning'));
});

test('records model failures without converting them to successful agent responses', async () => {
  const events: Attributes[] = [];
  const model = new ScriptedModel(async function* () { throw new Error('api_key="hidden-key" model rejected request'); });
  await assert.rejects(withExecutionObservability(scope((event) => events.push(event)), () =>
    observeAgent(new Agent({ model, printer: false }), 'scanner', 'Scanner').invoke('Analyze repository.')), /model rejected/);
  const failure = events.find((event) => title(event) === 'Model error')!;
  assert.equal(failure['threatforest.execution.status'], 'error');
  assert.doesNotMatch(JSON.stringify(events), /hidden-key/);
  assert.ok(!events.some((event) => title(event) === 'Agent response'));
});

test('parallel runs retain their own ownership and worker metadata across async boundaries', async () => {
  const events: Attributes[] = [];
  await Promise.all(['one', 'two'].map((id) => withExecutionObservability(scope((event) => events.push(event), id), async () => {
    await Promise.resolve();
    assert.equal(executionTraceAttributes()['threatforest.run.id'], id);
    return observeOperation(`ttp-${id}`, `TTP mapping ${id}`, { steps: [id] }, async () => {
      await Promise.resolve();
      return { technique: id };
    });
  })));
  assert.equal(events.length, 4);
  for (const event of events) {
    const id = event['threatforest.run.id'];
    assert.equal(event['threatforest.owner.id'], `owner_${id}`);
    assert.equal(event['threatforest.application.id'], `app_${id}`);
    assert.equal(event['threatforest.execution.task_id'], `ttp-${id}`);
  }
  assert.deepEqual(executionTraceAttributes(), {});
});

test('telemetry exporter failures do not fail successful work', async () => {
  const result = await withExecutionObservability(scope(() => { throw new Error('export failed'); }), () =>
    observeOperation('ttp', 'TTP mapping', { step: 'S1' }, async () => ({ accepted: true })));
  assert.deepEqual(result, { accepted: true });
});
