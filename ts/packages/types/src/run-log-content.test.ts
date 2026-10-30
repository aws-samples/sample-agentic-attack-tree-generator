import assert from 'node:assert/strict';
import test from 'node:test';
import { boundLogContent, logContent, messageLogContent, MAX_LOG_CONTENT_CHARACTERS } from './run-log-content.js';

test('redacts credentials in structured and free-text tool content while preserving evidence and usage', () => {
  const block = logContent('tool_result', {
    path: '/tmp/threatforest/owners/o/applications/a/runs/r/engine/state/context.json',
    input_tokens: 123, password: 'hidden-password', secret_access_key: 'hidden-key',
    content: 'api_key="hidden-api" Authorization: Bearer hidden-token\nsource.ts:25 has no tenant guard',
    nested: { sessionToken: 'hidden-session' },
  });
  assert.doesNotMatch(block.text, /hidden-|\/tmp\/threatforest/);
  assert.match(block.text, /source\.ts:25 has no tenant guard/);
  assert.equal(JSON.parse(block.text).input_tokens, 123);
  assert.equal(JSON.parse(block.text).path, 'engine/state/context.json');
});

test('captures only exposed reasoning text and never signatures, redacted bytes or system messages', () => {
  const content = messageLogContent([
    { role: 'system', content: [{ text: 'private-system-message' }] },
    { role: 'assistant', content: [
      { type: 'reasoningBlock', text: 'The endpoint crosses a trust boundary.', signature: 'hidden-signature' },
      { type: 'reasoningBlock', redactedContent: [80, 82, 73, 86, 65, 84, 69] },
      { text: '{"result":"review access control"}' },
    ] },
  ], 'response');
  assert.deepEqual(content.map((block) => block.kind), ['reasoning', 'response']);
  assert.equal(content[0]?.role, 'assistant');
  assert.doesNotMatch(JSON.stringify(content), /hidden-signature|private-system-message|80,82/);
  assert.equal(messageLogContent({ type: 'reasoningBlock', signature: 'only-signature' }, 'response').length, 0);
  assert.equal(messageLogContent({ type: 'reasoningBlock', text: 'prior reasoning' }, 'request').length, 0);
});

test('supports legacy, stable OTel and SDK tool results with structured JSON intact', () => {
  const content = messageLogContent([
    { role: 'user', parts: [{ type: 'text', content: 'Review business context.' }] },
    { role: 'assistant', parts: [{ type: 'tool_call', name: 'read', arguments: { path: 'context.json' } }] },
    { role: 'tool', parts: [{ type: 'tool_call_response', response: [{ json: { trust_boundary: 'tenant' } }] }] },
  ], 'request');
  assert.deepEqual(content.map((block) => block.role), ['user', 'assistant', 'tool']);
  assert.match(content[1]!.text, /context\.json/);
  assert.equal(JSON.parse(content[2]!.text).trust_boundary, 'tenant');
  const response = messageLogContent({ type: 'text', content: '{"priority":"integrity"}' }, 'response');
  assert.equal(JSON.parse(response[0]!.text).priority, 'integrity');
  assert.equal(messageLogContent('{"priority":"integrity"}', 'response').length, 1);
});

test('bounds combined content without allowing reasoning to erase the response', () => {
  const blocks = boundLogContent([
    logContent('reasoning', 'r'.repeat(30_000)),
    logContent('response', '{"mitigations": ["Enforce tenant-scoped lookup"]}'),
    logContent('response', 'x'.repeat(30_000)),
  ]);
  assert.ok(blocks.reduce((sum, block) => sum + block.text.length, 0) <= MAX_LOG_CONTENT_CHARACTERS);
  assert.equal(blocks[0]?.truncated, true);
  assert.equal(blocks[1]?.truncated, false);
  assert.match(blocks[1]!.text, /tenant-scoped/);
  assert.equal(blocks[2]?.truncated, true);
  assert.equal(logContent('tool_result', Array.from({ length: 101 }, (_, index) => index)).truncated, true);
});
