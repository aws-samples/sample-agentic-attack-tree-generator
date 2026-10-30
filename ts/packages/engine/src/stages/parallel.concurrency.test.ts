import assert from 'node:assert/strict';
import test from 'node:test';
import { collectThreatResults } from './parallel.js';

test('bounded workers retain input order and retry only failed work', async () => {
  let active = 0;
  let peak = 0;
  const calls = [0, 0, 0, 0];
  const results = await collectThreatResults(4, 1, async index => {
    active++;
    peak = Math.max(peak, active);
    calls[index]!++;
    await new Promise(resolve => setImmediate(resolve));
    active--;
    if (index === 1 && calls[index] === 1) throw new Error('transient');
    return index;
  }, undefined, { concurrency: 2 });
  assert.equal(peak, 2);
  assert.deepEqual(results, [0, 1, 2, 3]);
  assert.deepEqual(calls, [1, 2, 1, 1]);
});

test('cancellation stops queued work and prevents retry', async () => {
  const controller = new AbortController();
  let calls = 0;
  await assert.rejects(collectThreatResults(10, 4, async () => {
    calls++;
    controller.abort(new Error('stop requested'));
    throw controller.signal.reason;
  }, undefined, { concurrency: 2, cancelSignal: controller.signal }), /stop requested/);
  assert.equal(calls, 1);
});
