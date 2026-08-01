/**
 * Tests for failed-node error reporting.
 *
 * Reporting only `error.message` is what made the HTTP/2 inactivity timeout so
 * expensive to diagnose: the run summary said nothing but "scanner: Stream ended
 * without completing a message", with the actual TimeoutError sitting one link
 * down in `.cause` and never printed.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { describeNodeError } from './graph.js';

test('surfaces the cause chain, not just the outer message', () => {
  // The real shape of the bug this fixes.
  const timeout = new Error('Stream timed out because of no activity for 120000 ms');
  timeout.name = 'TimeoutError';
  const outer = new Error('Stream ended without completing a message', { cause: timeout });

  const text = describeNodeError(outer);

  assert.match(text, /Stream ended without completing a message/);
  assert.match(text, /TimeoutError/, 'the diagnosis must appear');
  assert.match(text, /no activity for 120000 ms/);
});

test('names the error type only when it carries signal', () => {
  const validation = new Error('temperature is deprecated for this model');
  validation.name = 'ValidationException';
  assert.match(describeNodeError(validation), /^ValidationException: /);

  // Generic wrappers add nothing, so they are reported bare.
  const plain = new Error('something broke');
  assert.equal(describeNodeError(plain), 'something broke');
});

test('does not repeat a cause that merely restates its wrapper', () => {
  const inner = new Error('AccessDeniedException: not authorized');
  const outer = new Error('AccessDeniedException: not authorized', { cause: inner });

  // One occurrence, not two.
  const text = describeNodeError(outer);
  assert.equal(text.split('not authorized').length - 1, 1);
});

test('caps depth so a long or cyclic chain cannot run away', () => {
  const a = new Error('level-a');
  const b = new Error('level-b', { cause: a });
  // Cycle: a.cause -> b, b.cause -> a.
  (a as { cause?: unknown }).cause = b;

  const text = describeNodeError(b);
  assert.ok(text.length < 200, 'must terminate');
  assert.match(text, /level-b/);
});

test('falls back cleanly for a missing or non-Error value', () => {
  assert.equal(describeNodeError(undefined), 'failed');
  assert.equal(describeNodeError('a string'), 'failed');
  assert.equal(describeNodeError(new Error('   ')), 'failed');
});
