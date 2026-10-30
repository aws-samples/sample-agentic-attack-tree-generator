import assert from 'node:assert/strict';
import test from 'node:test';
import { runDisplayName } from './run-name.js';

test('run display names are readable and independent of opaque IDs or providers', () => {
  assert.equal(runDisplayName('Payments', '2026-09-17T13:42:07Z'), 'Payments · 17 Sept 2026, 13:42:07 UTC');
  assert.equal(runDisplayName(null, 'invalid'), 'Threat model');
  assert.equal(runDisplayName('Payments', '2026-09-17T14:42:07+01:00'),
    runDisplayName('Payments', '2026-09-17T13:42:07Z'));
});
