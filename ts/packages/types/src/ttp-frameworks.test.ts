import assert from 'node:assert/strict';
import test from 'node:test';
import { MatchStepsRequestSchema } from './ml-service.js';
import {
  DEFAULT_TTP_FRAMEWORK_IDS,
  TTP_FRAMEWORK_CATALOG,
  TTP_FRAMEWORK_IDS,
} from './ttp-frameworks.js';

test('all hosted defaults are canonical mapper framework IDs', () => {
  assert.deepEqual(DEFAULT_TTP_FRAMEWORK_IDS, ['attack', 'atlas', 'wiz']);
  assert.deepEqual(Object.keys(TTP_FRAMEWORK_CATALOG), TTP_FRAMEWORK_IDS);

  const request = MatchStepsRequestSchema.parse({
    steps: ['Exfiltrate data from object storage.'],
    frameworks: [...DEFAULT_TTP_FRAMEWORK_IDS],
  });
  assert.deepEqual(request.frameworks, TTP_FRAMEWORK_IDS);
});

test('the mapper request contract rejects threat-modeling methodologies', () => {
  assert.throws(() =>
    MatchStepsRequestSchema.parse({
      steps: ['Spoof an authenticated user.'],
      frameworks: ['STRIDE'],
    }),
  );
});
