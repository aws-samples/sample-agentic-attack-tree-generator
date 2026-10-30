import assert from 'node:assert/strict';
import test from 'node:test';
import {
  apiRequest,
  createApplication,
  deleteApplication,
  expectApi,
} from './support/api.mjs';
import { optional, skipUnless } from './support/env.mjs';

test(
  'applications are isolated by Cognito subject',
  {
    skip: skipUnless(
      'TF_BASE_URL',
      'TF_TEST_USER_A_ACCESS_TOKEN',
      'TF_TEST_USER_B_ACCESS_TOKEN',
    ),
    timeout: 60_000,
  },
  async () => {
    const tokenA = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const tokenB = optional('TF_TEST_USER_B_ACCESS_TOKEN');
    const application = await createApplication(tokenA, 'Isolation Test');
    try {
      const own = await expectApi(
        `/api/applications/by-id/${encodeURIComponent(application.id)}`,
        tokenA,
      );
      assert.equal(own.body.id, application.id);

      const foreignRead = await apiRequest(
        `/api/applications/by-id/${encodeURIComponent(application.id)}`,
        tokenB,
      );
      assert.equal(foreignRead.response.status, 404);

      const foreignDelete = await apiRequest(
        `/api/applications/by-id/${encodeURIComponent(application.id)}`,
        tokenB,
        { method: 'DELETE' },
      );
      assert.equal(foreignDelete.response.status, 404);

      const listB = await expectApi('/api/applications', tokenB);
      assert.equal(
        listB.body.applications.some((entry) => entry.id === application.id),
        false,
      );
    } finally {
      await deleteApplication(tokenA, application.id);
    }
  },
);
