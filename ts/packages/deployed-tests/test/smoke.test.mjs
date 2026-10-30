import assert from 'node:assert/strict';
import test from 'node:test';
import { expectApi } from './support/api.mjs';
import { normalizedBaseUrl, optional, skipUnless } from './support/env.mjs';

test(
  'CloudFront redirects unauthenticated viewers to Cognito with PKCE',
  { skip: skipUnless('TF_BASE_URL', 'TF_COGNITO_DOMAIN') },
  async () => {
    const response = await fetch(normalizedBaseUrl(), { redirect: 'manual' });
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get('location'));
    assert.equal(location.origin, optional('TF_COGNITO_DOMAIN'));
    assert.equal(location.pathname, '/oauth2/authorize');
    assert.equal(location.searchParams.get('response_type'), 'code');
    assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
    assert.match(location.searchParams.get('code_challenge') || '', /^[A-Za-z0-9_-]{43}$/);
    assert.ok(location.searchParams.get('state'));
  },
);

test(
  'authenticated health route is reachable through CloudFront',
  { skip: skipUnless('TF_BASE_URL', 'TF_TEST_USER_A_ACCESS_TOKEN') },
  async () => {
    const { body } = await expectApi(
      '/api/health',
      optional('TF_TEST_USER_A_ACCESS_TOKEN'),
    );
    assert.deepEqual(body, { status: 'ok' });
  },
);
