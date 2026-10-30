import assert from 'node:assert/strict';
import test from 'node:test';
import { apiRequest } from './support/api.mjs';
import {
  decodeJwt,
  normalizedBaseUrl,
  optional,
  skipUnless,
} from './support/env.mjs';

test(
  'Cognito access token has the expected issuer, audience, use, and lifetime',
  {
    skip: skipUnless(
      'TF_TEST_USER_A_ACCESS_TOKEN',
      'TF_USER_POOL_ID',
      'TF_USER_POOL_CLIENT_ID',
      'TF_REGION',
    ),
  },
  () => {
    const claims = decodeJwt(optional('TF_TEST_USER_A_ACCESS_TOKEN'));
    assert.equal(claims.token_use, 'access');
    assert.equal(claims.client_id, optional('TF_USER_POOL_CLIENT_ID'));
    assert.equal(
      claims.iss,
      `https://cognito-idp.${optional('TF_REGION')}.amazonaws.com/${optional('TF_USER_POOL_ID')}`,
    );
    assert.ok(Number(claims.exp) > Math.floor(Date.now() / 1000));
    assert.match(String(claims.sub), /^[A-Za-z0-9_-]+$/);
  },
);

test(
  'service routes require both the CloudFront session and a valid JWT',
  { skip: skipUnless('TF_BASE_URL', 'TF_TEST_USER_A_ACCESS_TOKEN') },
  async () => {
    const unauthenticated = await fetch(`${normalizedBaseUrl()}/api/health`, {
      redirect: 'manual',
    });
    assert.equal(unauthenticated.status, 401);
    assert.equal(unauthenticated.headers.get('set-cookie'), null);
    assert.equal(unauthenticated.headers.get('location'), null);

    const missingJwt = await fetch(`${normalizedBaseUrl()}/api/health`, {
      headers: { cookie: 'tf_session=1' },
      redirect: 'manual',
    });
    assert.equal(missingJwt.status, 401);

    const token = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const [header, payload, signature] = token.split('.');
    const tamperedSignature =
      `${signature.startsWith('a') ? 'b' : 'a'}${signature.slice(1)}`;
    const tampered = `${header}.${payload}.${tamperedSignature}`;
    const denied = await apiRequest('/api/health', tampered);
    assert.equal(denied.response.status, 401);
  },
);
