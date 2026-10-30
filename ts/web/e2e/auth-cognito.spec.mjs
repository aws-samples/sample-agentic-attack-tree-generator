import { expect, test } from '@playwright/test';
import { installBaseApi, json } from './support/mock-api.mjs';

const firstState = 'a'.repeat(43);
const secondState = 'b'.repeat(43);

async function seedLoginCookies(context) {
  await context.addCookies([
    {
      name: 'tf_oauth_client',
      value: 'client-playwright',
      domain: '127.0.0.1',
      path: '/',
    },
    {
      name: 'tf_oauth_domain',
      value: encodeURIComponent('https://auth.example.test'),
      domain: '127.0.0.1',
      path: '/',
    },
    {
      name: `tf_pkce_verifier_${firstState}`,
      value: 'pkce-verifier-value',
      domain: '127.0.0.1',
      path: '/',
    },
    {
      name: `tf_pkce_verifier_${secondState}`,
      value: 'second-verifier-value',
      domain: '127.0.0.1',
      path: '/',
    },
  ]);
}

test('authorization callback exchanges a PKCE code and stores the session', async ({
  page,
  context,
}) => {
  await seedLoginCookies(context);
  await installBaseApi(page, undefined, { session: false });
  let tokenRequest = null;
  await page.route('https://auth.example.test/oauth2/token', async (route) => {
    tokenRequest = route.request().postData();
    return json(route, {
      access_token: 'cognito-access',
      id_token: 'cognito-id',
      refresh_token: 'cognito-refresh',
      expires_in: 3600,
      token_type: 'Bearer',
    }, 200, {
      'Access-Control-Allow-Origin': 'http://127.0.0.1:3100',
    });
  });

  await page.goto(`/auth/callback?code=authorization-code&state=${firstState}`);
  await expect
    .poll(() => new URL(page.url()).pathname)
    .toBe('/');
  expect(tokenRequest).toContain('grant_type=authorization_code');
  expect(tokenRequest).toContain('code_verifier=pkce-verifier-value');
  expect(tokenRequest).toContain('redirect_uri=http%3A%2F%2F127.0.0.1%3A3100%2Fauth%2Fcallback');
  const stored = await page.evaluate(() =>
    JSON.parse(sessionStorage.getItem('threatforest.oauth.tokens.v1')),
  );
  expect(stored.accessToken).toBe('cognito-access');
  expect(stored.refreshToken).toBe('cognito-refresh');
  const cookies = await context.cookies();
  expect(cookies.some(cookie => cookie.name === `tf_pkce_verifier_${firstState}`)).toBe(false);
  expect(cookies.some(cookie => cookie.name === `tf_pkce_verifier_${secondState}`)).toBe(true);
});

test('two login tabs exchange independently without consuming each other’s verifier', async ({
  page,
  context,
}) => {
  await seedLoginCookies(context);
  const secondPage = await context.newPage();
  await installBaseApi(page, undefined, { session: false });
  await installBaseApi(secondPage, undefined, { session: false });
  const exchanged = [];
  await context.route('https://auth.example.test/oauth2/token', async route => {
    const parameters = new URLSearchParams(route.request().postData());
    const verifier = parameters.get('code_verifier');
    exchanged.push(verifier);
    await json(route, {
      access_token: `access-${verifier}`,
      refresh_token: 'refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
    }, 200, { 'Access-Control-Allow-Origin': 'http://127.0.0.1:3100' });
  });
  await Promise.all([
    page.goto(`/auth/callback?code=first-code&state=${firstState}`),
    secondPage.goto(`/auth/callback?code=second-code&state=${secondState}`),
  ]);
  for (const [tab, verifier] of [[page, 'pkce-verifier-value'], [secondPage, 'second-verifier-value']]) {
    await expect.poll(() => new URL(tab.url()).pathname).toBe('/');
    expect(await tab.evaluate(() =>
      JSON.parse(sessionStorage.getItem('threatforest.oauth.tokens.v1')).accessToken,
    )).toBe(`access-${verifier}`);
  }
  expect(exchanged.sort()).toEqual(['pkce-verifier-value', 'second-verifier-value']);
  await secondPage.close();
});

test('a failed code exchange provides recovery without a logout redirect loop', async ({
  page, context,
}) => {
  await seedLoginCookies(context);
  let exchanges = 0;
  await page.route('https://auth.example.test/oauth2/token', async route => {
    exchanges += 1;
    return json(route, { error: 'invalid_grant' }, 400, {
      'Access-Control-Allow-Origin': 'http://127.0.0.1:3100',
    });
  });
  await page.goto(`/auth/callback?code=expired-code&state=${firstState}`);
  await expect(page.getByRole('heading', { name: 'Sign in again' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Sign in to ThreatForest' })).toHaveAttribute('href', '/auth/login');
  expect(new URL(page.url()).pathname).toBe('/auth/callback');
  expect(new URL(page.url()).search).toBe('');
  expect(exchanges).toBe(1);
});

test('live CloudFront redirect uses Cognito authorization code flow with PKCE', async ({
  page,
}) => {
  test.skip(process.env.TF_PLAYWRIGHT_LIVE !== '1', 'Set TF_PLAYWRIGHT_LIVE=1.');
  await page.goto('/');
  const authorizationUrl = new URL(page.url());
  expect(['/oauth2/authorize', '/login']).toContain(
    authorizationUrl.pathname,
  );
  expect(authorizationUrl.searchParams.get('response_type')).toBe('code');
  expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorizationUrl.searchParams.get('code_challenge')).toMatch(
    /^[A-Za-z0-9_-]{43}$/,
  );
  expect(authorizationUrl.searchParams.get('state')).toBeTruthy();
});
