import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const stateA = 'a'.repeat(43);
const stateB = 'b'.repeat(43);

function browser(query = `code=authorization-code&state=${stateA}`, pathname = '/auth/callback') {
  const cookies = new Map([
    ['tf_oauth_client', 'test-client'],
    ['tf_oauth_domain', encodeURIComponent('https://auth.example.test')],
    [`tf_pkce_verifier_${stateA}`, 'verifier-A'],
    [`tf_pkce_verifier_${stateB}`, 'verifier-B'],
  ]);
  const storage = new Map<string, string>();
  const history = { replaceState: vi.fn() };
  vi.stubGlobal('document', {
    get cookie() { return [...cookies].map(([key, value]) => `${key}=${value}`).join('; '); },
    set cookie(value: string) {
      const [pair] = value.split(';');
      const separator = pair!.indexOf('=');
      const name = pair!.slice(0, separator);
      if (value.includes('Max-Age=0')) cookies.delete(name);
      else cookies.set(name, pair!.slice(separator + 1));
    },
  });
  vi.stubGlobal('window', {
    location: { href: `https://app.example.test${pathname}?${query}`, origin: 'https://app.example.test' },
    history,
    sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
    },
  });
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
    access_token: 'access-token', refresh_token: 'refresh-token', expires_in: 3600, token_type: 'Bearer',
  }), { status: 200 }));
  vi.stubGlobal('fetch', fetch);
  return { cookies, fetch, storage, history };
}

describe('Cognito authorization callback', () => {
  beforeEach(() => vi.resetModules());
  afterEach(() => vi.unstubAllGlobals());

  it('exchanges with the matching attempt and preserves another tab’s verifier', async () => {
    const fixture = browser();
    const { completeAuthorizationCodeFlow } = await import('./session');
    expect(await completeAuthorizationCodeFlow()).toBe(true);
    const [url, request] = fixture.fetch.mock.calls[0]!;
    expect(url).toBe('https://auth.example.test/oauth2/token');
    expect(new URLSearchParams(String(request!.body)).get('code_verifier')).toBe('verifier-A');
    expect(new URLSearchParams(String(request!.body)).get('redirect_uri')).toBe('https://app.example.test/auth/callback');
    expect(request!.credentials).toBe('omit');
    expect(fixture.cookies.has(`tf_pkce_verifier_${stateA}`)).toBe(false);
    expect(fixture.cookies.get(`tf_pkce_verifier_${stateB}`)).toBe('verifier-B');
    expect(fixture.cookies.get('tf_session')).toBe('1');
    expect(JSON.parse(fixture.storage.get('threatforest.oauth.tokens.v1')!).accessToken).toBe('access-token');
    expect(fixture.history.replaceState).toHaveBeenCalledWith(null, '', '/auth/callback');
  });

  it('deduplicates concurrent and repeated exchanges of the single-use authorization code', async () => {
    const fixture = browser();
    const { completeAuthorizationCodeFlow } = await import('./session');
    expect(await Promise.all([completeAuthorizationCodeFlow(), completeAuthorizationCodeFlow()])).toEqual([true, true]);
    expect(await completeAuthorizationCodeFlow()).toBe(true);
    expect(fixture.fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    'code=authorization-code',
    `state=${stateA}`,
    'code=authorization-code&state=invalid',
    `code=authorization-code&state=${stateA}&state=${stateB}`,
    `code=authorization-code&code=other&state=${stateA}`,
    `code=authorization-code&state=${stateA}&error=access_denied`,
    '',
  ])('rejects malformed callbacks before sending any code: %s', async (query) => {
    const fixture = browser(query);
    const { completeAuthorizationCodeFlow } = await import('./session');
    await expect(completeAuthorizationCodeFlow()).rejects.toThrow('invalid or expired');
    expect(fixture.fetch).not.toHaveBeenCalled();
  });

  it('never uses another attempt’s verifier when its own has expired', async () => {
    const fixture = browser();
    fixture.cookies.delete(`tf_pkce_verifier_${stateA}`);
    const { completeAuthorizationCodeFlow } = await import('./session');
    await expect(completeAuthorizationCodeFlow()).rejects.toThrow('missing its PKCE session');
    expect(fixture.fetch).not.toHaveBeenCalled();
    expect(fixture.cookies.get(`tf_pkce_verifier_${stateB}`)).toBe('verifier-B');
  });

  it('supports an edge-validated legacy login that started before deployment', async () => {
    const fixture = browser();
    fixture.cookies.delete(`tf_pkce_verifier_${stateA}`);
    fixture.cookies.set('tf_pkce_verifier', 'legacy-verifier');
    const { completeAuthorizationCodeFlow } = await import('./session');
    await completeAuthorizationCodeFlow();
    const parameters = new URLSearchParams(String(fixture.fetch.mock.calls[0]![1]!.body));
    expect(parameters.get('code_verifier')).toBe('legacy-verifier');
    expect(fixture.cookies.has('tf_pkce_verifier')).toBe(false);
  });

  it('does not establish a session or repeatedly exchange a rejected code', async () => {
    const fixture = browser();
    fixture.fetch.mockResolvedValue(new Response(null, { status: 400 }));
    const { completeAuthorizationCodeFlow } = await import('./session');
    await expect(completeAuthorizationCodeFlow()).rejects.toThrow('status 400');
    await expect(completeAuthorizationCodeFlow()).rejects.toThrow('status 400');
    expect(fixture.fetch).toHaveBeenCalledTimes(1);
    expect(fixture.cookies.has('tf_session')).toBe(false);
    expect(fixture.storage.size).toBe(0);
  });

  it('does not interpret application query parameters as authorization callbacks', async () => {
    const fixture = browser(`code=report-filter&state=${stateA}`, '/applications');
    const { completeAuthorizationCodeFlow } = await import('./session');
    expect(await completeAuthorizationCodeFlow()).toBe(false);
    expect(fixture.fetch).not.toHaveBeenCalled();
  });
});
