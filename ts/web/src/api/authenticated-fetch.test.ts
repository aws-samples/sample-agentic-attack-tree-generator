import { describe, expect, it, vi } from 'vitest';

import { authenticatedFetch } from './authenticated-fetch.js';

function response(status: number): Response {
  return new Response(null, { status });
}

describe('authenticatedFetch', () => {
  it('adds the current bearer token without losing caller headers', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(response(200));
    const getAccessToken = vi.fn(async () => 'access-token');

    await authenticatedFetch(
      '/api/applications',
      { headers: { Accept: 'application/json' } },
      { fetch, getAccessToken },
    );

    expect(fetch).toHaveBeenCalledTimes(1);
    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('Accept')).toBe('application/json');
    expect(headers.get('Authorization')).toBe('Bearer access-token');
    expect(getAccessToken).toHaveBeenCalledWith();
  });

  it('refreshes after one 401 and retries exactly once', async () => {
    const seenAuthorizations: Array<string | null> = [];
    const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(
      async (_input, init) => {
        seenAuthorizations.push(
          new Headers(init?.headers).get('Authorization'),
        );
        return response(seenAuthorizations.length === 1 ? 401 : 200);
      },
    );
    const getAccessToken = vi
      .fn<(forceRefresh?: boolean) => Promise<string | null>>()
      .mockResolvedValueOnce('expired-token')
      .mockResolvedValueOnce('fresh-token');

    const result = await authenticatedFetch('/api/report', undefined, {
      fetch,
      getAccessToken,
    });

    expect(result.status).toBe(200);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(getAccessToken).toHaveBeenNthCalledWith(2, true);
    expect(seenAuthorizations).toEqual([
      'Bearer expired-token',
      'Bearer fresh-token',
    ]);
  });

  it('does not retry when no authenticated session exists', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(response(401));
    const getAccessToken = vi.fn(async () => null);

    const result = await authenticatedFetch('/api/report', undefined, {
      fetch,
      getAccessToken,
    });

    expect(result.status).toBe(401);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(getAccessToken).toHaveBeenCalledTimes(1);
  });

  it('preserves an explicit authorization header on the first request', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(response(200));
    const getAccessToken = vi.fn(async () => 'session-token');

    await authenticatedFetch(
      '/api/applications',
      { headers: { Authorization: 'Bearer explicit-token' } },
      { fetch, getAccessToken },
    );

    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer explicit-token');
  });
});
