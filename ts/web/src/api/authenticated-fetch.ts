import { getAccessToken } from '../auth/session';

interface AuthenticatedFetchDependencies {
  readonly fetch: typeof globalThis.fetch;
  readonly getAccessToken: (forceRefresh?: boolean) => Promise<string | null>;
}

const defaultDependencies: AuthenticatedFetchDependencies = {
  fetch: (...args) => globalThis.fetch(...args),
  getAccessToken,
};

/**
 * Adds the current Cognito bearer token and retries once after a 401 with a
 * forced token refresh. The caller still owns response parsing and errors.
 */
export async function authenticatedFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
  dependencies: AuthenticatedFetchDependencies = defaultDependencies,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  const accessToken = await dependencies.getAccessToken();
  if (accessToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const response = await dependencies.fetch(input, { ...init, headers });
  if (response.status !== 401 || !accessToken) {
    return response;
  }

  const refreshed = await dependencies.getAccessToken(true);
  if (!refreshed) {
    return response;
  }
  headers.set('Authorization', `Bearer ${refreshed}`);
  return dependencies.fetch(input, { ...init, headers });
}
