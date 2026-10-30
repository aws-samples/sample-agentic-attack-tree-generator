'use client';

const STORAGE_KEY = 'threatforest.oauth.tokens.v1';
const SESSION_COOKIE = 'tf_session';
const CLIENT_COOKIE = 'tf_oauth_client';
const DOMAIN_COOKIE = 'tf_oauth_domain';
const VERIFIER_COOKIE = 'tf_pkce_verifier';

interface OAuthConfig {
  clientId: string;
  managedLoginBaseUrl: string;
}

interface CognitoTokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

interface StoredTokens {
  accessToken: string;
  idToken: string | null;
  refreshToken: string | null;
  expiresAt: number;
  tokenType: string;
}

let refreshInFlight: Promise<StoredTokens | null> | null = null;
let authorizationInFlight: Promise<boolean> | null = null;

export function parseCookies(cookieHeader: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) out[name] = value;
  }
  return out;
}

function browserCookies(): Record<string, string> {
  return typeof document === 'undefined' ? {} : parseCookies(document.cookie);
}

function oauthConfig(): OAuthConfig | null {
  const cookies = browserCookies();
  const clientId = cookies[CLIENT_COOKIE];
  const encodedDomain = cookies[DOMAIN_COOKIE];
  if (!clientId || !encodedDomain) return null;
  try {
    const managedLoginBaseUrl = decodeURIComponent(encodedDomain);
    const parsed = new URL(managedLoginBaseUrl);
    if (parsed.protocol !== 'https:') return null;
    return { clientId, managedLoginBaseUrl: parsed.origin };
  } catch {
    return null;
  }
}

function loadTokens(): StoredTokens | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredTokens;
    if (
      !parsed.accessToken ||
      !Number.isFinite(parsed.expiresAt) ||
      !parsed.tokenType
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function storeTokens(response: CognitoTokenResponse, previous?: StoredTokens | null): StoredTokens {
  const stored: StoredTokens = {
    accessToken: response.access_token,
    idToken: response.id_token ?? previous?.idToken ?? null,
    refreshToken: response.refresh_token ?? previous?.refreshToken ?? null,
    expiresAt: Date.now() + Math.max(1, response.expires_in) * 1000,
    tokenType: response.token_type || 'Bearer',
  };
  window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
  return stored;
}

async function tokenRequest(
  config: OAuthConfig,
  parameters: URLSearchParams,
  previous?: StoredTokens | null,
): Promise<StoredTokens> {
  const response = await fetch(`${config.managedLoginBaseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: parameters.toString(),
    credentials: 'omit',
  });
  if (!response.ok) {
    throw new Error(`Cognito token exchange failed with status ${response.status}`);
  }
  return storeTokens((await response.json()) as CognitoTokenResponse, previous);
}

export async function completeAuthorizationCodeFlow(): Promise<boolean> {
  if (typeof window === 'undefined') return false;
  const url = new URL(window.location.href);
  if (!['/auth/callback', '/auth/callback/', '/auth/callback/index.html'].includes(url.pathname)) {
    return false;
  }
  // React can mount the boundary twice. Authorization codes are single-use.
  authorizationInFlight ??= exchangeAuthorizationCode(url);
  return authorizationInFlight;
}

async function exchangeAuthorizationCode(url: URL): Promise<boolean> {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state || !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      url.searchParams.getAll('code').length !== 1 ||
      url.searchParams.getAll('state').length !== 1 || url.searchParams.has('error')) {
    throw new Error('The Cognito callback is invalid or expired');
  }

  const config = oauthConfig();
  const cookies = browserCookies();
  const scopedVerifier = `${VERIFIER_COOKIE}_${state}`;
  // In-flight logins issued by the previous edge deployment retain their verifier.
  // The edge validates the matching HttpOnly state cookie before serving this page.
  const verifierCookie = cookies[scopedVerifier] ? scopedVerifier : VERIFIER_COOKIE;
  const verifier = cookies[verifierCookie];
  if (!config || !verifier) {
    throw new Error('The Cognito callback is missing its PKCE session');
  }

  await tokenRequest(
    config,
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.clientId,
      code,
      code_verifier: verifier,
      redirect_uri: `${window.location.origin}/auth/callback`,
    }),
  );
  document.cookie = `${SESSION_COOKIE}=1; Secure; Path=/; SameSite=Lax; Max-Age=3600`;
  document.cookie = `${verifierCookie}=; Secure; Path=/; SameSite=Lax; Max-Age=0`;
  window.history.replaceState(null, '', '/auth/callback');
  return true;
}

async function refreshTokens(current: StoredTokens): Promise<StoredTokens | null> {
  const config = oauthConfig();
  if (!config || !current.refreshToken) return null;
  try {
    return await tokenRequest(
      config,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: config.clientId,
        refresh_token: current.refreshToken,
      }),
      current,
    );
  } catch {
    clearAuthSession();
    return null;
  }
}

export async function getAccessToken(forceRefresh = false): Promise<string | null> {
  if (typeof window === 'undefined') return null;
  const current = loadTokens();
  if (!current) return null;
  if (!forceRefresh && current.expiresAt > Date.now() + 60_000) {
    return current.accessToken;
  }
  refreshInFlight ??= refreshTokens(current).finally(() => {
    refreshInFlight = null;
  });
  return (await refreshInFlight)?.accessToken ?? null;
}

export function clearAuthSession(): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.removeItem(STORAGE_KEY);
  document.cookie = `${SESSION_COOKIE}=; Secure; Path=/; SameSite=Lax; Max-Age=0`;
}

export function beginLogout(): void {
  clearAuthSession();
  window.location.assign('/auth/logout');
}
