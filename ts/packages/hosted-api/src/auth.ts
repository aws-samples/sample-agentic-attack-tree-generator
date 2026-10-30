import { timingSafeEqual } from 'node:crypto';
import { UserIdSchema, type UserId } from '@threatforest/types';
import { forbidden, unauthorized } from './errors.js';

type Claims = Record<string, unknown>;

export interface AuthorizerContext {
  jwt?: { claims?: Claims };
  claims?: Claims;
  [key: string]: unknown;
}

export interface AuthEvent {
  headers?: Record<string, string | undefined> | null;
  requestContext?: {
    authorizer?: AuthorizerContext | null;
    [key: string]: unknown;
  };
}

export interface CognitoClaimRequirements {
  issuer?: string;
  audience?: string;
}

function claimsFrom(event: AuthEvent): Claims {
  const authorizer = event.requestContext?.authorizer;
  const claims = authorizer?.jwt?.claims ?? authorizer?.claims;
  if (claims === undefined || claims === null || typeof claims !== 'object') {
    throw unauthorized();
  }
  return claims;
}

function exactClaim(claims: Claims, name: string, expected: string): void {
  const value = claims[name];
  const values = Array.isArray(value) ? value : [value];
  if (!values.some((candidate) => candidate === expected)) {
    throw unauthorized('The Cognito token claims are not valid for this API.');
  }
}

export function extractCognitoOwner(
  event: AuthEvent,
  requirements: CognitoClaimRequirements = {},
): UserId {
  const claims = claimsFrom(event);
  const parsed = UserIdSchema.safeParse(claims.sub);
  if (!parsed.success) {
    throw unauthorized('The Cognito authorizer did not provide a valid sub claim.');
  }
  if (requirements.issuer !== undefined) {
    exactClaim(claims, 'iss', requirements.issuer);
  }
  if (requirements.audience !== undefined) {
    const audience = claims.aud ?? claims.client_id;
    exactClaim({ audience }, 'audience', requirements.audience);
  }
  return parsed.data;
}

function header(
  headers: Record<string, string | undefined> | null | undefined,
  name: string,
): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

function equalSecret(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  return (
    actualBytes.length === expectedBytes.length &&
    timingSafeEqual(actualBytes, expectedBytes)
  );
}

export function verifyOriginSecret(
  event: AuthEvent,
  expectedSecret: string,
  headerName = 'x-threatforest-origin-verify',
): void {
  if (expectedSecret.length < 16) {
    throw new Error('origin verification secret must contain at least 16 characters');
  }
  const actual = header(event.headers, headerName);
  if (actual === undefined || !equalSecret(actual, expectedSecret)) {
    throw forbidden();
  }
}

export function readHeader(event: AuthEvent, name: string): string | undefined {
  return header(event.headers, name);
}
