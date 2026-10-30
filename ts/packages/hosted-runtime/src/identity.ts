import { UserIdSchema, type ApplicationId, type UserId } from '@threatforest/types';
import type {
  ActorIdDeriver,
  AuthenticatedPrincipal,
  PrincipalResolver,
  RuntimeHttpRequest,
} from './contracts.js';
import { isRecord, sha256 } from './util.js';

export class AuthenticationError extends Error {
  constructor(message = 'authentication is required') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export interface VerifiedCognitoPrincipalResolverOptions {
  expectedIssuer?: string;
  /**
   * Only configure this when the ingress removes caller-supplied values and
   * injects the header from a verified Cognito token.
   */
  trustedSubjectHeader?: string;
  trustedIssuerHeader?: string;
  claimsExtractor?: (request: RuntimeHttpRequest) => unknown;
}

function headerValue(
  headers: RuntimeHttpRequest['headers'],
  requestedName: string | undefined,
): string | undefined {
  if (headers === undefined || requestedName === undefined) {
    return undefined;
  }
  const name = requestedName.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) {
      continue;
    }
    return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

function contextClaims(request: RuntimeHttpRequest): unknown {
  if (!isRecord(request.context)) {
    return undefined;
  }
  if (isRecord(request.context['verifiedClaims'])) {
    return request.context['verifiedClaims'];
  }
  const authorizer = request.context['authorizer'];
  if (isRecord(authorizer)) {
    const jwt = authorizer['jwt'];
    if (isRecord(jwt) && isRecord(jwt['claims'])) {
      return jwt['claims'];
    }
    if (isRecord(authorizer['claims'])) {
      return authorizer['claims'];
    }
  }
  const principal = request.context['principal'];
  if (isRecord(principal) && isRecord(principal['claims'])) {
    return principal['claims'];
  }
  return undefined;
}

function opaqueUserId(issuer: string, subject: string): UserId {
  return UserIdSchema.parse(`cog_${sha256(`${issuer}\0${subject}`).slice(0, 48)}`);
}

/**
 * Resolves only claims already verified by the hosting layer. It deliberately
 * does not decode or trust Authorization JWT payloads.
 */
export class VerifiedCognitoPrincipalResolver implements PrincipalResolver {
  readonly #options: VerifiedCognitoPrincipalResolverOptions;

  constructor(options: VerifiedCognitoPrincipalResolverOptions = {}) {
    this.#options = options;
  }

  async resolve(request: RuntimeHttpRequest): Promise<AuthenticatedPrincipal> {
    const extracted = (this.#options.claimsExtractor ?? contextClaims)(request);
    const claims = isRecord(extracted) ? extracted : {};
    const headerSubject = headerValue(request.headers, this.#options.trustedSubjectHeader);
    const headerIssuer = headerValue(request.headers, this.#options.trustedIssuerHeader);
    const subject = typeof claims['sub'] === 'string' ? claims['sub'] : headerSubject;
    const issuer =
      typeof claims['iss'] === 'string'
        ? claims['iss']
        : (headerIssuer ?? this.#options.expectedIssuer ?? '');

    if (subject === undefined || subject.length === 0 || issuer.length === 0) {
      throw new AuthenticationError();
    }
    if (this.#options.expectedIssuer !== undefined && issuer !== this.#options.expectedIssuer) {
      throw new AuthenticationError('the verified token issuer is not trusted');
    }

    return {
      subject,
      issuer,
      userId: opaqueUserId(issuer, subject),
      claims: Object.freeze({ ...claims, sub: subject, iss: issuer }),
    };
  }
}

interface CognitoTokenVerifier {
  verify(token: string): Promise<unknown>;
}

interface CognitoJwtVerifyModule {
  CognitoJwtVerifier: {
    create(options: {
      userPoolId: string;
      clientId: string | readonly string[];
      tokenUse: 'id' | 'access';
    }): CognitoTokenVerifier;
  };
}

export interface CognitoJwtPrincipalResolverOptions {
  userPoolId: string;
  clientId: string | readonly string[];
  tokenUse?: 'id' | 'access';
  verifier?: CognitoTokenVerifier;
}

function bearerToken(request: RuntimeHttpRequest): string {
  const authorization = headerValue(request.headers, 'authorization');
  if (authorization === undefined) {
    throw new AuthenticationError();
  }
  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  if (match?.[1] === undefined) {
    throw new AuthenticationError('Authorization must contain one Bearer token');
  }
  return match[1];
}

/**
 * Production resolver for AgentCore's forwarded Authorization header. It
 * verifies signature, issuer, expiry, token use, and app client before using
 * any claim.
 */
export class CognitoJwtPrincipalResolver implements PrincipalResolver {
  readonly #verifier: CognitoTokenVerifier;

  private constructor(verifier: CognitoTokenVerifier) {
    this.#verifier = verifier;
  }

  static async create(
    options: CognitoJwtPrincipalResolverOptions,
  ): Promise<CognitoJwtPrincipalResolver> {
    let verifier = options.verifier;
    if (verifier === undefined) {
      const packageName: string = 'aws-jwt-verify';
      const module = (await import(packageName)) as unknown as CognitoJwtVerifyModule;
      verifier = module.CognitoJwtVerifier.create({
        userPoolId: options.userPoolId,
        clientId: options.clientId,
        tokenUse: options.tokenUse ?? 'access',
      });
    }
    return new CognitoJwtPrincipalResolver(verifier);
  }

  async resolve(request: RuntimeHttpRequest): Promise<AuthenticatedPrincipal> {
    let verified: unknown;
    try {
      verified = await this.#verifier.verify(bearerToken(request));
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError('Cognito token verification failed');
    }
    if (!isRecord(verified)) {
      throw new AuthenticationError('verified Cognito claims are invalid');
    }
    const subject = verified['sub'];
    const issuer = verified['iss'];
    if (typeof subject !== 'string' || typeof issuer !== 'string') {
      throw new AuthenticationError('verified Cognito token is missing sub or iss');
    }
    return {
      subject,
      issuer,
      userId: opaqueUserId(issuer, subject),
      claims: Object.freeze({ ...verified }),
    };
  }
}

export interface AgentCoreRuntimeUserPrincipalResolverOptions {
  trustedIssuer?: string;
  headerName?: string;
}

/**
 * Resolves the upstream user ID passed by the trusted IAM-authorized
 * dispatcher through AgentCore's custom-header allowlist. Arbitrary payload
 * fields are never accepted as identity.
 */
export class AgentCoreRuntimeUserPrincipalResolver
  implements PrincipalResolver
{
  readonly #issuer: string;
  readonly #headerName: string;

  constructor(options: AgentCoreRuntimeUserPrincipalResolverOptions = {}) {
    this.#issuer =
      options.trustedIssuer ?? 'urn:threatforest:cognito-upstream';
    this.#headerName =
      options.headerName ??
      'x-amzn-bedrock-agentcore-runtime-custom-userid';
  }

  async resolve(
    request: RuntimeHttpRequest,
  ): Promise<AuthenticatedPrincipal> {
    const raw = headerValue(request.headers, this.#headerName);
    const parsed = UserIdSchema.safeParse(raw);
    if (!parsed.success) {
      throw new AuthenticationError(
        'AgentCore did not provide a valid trusted runtime user ID',
      );
    }
    return {
      subject: parsed.data,
      issuer: this.#issuer,
      userId: parsed.data,
      claims: Object.freeze({
        sub: parsed.data,
        iss: this.#issuer,
        identity_source: 'agentcore-runtime-custom-user-id',
      }),
    };
  }
}

export interface GenerateMacInput {
  keyId: string;
  message: Uint8Array;
  algorithm: 'HMAC_SHA_256';
}

export interface GenerateMacClient {
  generateMac(input: GenerateMacInput): Promise<Uint8Array>;
}

export interface KmsHmacActorIdDeriverOptions {
  keyId: string;
  client: GenerateMacClient;
  prefix?: string;
}

export class KmsHmacActorIdDeriver implements ActorIdDeriver {
  readonly #keyId: string;
  readonly #client: GenerateMacClient;
  readonly #prefix: string;

  constructor(options: KmsHmacActorIdDeriverOptions) {
    this.#keyId = options.keyId;
    this.#client = options.client;
    this.#prefix = options.prefix ?? 'tf_';
  }

  async deriveActorId(
    principal: AuthenticatedPrincipal,
    applicationId: ApplicationId,
  ): Promise<string> {
    const message = new TextEncoder().encode(
      `threatforest-agentcore-actor-v1\0${principal.issuer}\0${principal.subject}\0${applicationId}`,
    );
    const mac = await this.#client.generateMac({
      keyId: this.#keyId,
      message,
      algorithm: 'HMAC_SHA_256',
    });
    if (mac.byteLength < 32) {
      throw new Error('KMS GenerateMac returned an invalid HMAC');
    }
    return `${this.#prefix}${Buffer.from(mac).toString('base64url')}`;
  }
}
