import type {
  ApplicationId,
  InteractionId,
  UserId,
} from '@threatforest/types';
import type { CognitoClaimRequirements } from './auth.js';
import {
  extractCognitoOwner,
  readHeader,
  verifyOriginSecret,
} from './auth.js';
import {
  ApplicationService,
  VersionService,
  applicationId,
} from './application-service.js';
import {
  badRequest,
  gone,
  mapError,
  notFound,
  payloadTooLarge,
  uriTooLong,
} from './errors.js';
import type {
  MutationContext,
  MutationResponseRecord,
  ReportPayload,
} from './contracts.js';
import { SettingsService } from './settings-service.js';
import { HitlService, RunService, runId } from './run-service.js';
import { UploadService, uploadId } from './upload-service.js';
import { ReplayTicketService } from './websocket.js';
import { RunObservabilityService } from './run-observability-service.js';
import {
  ReportImportService,
  reportImportId,
} from './report-import-service.js';

export interface ApiGatewayEvent {
  version?: string;
  rawPath?: string;
  path?: string;
  rawQueryString?: string;
  httpMethod?: string;
  headers?: Record<string, string | undefined> | null;
  queryStringParameters?: Record<string, string | undefined> | null;
  body?: string | null;
  isBase64Encoded?: boolean;
  requestContext?: {
    requestId?: string;
    http?: { method?: string; path?: string };
    authorizer?: {
      jwt?: { claims?: Record<string, unknown> };
      claims?: Record<string, unknown>;
      [key: string]: unknown;
    } | null;
    [key: string]: unknown;
  };
}

export interface ApiGatewayResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  isBase64Encoded?: boolean;
}

export interface HostedApiServices {
  applications: ApplicationService;
  versions: VersionService;
  settings: SettingsService;
  runs: RunService;
  observability: Pick<RunObservabilityService, 'list'>;
  hitl: HitlService;
  uploads: UploadService;
  imports: ReportImportService;
  tickets: ReplayTicketService;
}

export interface HttpHandlerLimits {
  maximumBodyBytes: number;
  maximumPathBytes: number;
  maximumPathSegments: number;
  maximumQueryParameters: number;
  maximumHeaders: number;
  maximumJsonDepth: number;
  maximumJsonNodes: number;
}

export interface HttpHandlerOptions {
  originSecret: string;
  services: HostedApiServices;
  cognito?: CognitoClaimRequirements;
  limits?: Partial<HttpHandlerLimits>;
}

interface Request {
  method: string;
  path: string;
  segments: string[];
  query: Record<string, string | undefined>;
  ownerId: UserId;
  requestId: string;
  event: ApiGatewayEvent;
  body(): unknown;
  mutation(): MutationContext;
}

const DEFAULT_LIMITS: HttpHandlerLimits = {
  maximumBodyBytes: 1024 * 1024,
  maximumPathBytes: 4096,
  maximumPathSegments: 20,
  maximumQueryParameters: 100,
  maximumHeaders: 100,
  maximumJsonDepth: 32,
  maximumJsonNodes: 50_000,
};

function eventMethod(event: ApiGatewayEvent): string {
  return (event.requestContext?.http?.method ?? event.httpMethod ?? '').toUpperCase();
}

function eventPath(event: ApiGatewayEvent): string {
  return event.rawPath ?? event.requestContext?.http?.path ?? event.path ?? '';
}

function decodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw badRequest('Request path contains invalid percent encoding.');
  }
}

function parseSegments(path: string, limits: HttpHandlerLimits): string[] {
  if (Buffer.byteLength(path) > limits.maximumPathBytes) {
    throw uriTooLong(`Request path exceeds ${limits.maximumPathBytes} bytes.`);
  }
  const raw = path.split('/').filter(Boolean);
  if (raw[0] === 'api') {
    raw.shift();
  }
  if (raw.length > limits.maximumPathSegments) {
    throw uriTooLong(`Request path exceeds ${limits.maximumPathSegments} segments.`);
  }
  const decoded = raw.map(decodeSegment);
  if (decoded.some((segment) => Buffer.byteLength(segment) > 4096)) {
    throw uriTooLong('A request path segment exceeds 4096 bytes.');
  }
  return decoded;
}

function validateJsonShape(
  value: unknown,
  limits: HttpHandlerLimits,
  depth = 0,
  counter = { nodes: 0 },
): void {
  counter.nodes += 1;
  if (counter.nodes > limits.maximumJsonNodes) {
    throw payloadTooLarge('JSON body contains too many values.');
  }
  if (depth > limits.maximumJsonDepth) {
    throw payloadTooLarge('JSON body is nested too deeply.');
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      validateJsonShape(item, limits, depth + 1, counter);
    }
  } else if (typeof value === 'object' && value !== null) {
    for (const item of Object.values(value)) {
      validateJsonShape(item, limits, depth + 1, counter);
    }
  }
}

function bodyParser(event: ApiGatewayEvent, limits: HttpHandlerLimits): () => unknown {
  let parsed = false;
  let cached: unknown = {};
  return () => {
    if (parsed) {
      return cached;
    }
    parsed = true;
    if (event.body === undefined || event.body === null || event.body === '') {
      return cached;
    }
    const bytes = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64')
      : Buffer.from(event.body, 'utf8');
    if (bytes.byteLength > limits.maximumBodyBytes) {
      throw payloadTooLarge(
        `Request body exceeds ${limits.maximumBodyBytes} bytes.`,
      );
    }
    try {
      cached = JSON.parse(bytes.toString('utf8')) as unknown;
    } catch {
      throw badRequest('Request body must contain valid JSON.');
    }
    validateJsonShape(cached, limits);
    return cached;
  };
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (['true', '1', 'yes', 'on'].includes(value.toLowerCase())) {
    return true;
  }
  if (['false', '0', 'no', 'off'].includes(value.toLowerCase())) {
    return false;
  }
  return fallback;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw badRequest('Request body must be a JSON object.');
  }
  return value as Record<string, unknown>;
}

function positiveRevision(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw badRequest('revision must be a positive integer.');
  }
  return value as number;
}

function success(
  statusCode: number,
  value: unknown,
  headers: Record<string, string> = {},
): ApiGatewayResponse {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
    body: JSON.stringify(value),
  };
}

function mutation(result: MutationResponseRecord): ApiGatewayResponse {
  return success(result.status, result.value, result.headers);
}

function report(payload: ReportPayload): ApiGatewayResponse {
  if (payload.redirectUrl !== undefined) {
    return {
      statusCode: 302,
      headers: {
        location: payload.redirectUrl,
        'cache-control': 'no-store',
      },
      body: '',
    };
  }
  if (payload.body === undefined) {
    throw new Error('report adapter returned neither body nor redirect URL');
  }
  return {
    statusCode: 200,
    headers: {
      'content-type': payload.contentType,
      'content-disposition': `attachment; filename="${payload.filename.replaceAll('"', '')}"`,
      'cache-control': 'no-store',
    },
    body: Buffer.from(payload.body).toString('base64'),
    isBase64Encoded: true,
  };
}

function hostedOnly(localFeature: string, replacement: string): never {
  throw gone(
    `${localFeature} is unavailable in hosted mode. ${replacement}`,
    'filesystem_endpoint_unavailable',
  );
}

function configApplicationId(request: Request): ApplicationId | undefined {
  const value =
    readHeader(request.event, 'x-threatforest-application-id') ??
    request.query.application_id;
  return value === undefined || value === '' ? undefined : applicationId(value);
}

function hitlInteractionId(value: string): InteractionId {
  return value as InteractionId;
}

async function route(
  request: Request,
  services: HostedApiServices,
): Promise<ApiGatewayResponse> {
  const { segments: s, method } = request;

  if (method === 'GET' && s.length === 1 && s[0] === 'health') {
    return success(200, { status: 'ok' });
  }

  if (s[0] === 'filesystem') {
    hostedOnly(
      'Server filesystem browsing and native directory selection',
      'Create an application and use its upload-session endpoints.',
    );
  }
  if (s[0] === 'imports') {
    if (s.length === 2 && s[1] === 'info' && method === 'GET') {
      return success(200, await services.imports.info(request.ownerId));
    }
    if (s[1] === 'tfreport') {
      if (s.length === 2 && method === 'POST') {
        return mutation(
          await services.imports.create(request.mutation(), request.body()),
        );
      }
      if (s.length >= 3) {
        const importId = reportImportId(s[2]);
        if (s.length === 3 && method === 'GET') {
          const session = await services.imports.get(
            request.ownerId,
            importId,
          );
          return success(200, {
            import_id: session.importId,
            status: session.status,
            filename: session.filename,
            size_bytes: session.sizeBytes,
            result: session.result,
            failure_code: session.failureCode,
            created_at: session.createdAt,
            updated_at: session.updatedAt,
          });
        }
        if (s.length === 3 && method === 'DELETE') {
          return mutation(
            await services.imports.abort(request.mutation(), importId),
          );
        }
        if (s.length === 4 && s[3] === 'parts' && method === 'POST') {
          return mutation(
            await services.imports.presignPart(
              request.mutation(),
              importId,
              request.body(),
            ),
          );
        }
        if (s.length === 4 && s[3] === 'complete' && method === 'POST') {
          return mutation(
            await services.imports.complete(
              request.mutation(),
              importId,
              request.body(),
            ),
          );
        }
      }
    }
  }
  if (s[0] === 'test') {
    hostedOnly('Local development test routes', 'Use the deployed test suite.');
  }

  if (s[0] === 'config') {
    const appId = configApplicationId(request);
    if (s.length === 1 && method === 'GET') {
      return success(200, await services.settings.getConfig(request.ownerId, appId));
    }
    if (s.length === 2 && s[1] === 'providers' && method === 'GET') {
      return success(200, await services.settings.providers());
    }
    if (s.length === 2 && s[1] === 'frameworks' && method === 'GET') {
      return success(200, await services.settings.frameworks());
    }
    if (
      s.length === 3 &&
      s[1] === 'bedrock' &&
      s[2] === 'models' &&
      method === 'GET'
    ) {
      return success(
        200,
        await services.settings.models(
          request.query.region,
          bool(request.query.refresh, false),
        ),
      );
    }
    if (s.length === 2 && s[1] === 'test' && method === 'POST') {
      return success(
        200,
        await services.settings.test(request.ownerId, request.body()),
      );
    }
    if (s.length === 2 && s[1] === 'save' && method === 'POST') {
      return mutation(
        await services.settings.saveConfig(request.mutation(), appId, request.body()),
      );
    }
    if (s[1] === 'langfuse') {
      throw gone(
        'Langfuse environment configuration is local-only. Hosted tracing is managed by AgentCore and CloudWatch.',
        'hosted_observability_managed',
      );
    }
  }

  if (s[0] === 'applications') {
    if (s.length === 1 && method === 'GET') {
      return success(200, await services.applications.list(request.ownerId));
    }
    if (s.length === 1 && method === 'POST') {
      return mutation(
        await services.applications.create(request.mutation(), request.body()),
      );
    }
    if (s[1] === 'by-id' && s.length >= 3) {
      const appId = applicationId(s[2]);
      if (s.length === 3 && method === 'GET') {
        return success(200, await services.applications.get(request.ownerId, appId));
      }
      if (s.length === 3 && method === 'PATCH') {
        return mutation(
          await services.applications.update(
            request.mutation(),
            appId,
            request.body(),
          ),
        );
      }
      if (s.length === 3 && method === 'DELETE') {
        return mutation(
          await services.applications.delete(request.mutation(), appId),
        );
      }
    }
    if (s.length >= 2) {
      const appId = applicationId(s[1]);
      if (s.length === 3 && s[2] === 'sources' && method === 'GET') {
        return success(200, await services.runs.sources(request.ownerId, appId));
      }
      if (s.length === 2 && method === 'DELETE') {
        return mutation(
          await services.applications.delete(request.mutation(), appId),
        );
      }
      if (s[2] === 'uploads') {
        if (s.length === 3 && method === 'POST') {
          return mutation(
            await services.uploads.create(request.mutation(), appId, request.body()),
          );
        }
        if (s.length >= 4) {
          const id = uploadId(s[3]);
          if (s.length === 4 && method === 'GET') {
            const session = await services.uploads.get(request.ownerId, appId, id);
            return success(200, { upload_id: id, manifest: session.manifest });
          }
          if (s.length === 4 && method === 'DELETE') {
            return mutation(
              await services.uploads.abort(request.mutation(), appId, id),
            );
          }
          if (s.length === 5 && s[4] === 'parts' && method === 'POST') {
            return mutation(
              await services.uploads.presignPart(
                request.mutation(),
                appId,
                id,
                request.body(),
              ),
            );
          }
          if (s.length === 5 && s[4] === 'complete' && method === 'POST') {
            return mutation(
              await services.uploads.complete(
                request.mutation(),
                appId,
                id,
                request.body(),
              ),
            );
          }
        }
      }
      if (s[2] === 'versions') {
        if (s.length === 3 && method === 'GET') {
          return success(200, await services.versions.list(request.ownerId, appId));
        }
        if (s.length >= 4) {
          const versionId = s[3]!;
          if (s.length === 4 && method === 'DELETE') {
            return mutation(
              await services.versions.remove(request.mutation(), appId, versionId),
            );
          }
          if (s.length === 5 && s[4] === 'data' && method === 'GET') {
            return success(
              200,
              await services.versions.data(request.ownerId, appId, versionId),
            );
          }
          if (s.length === 5 && s[4] === 'report' && method === 'GET') {
            return report(
              await services.versions.report(
                request.ownerId,
                appId,
                versionId,
                bool(request.query.include_scanner_context, true),
              ),
            );
          }
          if (
            s.length === 6 &&
            s[4] === 'report' &&
            s[5] === 'metadata' &&
            method === 'GET'
          ) {
            const payload = await services.versions.report(
              request.ownerId,
              appId,
              versionId,
              bool(request.query.include_scanner_context, true),
            );
            return success(200, { report: payload.metadata });
          }
          if (s[4] === 'mitigation-overrides') {
            if (s.length === 5 && method === 'GET') {
              return success(
                200,
                await services.versions.overrides(
                  request.ownerId,
                  appId,
                  versionId,
                ),
              );
            }
            const key = s.slice(5).join('/');
            if (s.length >= 6 && method === 'PUT') {
              return mutation(
                await services.versions.setOverride(
                  request.mutation(),
                  appId,
                  versionId,
                  key,
                  request.body(),
                ),
              );
            }
            if (s.length >= 6 && method === 'DELETE') {
              return mutation(
                await services.versions.clearOverride(
                  request.mutation(),
                  appId,
                  versionId,
                  key,
                ),
              );
            }
          }
        }
      }
      if (s.length === 3 && s[2] === 'report' && method === 'GET') {
        return report(
          await services.versions.report(
            request.ownerId,
            appId,
            null,
            bool(request.query.include_scanner_context, true),
          ),
        );
      }
      if (
        s.length === 4 &&
        s[2] === 'report' &&
        s[3] === 'metadata' &&
        method === 'GET'
      ) {
        const payload = await services.versions.report(
          request.ownerId,
          appId,
          null,
          bool(request.query.include_scanner_context, true),
        );
        return success(200, { report: payload.metadata });
      }
    }
  }

  if (s[0] === 'runs') {
    if (s.length === 1 && method === 'GET') {
      const statuses =
        request.query.status === undefined
          ? undefined
          : new Set(request.query.status.split(',').map((value) => value.trim()));
      return success(200, await services.runs.list(request.ownerId, statuses));
    }
    if (s.length === 1 && method === 'POST') {
      return mutation(await services.runs.create(request.mutation(), request.body()));
    }
    if (s.length >= 2) {
      const id = runId(s[1]);
      if (s.length === 2 && method === 'GET') {
        return success(200, (await services.runs.get(request.ownerId, id)).state);
      }
      if (s.length === 3 && s[2] === 'logs' && method === 'GET') {
        return success(
          200,
          await services.observability.list(request.ownerId, id, {
            ...(request.query.since ? { since: request.query.since } : {}),
            ...(request.query.until ? { until: request.query.until } : {}),
            ...(request.query.next_token
              ? { nextToken: request.query.next_token }
              : {}),
          }),
        );
      }
      if (
        s.length === 3 &&
        (s[2] === 'pause' || s[2] === 'stop') &&
        method === 'POST'
      ) {
        return mutation(
          await services.runs.control(request.mutation(), id, s[2]),
        );
      }
      if (s.length === 3 && s[2] === 'resume' && method === 'POST') {
        return mutation(await services.runs.resume(request.mutation(), id));
      }
      if (s.length === 3 && s[2] === 'respond' && method === 'POST') {
        const body = object(request.body());
        const text = body.text;
        if (text !== null && typeof text !== 'string') {
          throw badRequest('text must be a string or null.');
        }
        return mutation(
          await services.hitl.respondLegacy(
            request.mutation(),
            id,
            text as string | null,
          ),
        );
      }
      if (s.length === 3 && s[2] === 'interactions' && method === 'GET') {
        return success(200, {
          interactions: await services.hitl.pending(request.ownerId, id),
        });
      }
      if (
        s.length === 5 &&
        s[2] === 'interactions' &&
        (s[4] === 'respond' || s[4] === 'skip') &&
        method === 'POST'
      ) {
        const body = object(request.body());
        const action = s[4] === 'skip' ? 'skip' : 'submit';
        const text = action === 'skip' ? null : body.text;
        if (text !== null && typeof text !== 'string') {
          throw badRequest('text must be a string.');
        }
        return mutation(
          await services.hitl.respond(
            request.mutation(),
            id,
            hitlInteractionId(s[3]!),
            positiveRevision(body.revision),
            action,
            text as string | null,
          ),
        );
      }
      if (s.length === 3 && s[2] === 'replay-ticket' && method === 'POST') {
        const body = object(request.body());
        const afterSequence = body.after_sequence;
        if (
          !Number.isSafeInteger(afterSequence) ||
          (afterSequence as number) < -1
        ) {
          throw badRequest(
            'after_sequence must be an integer greater than or equal to -1.',
          );
        }
        return success(
          200,
          await services.tickets.issue(
            request.ownerId,
            id,
            afterSequence as number,
          ),
        );
      }
    }
  }

  if (s[0] === 'paused-runs') {
    if (s.length === 1 && method === 'GET') {
      const runs = await services.runs.list(request.ownerId, new Set(['paused']));
      return success(200, {
        paused_runs: runs.runs.map((run) => ({
          app_id: run.config.app_id,
          app_name: run.config.app_id,
          paused_at: run.paused_at ?? run.started_at,
          paused_at_stage: run.paused_at_stage,
          run_id: run.run_id,
        })),
      });
    }
    if (s.length === 2 && method === 'DELETE') {
      throw gone(
        'Hosted paused runs are durable and cannot be cleared as local files. Resume or stop the run instead.',
        'durable_run_cannot_be_deleted',
      );
    }
  }

  throw notFound(`No route for ${method} /api/${s.join('/')}.`);
}

export function createHttpHandler(options: HttpHandlerOptions) {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  return async (event: ApiGatewayEvent): Promise<ApiGatewayResponse> => {
    const requestId =
      event.requestContext?.requestId ??
      `local-${Date.now().toString(36)}`;
    try {
      if (Object.keys(event.headers ?? {}).length > limits.maximumHeaders) {
        throw payloadTooLarge(`Request has more than ${limits.maximumHeaders} headers.`);
      }
      if (
        Object.keys(event.queryStringParameters ?? {}).length >
        limits.maximumQueryParameters
      ) {
        throw uriTooLong(
          `Request has more than ${limits.maximumQueryParameters} query parameters.`,
        );
      }
      verifyOriginSecret(event, options.originSecret);
      const ownerId = extractCognitoOwner(event, options.cognito);
      const method = eventMethod(event);
      if (!['GET', 'POST', 'PATCH', 'PUT', 'DELETE'].includes(method)) {
        throw badRequest('Unsupported HTTP method.');
      }
      const path = eventPath(event);
      const segments = parseSegments(path, limits);
      const parseBody = bodyParser(event, limits);
      const idempotencyKey =
        readHeader(event, 'idempotency-key') ?? `request:${requestId}`;
      const request: Request = {
        method,
        path,
        segments,
        query: event.queryStringParameters ?? {},
        ownerId,
        requestId,
        event,
        body: parseBody,
        mutation: () => ({ ownerId, idempotencyKey }),
      };
      const response = await route(request, options.services);
      if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(method)) {
        response.headers['idempotency-key'] = idempotencyKey;
      }
      response.headers['x-request-id'] = requestId;
      return response;
    } catch (error) {
      const mapped = mapError(error);
      return {
        statusCode: mapped.status,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'x-request-id': requestId,
        },
        body: JSON.stringify({
          detail: mapped.expose ? mapped.message : 'Internal server error.',
          code: mapped.code,
          request_id: requestId,
        }),
      };
    }
  };
}
