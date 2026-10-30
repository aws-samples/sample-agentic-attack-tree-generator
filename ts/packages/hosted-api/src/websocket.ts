import {
  createHmac,
  timingSafeEqual,
} from 'node:crypto';
import type {
  ApplicationId,
  HostedProgressEvent,
  RunId,
  UserId,
} from '@threatforest/types';
import { extractCognitoOwner, verifyOriginSecret, type CognitoClaimRequirements } from './auth.js';
import {
  badRequest,
  mapError,
  unauthorized,
  unprocessable,
} from './errors.js';
import type {
  Clock,
  ConnectionAdapter,
  EventAdapter,
  IdFactory,
  WebSocketConnection,
} from './contracts.js';
import { RunService } from './run-service.js';
import { asRunId } from './runtime.js';

interface ReplayTicketPayload {
  version: 1;
  subject: UserId;
  applicationId: ApplicationId;
  runId: RunId;
  ticketId: string;
  afterSequence: number;
  issuedAt: number;
  expiresAt: number;
}

export interface ReplayTicket {
  ticket: string;
  expires_at: string;
}

export interface ReplayTicketServiceOptions {
  secret: string;
  runs: RunService;
  ids: IdFactory;
  clock: Clock;
  lifetimeSeconds?: number;
}

function signature(secret: string, payload: string): Buffer {
  return createHmac('sha256', secret).update(payload).digest();
}

function decodeJsonPayload(encoded: string): ReplayTicketPayload {
  if (encoded.length > 4096) {
    throw unauthorized('Replay ticket is invalid.');
  }
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw unauthorized('Replay ticket is invalid.');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw unauthorized('Replay ticket is invalid.');
  }
  const candidate = value as Partial<ReplayTicketPayload>;
  if (
    candidate.version !== 1 ||
    typeof candidate.subject !== 'string' ||
    typeof candidate.applicationId !== 'string' ||
    typeof candidate.runId !== 'string' ||
    typeof candidate.ticketId !== 'string' ||
    !Number.isSafeInteger(candidate.afterSequence) ||
    (candidate.afterSequence as number) < -1 ||
    !Number.isSafeInteger(candidate.issuedAt) ||
    !Number.isSafeInteger(candidate.expiresAt)
  ) {
    throw unauthorized('Replay ticket is invalid.');
  }
  return candidate as ReplayTicketPayload;
}

export class ReplayTicketService {
  readonly #secret: string;
  readonly #runs: RunService;
  readonly #ids: IdFactory;
  readonly #clock: Clock;
  readonly #lifetimeSeconds: number;

  constructor(options: ReplayTicketServiceOptions) {
    if (Buffer.byteLength(options.secret) < 32) {
      throw new Error('replay ticket secret must contain at least 32 bytes');
    }
    this.#secret = options.secret;
    this.#runs = options.runs;
    this.#ids = options.ids;
    this.#clock = options.clock;
    this.#lifetimeSeconds = options.lifetimeSeconds ?? 120;
    if (this.#lifetimeSeconds < 1 || this.#lifetimeSeconds > 300) {
      throw new Error('replay ticket lifetime must be between 1 and 300 seconds');
    }
  }

  async issue(
    ownerId: UserId,
    runId: RunId,
    afterSequence: number,
  ): Promise<ReplayTicket> {
    if (!Number.isSafeInteger(afterSequence) || afterSequence < -1) {
      throw unprocessable(
        'after_sequence must be an integer greater than or equal to -1.',
      );
    }
    const run = await this.#runs.getRecord(ownerId, runId);
    const issuedAt = Math.floor(this.#clock.now().getTime() / 1000);
    const payload: ReplayTicketPayload = {
      version: 1,
      subject: ownerId,
      applicationId: run.application_id,
      runId,
      ticketId: this.#ids.ticketId(),
      afterSequence,
      issuedAt,
      expiresAt: issuedAt + this.#lifetimeSeconds,
    };
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signed = signature(this.#secret, encoded).toString('base64url');
    return {
      ticket: `${encoded}.${signed}`,
      expires_at: new Date(payload.expiresAt * 1000).toISOString(),
    };
  }

  async verify(
    ticket: string,
    expectedOwnerId?: UserId,
  ): Promise<ReplayTicketPayload> {
    const pieces = ticket.split('.');
    if (pieces.length !== 2) {
      throw unauthorized('Replay ticket is invalid.');
    }
    const encoded = pieces[0]!;
    const supplied = pieces[1]!;
    let suppliedBytes: Buffer;
    try {
      suppliedBytes = Buffer.from(supplied, 'base64url');
    } catch {
      throw unauthorized('Replay ticket is invalid.');
    }
    const expected = signature(this.#secret, encoded);
    if (
      suppliedBytes.length !== expected.length ||
      !timingSafeEqual(suppliedBytes, expected)
    ) {
      throw unauthorized('Replay ticket is invalid.');
    }
    const payload = decodeJsonPayload(encoded);
    const now = Math.floor(this.#clock.now().getTime() / 1000);
    if (payload.expiresAt <= now || payload.issuedAt > now + 30) {
      throw unauthorized('Replay ticket has expired.');
    }
    if (
      expectedOwnerId !== undefined &&
      payload.subject !== expectedOwnerId
    ) {
      throw unauthorized('Replay ticket belongs to another user.');
    }
    await this.#runs.getRecordForScope(
      {
        owner_id: payload.subject,
        application_id: payload.applicationId,
      },
      payload.runId,
    );
    return payload;
  }
}

export interface WebSocketGatewayEvent {
  rawPath?: string;
  path?: string;
  headers?: Record<string, string | undefined> | null;
  queryStringParameters?: Record<string, string | undefined> | null;
  body?: string | null;
  isBase64Encoded?: boolean;
  requestContext?: {
    routeKey?: string;
    connectionId?: string;
    http?: { path?: string };
    authorizer?: {
      jwt?: { claims?: Record<string, unknown> };
      claims?: Record<string, unknown>;
      [key: string]: unknown;
    } | null;
    [key: string]: unknown;
  };
}

export interface WebSocketGatewayResponse {
  statusCode: number;
  body?: string;
  headers?: Record<string, string>;
}

export interface WebSocketHandlerOptions {
  originSecret: string;
  tickets: ReplayTicketService;
  connections: ConnectionAdapter;
  events: EventAdapter;
  clock: Clock;
  cognito?: CognitoClaimRequirements;
  maximumReplayEvents?: number;
  allowUnticketedConnections?: boolean;
  runs?: RunService;
}

function cursor(value: unknown): number {
  if (value === undefined || value === null || value === '') {
    return -1;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < -1) {
    throw unprocessable('Replay cursor must be an integer greater than or equal to -1.');
  }
  return parsed;
}

function localRunId(event: WebSocketGatewayEvent): RunId {
  const path = event.rawPath ?? event.requestContext?.http?.path ?? event.path ?? '';
  const match = /^\/ws\/runs\/([^/]+)(?:\/progress)?\/?$/.exec(path);
  if (match === null) {
    throw unauthorized('An authenticated run path or replay ticket is required.');
  }
  try {
    return asRunId(decodeURIComponent(match[1]!));
  } catch {
    throw unauthorized('The WebSocket run path is invalid.');
  }
}

function messageBody(event: WebSocketGatewayEvent): Record<string, unknown> {
  if (event.body === undefined || event.body === null || event.body === '') {
    return {};
  }
  const bytes = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64')
    : Buffer.from(event.body, 'utf8');
  if (bytes.byteLength > 64 * 1024) {
    throw badRequest('WebSocket message exceeds 64 KiB.', 'message_too_large');
  }
  const parsed = JSON.parse(bytes.toString('utf8')) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw unprocessable('WebSocket message must be a JSON object.');
  }
  return parsed as Record<string, unknown>;
}

export function browserProgressEvent(
  event: HostedProgressEvent,
): Record<string, unknown> {
  const payloadDetails =
    typeof event.payload.details === 'object' &&
    event.payload.details !== null &&
    !Array.isArray(event.payload.details)
      ? (event.payload.details as Record<string, unknown>)
      : {};
  let type = event.type;
  let stage = event.stage ?? undefined;
  let details: unknown = event.payload.details;

  switch (event.type) {
    case 'stage_started':
      type = 'stage_start';
      break;
    case 'stage_completed':
      type = 'stage_complete';
      break;
    case 'hitl_requested':
      type = 'awaiting_input';
      details = {
        ...payloadDetails,
        phase:
          typeof event.payload.kind === 'string'
            ? event.payload.kind
            : event.stage ?? 'interviewer',
        interaction_id: event.payload.interaction_id,
        revision: event.payload.revision,
      };
      break;
    case 'run_completed':
      type = 'stage_complete';
      stage = 'complete';
      details = {
        ...payloadDetails,
        app_id: event.application_id,
        status: 'complete',
      };
      break;
    case 'stage_failed':
      type = 'run_failed';
      details = {
        ...payloadDetails,
        status: 'failed',
        error: event.message ?? 'The run failed without reporting a reason.',
      };
      break;
    case 'run_paused':
      type = 'scan_paused';
      break;
    case 'run_stopped':
      type = 'scan_stopped';
      break;
    default:
      break;
  }

  const value = {
    ...event.payload,
    type,
    stage,
    percentage: event.percentage ?? undefined,
    message: event.message ?? undefined,
    details,
    sequence: event.sequence,
    event_id: event.event_id,
    server_ts: Date.parse(event.emitted_at),
  };
  if (Buffer.byteLength(JSON.stringify(value)) <= 31 * 1024) {
    return value;
  }
  return {
    type,
    stage,
    percentage: event.percentage ?? undefined,
    message: event.message ?? undefined,
    sequence: event.sequence,
    event_id: event.event_id,
    server_ts: Date.parse(event.emitted_at) / 1000,
    payload_omitted: true,
  };
}

export function createWebSocketHandler(options: WebSocketHandlerOptions) {
  void options.maximumReplayEvents;
  void options.events;

  return async (event: WebSocketGatewayEvent): Promise<WebSocketGatewayResponse> => {
    const route = event.requestContext?.routeKey ?? '$default';
    const connectionId = event.requestContext?.connectionId;
    try {
      if (!connectionId) {
        throw badRequest('WebSocket connection ID is missing.');
      }
      if (route === '$disconnect') {
        await options.connections.delete(connectionId);
        return { statusCode: 200 };
      }
      if (route === '$connect') {
        verifyOriginSecret(event, options.originSecret);
        const ticket = event.queryStringParameters?.ticket;
        const afterSequence = cursor(
          event.queryStringParameters?.after_sequence ??
            event.queryStringParameters?.cursor,
        );
        let payload: ReplayTicketPayload;
        if (ticket) {
          let expectedOwnerId: UserId | undefined;
          try {
            expectedOwnerId = extractCognitoOwner(event, options.cognito);
          } catch {
            // Browser WebSocket upgrades cannot attach the Cognito bearer
            // header. The short-lived signed ticket carries the verified
            // subject issued by the authenticated HTTP endpoint.
          }
          payload = await options.tickets.verify(ticket, expectedOwnerId);
          if (payload.afterSequence !== afterSequence) {
            throw unauthorized('Replay ticket does not match after_sequence.');
          }
        } else {
          if (!options.allowUnticketedConnections || options.runs === undefined) {
            throw unauthorized('A signed replay ticket is required.');
          }
          const ownerId = extractCognitoOwner(event, options.cognito);
          const unticketedRunId = localRunId(event);
          const run = await options.runs.getRecord(ownerId, unticketedRunId);
          const now = Math.floor(options.clock.now().getTime() / 1000);
          payload = {
            version: 1,
            subject: ownerId,
            applicationId: run.application_id,
            runId: unticketedRunId,
            ticketId: `local:${connectionId}`,
            afterSequence,
            issuedAt: now,
            expiresAt: now + 300,
          };
        }
        const connection: WebSocketConnection = {
          connectionId,
          ownerId: payload.subject,
          applicationId: payload.applicationId,
          runId: payload.runId,
          phase: 'replay_pending',
          cursor: afterSequence,
          seenEventIds: [],
          ticketId: payload.ticketId,
          connectedAt: options.clock.now().toISOString(),
          expiresAt: new Date(
            Math.max(payload.expiresAt, Math.floor(options.clock.now().getTime() / 1000) + 86_400) *
              1000,
          ).toISOString(),
        };
        await options.connections.put(connection);
        return { statusCode: 200 };
      }

      const connection = await options.connections.get(connectionId);
      if (connection === null) {
        throw unauthorized('WebSocket connection is not authenticated.');
      }
      const body = messageBody(event);
      const action = body.action ?? route;
      if (action !== 'replay' && action !== '$default') {
        throw badRequest('Unsupported WebSocket action.');
      }
      const requestedCursor = cursor(body.after_sequence ?? body.cursor);
      if (requestedCursor !== connection.cursor) {
        throw unauthorized('Replay request does not match the connection cursor.');
      }
      await options.connections.activate(connectionId, requestedCursor);
      return { statusCode: 200 };
    } catch (error) {
      const mapped = mapError(error);
      console.error(
        JSON.stringify({
          event: 'threatforest.websocket.request_failed',
          route,
          error_name: error instanceof Error ? error.name : 'UnknownError',
          error_message:
            error instanceof Error
              ? error.message.replace(/\s+/g, ' ').slice(0, 512)
              : 'Non-Error failure',
          response_code: mapped.code,
          response_status: mapped.status,
        }),
      );
      return {
        statusCode: mapped.status,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          detail: mapped.expose ? mapped.message : 'Internal server error.',
          code: mapped.code,
        }),
      };
    }
  };
}

export class ControlPlaneEventAdapter implements EventAdapter {
  readonly #list: EventAdapter['list'];

  constructor(list: EventAdapter['list']) {
    this.#list = list;
  }

  list(
    scope: { owner_id: UserId; application_id: ApplicationId },
    runId: RunId,
    afterSequence: number,
  ): Promise<HostedProgressEvent[]> {
    return this.#list(scope, runId, afterSequence);
  }
}

export function ticketRunId(value: unknown): RunId {
  return asRunId(value);
}
