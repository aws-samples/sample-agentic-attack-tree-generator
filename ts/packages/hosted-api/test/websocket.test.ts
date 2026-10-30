import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ApplicationId,
  HostedProgressEvent,
  RunId,
  UserId,
} from '@threatforest/types';
import { InMemoryConnectionAdapter } from '../src/in-memory.js';
import {
  createWebSocketHandler,
  type WebSocketGatewayEvent,
} from '../src/websocket.js';
import { WebSocketFanout } from '../src/websocket-fanout.js';
import {
  ORIGIN_SECRET,
  OWNER_A,
  OWNER_B,
  apiEvent,
  createApplication,
  createRun,
  json,
  makeFixture,
} from './support.js';

function wsEvent(
  connectionId: string,
  options: {
    owner?: UserId;
    ticket?: string;
    afterSequence?: number;
    route?: string;
    path?: string;
    body?: unknown;
  } = {},
): WebSocketGatewayEvent {
  const query: Record<string, string> = {};
  if (options.ticket !== undefined) query.ticket = options.ticket;
  if (options.afterSequence !== undefined) {
    query.after_sequence = String(options.afterSequence);
  }
  return {
    rawPath: options.path ?? '/ws',
    headers: { 'x-threatforest-origin-verify': ORIGIN_SECRET },
    queryStringParameters: query,
    body: options.body === undefined ? null : JSON.stringify(options.body),
    requestContext: {
      routeKey: options.route ?? '$connect',
      connectionId,
      authorizer: {
        jwt: { claims: { sub: options.owner ?? OWNER_A } },
      },
    },
  };
}

function progress(
  applicationId: ApplicationId,
  runId: RunId,
  sequence: number,
  eventId = `event_${sequence}`,
): HostedProgressEvent {
  return {
    schema_version: 1,
    owner_id: OWNER_A,
    application_id: applicationId,
    run_id: runId,
    sequence,
    event_id: eventId,
    trace_id: '0123456789abcdef',
    type: 'stage_progress',
    stage: 'scanner',
    percentage: sequence * 10,
    message: `event ${sequence}`,
    payload: { details: { index: sequence } },
    emitted_at: `2026-08-19T12:00:0${sequence}.000Z`,
  };
}

async function issueTicket(
  fixture: ReturnType<typeof makeFixture>,
  runId: RunId,
  afterSequence: number,
  owner: UserId = OWNER_A,
): Promise<string> {
  const response = await fixture.handler(
    apiEvent('POST', `/api/runs/${runId}/replay-ticket`, {
      owner,
      body: { after_sequence: afterSequence },
    }),
  );
  assert.equal(response.statusCode, 200);
  assert.deepEqual(Object.keys(json(response)).sort(), ['expires_at', 'ticket']);
  return json(response).ticket as string;
}

test('replay tickets reject tampering, expiry, and cross-user use', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const ticket = await issueTicket(fixture, runId, -1);
  const connections = new InMemoryConnectionAdapter();
  const handler = createWebSocketHandler({
    originSecret: ORIGIN_SECRET,
    tickets: fixture.services.tickets,
    connections,
    events: { list: async () => [] },
    clock: fixture.clock,
    runs: fixture.services.runs,
  });

  const tampered = `${ticket.slice(0, 2)}x${ticket.slice(3)}`;
  const bad = await handler(
    wsEvent('tampered', { ticket: tampered, afterSequence: -1 }),
  );
  assert.equal(bad.statusCode, 401);

  const crossUser = await handler(
    wsEvent('cross-user', {
      owner: OWNER_B,
      ticket,
      afterSequence: -1,
    }),
  );
  assert.equal(crossUser.statusCode, 401);

  fixture.clock.advance(61_000);
  const expired = await handler(
    wsEvent('expired', { ticket, afterSequence: -1 }),
  );
  assert.equal(expired.statusCode, 401);
});

test('connect persists pending replay and stream activation deduplicates events', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const appId = application.id as ApplicationId;
  const ticket = await issueTicket(fixture, runId, 0);
  const connections = new InMemoryConnectionAdapter();
  const events = [
    progress(appId, runId, 0),
    progress(appId, runId, 1),
    progress(appId, runId, 1, 'duplicate_sequence'),
    progress(appId, runId, 2, 'event_1'),
    progress(appId, runId, 2),
  ];
  const handler = createWebSocketHandler({
    originSecret: ORIGIN_SECRET,
    tickets: fixture.services.tickets,
    connections,
    events: { list: async () => events },
    clock: fixture.clock,
    runs: fixture.services.runs,
  });

  const mismatchedCursor = await handler(
    wsEvent('wrong-cursor', { ticket, afterSequence: -1 }),
  );
  assert.equal(mismatchedCursor.statusCode, 401);

  const connected = await handler(
    wsEvent('connection-1', { ticket, afterSequence: 0 }),
  );
  assert.equal(connected.statusCode, 200);
  assert.equal(connections.messages.get('connection-1'), undefined);
  const pending = await connections.get('connection-1');
  assert.equal(pending?.phase, 'replay_pending');

  const activated = await handler(
    wsEvent('connection-1', {
      route: '$default',
      body: { action: 'replay', after_sequence: 0 },
    }),
  );
  assert.equal(activated.statusCode, 200);
  const live = await connections.get('connection-1');
  assert.equal(live?.phase, 'live');
  await new WebSocketFanout({
    connections,
    events: { list: async () => events },
    now: () => fixture.clock.now(),
  }).process({
    eventName: 'MODIFY',
    oldItem: { entity: 'hosted-websocket-subscription', connection: pending },
    newItem: { entity: 'hosted-websocket-subscription', connection: live },
  });
  assert.deepEqual(
    connections.messages
      .get('connection-1')
      ?.map((event) => event.sequence),
    [1, 2],
  );
  assert.equal((await connections.get('connection-1'))?.cursor, 2);
});

test('reconnect cursors replay only unseen events', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const appId = application.id as ApplicationId;
  const connections = new InMemoryConnectionAdapter();
  const events = [
    progress(appId, runId, 0),
    progress(appId, runId, 1),
    progress(appId, runId, 2),
  ];
  const handler = createWebSocketHandler({
    originSecret: ORIGIN_SECRET,
    tickets: fixture.services.tickets,
    connections,
    events: {
      list: async (_scope, _runId, after) =>
        events.filter((event) => event.sequence > after),
    },
    clock: fixture.clock,
    runs: fixture.services.runs,
  });

  const firstTicket = await issueTicket(fixture, runId, 0);
  await handler(
    wsEvent('first', { ticket: firstTicket, afterSequence: 0 }),
  );
  const firstPending = await connections.get('first');
  await handler(
    wsEvent('first', {
      route: '$default',
      body: { action: 'replay', after_sequence: 0 },
    }),
  );
  const fanout = new WebSocketFanout({
    connections,
    events: {
      list: async (_scope, _runId, after) =>
        events.filter((event) => event.sequence > after),
    },
    now: () => fixture.clock.now(),
  });
  await fanout.process({
    eventName: 'MODIFY',
    oldItem: {
      entity: 'hosted-websocket-subscription',
      connection: firstPending,
    },
    newItem: {
      entity: 'hosted-websocket-subscription',
      connection: await connections.get('first'),
    },
  });
  assert.deepEqual(
    connections.messages.get('first')?.map((event) => event.sequence),
    [1, 2],
  );

  const reconnectTicket = await issueTicket(fixture, runId, 1);
  await handler(
    wsEvent('reconnect', {
      ticket: reconnectTicket,
      afterSequence: 1,
    }),
  );
  const reconnectPending = await connections.get('reconnect');
  await handler(
    wsEvent('reconnect', {
      route: '$default',
      body: { action: 'replay', after_sequence: 1 },
    }),
  );
  await fanout.process({
    eventName: 'MODIFY',
    oldItem: {
      entity: 'hosted-websocket-subscription',
      connection: reconnectPending,
    },
    newItem: {
      entity: 'hosted-websocket-subscription',
      connection: await connections.get('reconnect'),
    },
  });
  assert.deepEqual(
    connections.messages.get('reconnect')?.map((event) => event.sequence),
    [2],
  );
});

test('explicit local compatibility mode permits the legacy run path without a ticket', async () => {
  const fixture = makeFixture();
  const application = await createApplication(fixture);
  const runId = await createRun(fixture, application);
  const connections = new InMemoryConnectionAdapter();
  const handler = createWebSocketHandler({
    originSecret: ORIGIN_SECRET,
    tickets: fixture.services.tickets,
    connections,
    events: { list: async () => [] },
    clock: fixture.clock,
    runs: fixture.services.runs,
    allowUnticketedConnections: true,
  });

  const response = await handler(
    wsEvent('local', {
      path: `/ws/runs/${runId}`,
      afterSequence: -1,
    }),
  );
  assert.equal(response.statusCode, 200);
  assert.equal((await connections.get('local'))?.runId, runId);
  assert.equal((await connections.get('local'))?.phase, 'replay_pending');
});
