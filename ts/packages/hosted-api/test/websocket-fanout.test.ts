import assert from 'node:assert/strict';
import test from 'node:test';
import type {
  ApplicationId,
  HostedProgressEvent,
  RunId,
} from '@threatforest/types';
import { InMemoryConnectionAdapter } from '../src/in-memory.js';
import type { WebSocketConnection } from '../src/contracts.js';
import { browserProgressEvent } from '../src/websocket.js';
import { WebSocketFanout } from '../src/websocket-fanout.js';
import { OWNER_A, OWNER_B } from './support.js';

const APP = 'app_fanout' as ApplicationId;
const RUN = 'run_fanout' as RunId;

function connection(
  overrides: Partial<WebSocketConnection> = {},
): WebSocketConnection {
  return {
    connectionId: 'connection-1',
    ownerId: OWNER_A,
    applicationId: APP,
    runId: RUN,
    phase: 'live',
    cursor: -1,
    seenEventIds: [],
    ticketId: 'ticket-1',
    connectedAt: '2026-08-19T12:00:00.000Z',
    expiresAt: '2026-08-20T12:00:00.000Z',
    ...overrides,
  };
}

function progress(sequence: number): HostedProgressEvent {
  return {
    schema_version: 1,
    owner_id: OWNER_A,
    application_id: APP,
    run_id: RUN,
    sequence,
    event_id: `event-${sequence}`,
    trace_id: '0123456789abcdef',
    type: 'stage_progress',
    stage: 'scanner',
    percentage: sequence * 10,
    message: `event ${sequence}`,
    payload: { sequence },
    emitted_at: `2026-08-19T12:00:0${sequence}.000Z`,
  };
}

test('durable events are adapted to the existing browser progress contract', () => {
  const started = browserProgressEvent({
    ...progress(0),
    type: 'stage_started',
    emitted_at: '2026-08-19T12:00:00.123Z',
  });
  assert.equal(started.type, 'stage_start');
  assert.equal(started.stage, 'scanner');
  assert.equal(started.server_ts, Date.parse('2026-08-19T12:00:00.123Z'));

  const hitl = browserProgressEvent({
    ...progress(1),
    type: 'hitl_requested',
    stage: 'scanner_review',
    payload: {
      interaction_id: 'hitl_scanner',
      revision: 2,
      kind: 'scanner_review',
    },
  });
  assert.equal(hitl.type, 'awaiting_input');
  assert.deepEqual(hitl.details, {
    phase: 'scanner_review',
    interaction_id: 'hitl_scanner',
    revision: 2,
  });

  const completed = browserProgressEvent({
    ...progress(2),
    type: 'run_completed',
    stage: null,
    percentage: 100,
    payload: {},
  });
  assert.equal(completed.type, 'stage_complete');
  assert.equal(completed.stage, 'complete');
  assert.deepEqual(completed.details, {
    app_id: APP,
    status: 'complete',
  });

  const failed = browserProgressEvent({
    ...progress(3),
    type: 'stage_failed',
    message: 'model invocation failed',
    payload: { error_code: 'model_error' },
  });
  assert.equal(failed.type, 'run_failed');
  assert.deepEqual(failed.details, {
    status: 'failed',
    error: 'model invocation failed',
  });
});

test('stream insertion catches up gaps once and stays tenant scoped', async () => {
  const connections = new InMemoryConnectionAdapter();
  await connections.put(connection());
  await connections.put(
    connection({
      connectionId: 'other-owner',
      ownerId: OWNER_B,
    }),
  );
  const events = [progress(0), progress(1), progress(2)];
  const fanout = new WebSocketFanout({
    connections,
    events: {
      list: async (scope, runId, after) =>
        scope.owner_id === OWNER_A && runId === RUN
          ? events.filter((event) => event.sequence > after)
          : [],
    },
    now: () => new Date('2026-08-19T12:30:00.000Z'),
  });

  await fanout.process({
    eventName: 'INSERT',
    newItem: { entity: 'event', ...progress(2) },
  });
  await fanout.process({
    eventName: 'INSERT',
    newItem: { entity: 'event', ...progress(2) },
  });

  assert.deepEqual(
    connections.messages
      .get('connection-1')
      ?.map((message) => message.sequence),
    [0, 1, 2],
  );
  assert.equal(connections.messages.get('other-owner'), undefined);
  assert.equal((await connections.get('connection-1'))?.cursor, 2);
});

test('pending, expired, and gone connections are not retried forever', async () => {
  const connections = new InMemoryConnectionAdapter();
  await connections.put(connection({ connectionId: 'pending', phase: 'replay_pending' }));
  await connections.put(
    connection({
      connectionId: 'expired',
      expiresAt: '2026-08-18T12:00:00.000Z',
    }),
  );
  await connections.put(connection({ connectionId: 'gone' }));
  const originalPost = connections.post.bind(connections);
  connections.post = async (connectionId, value) => {
    if (connectionId === 'gone') {
      const error = new Error('gone');
      error.name = 'GoneException';
      throw error;
    }
    await originalPost(connectionId, value);
  };
  const event = progress(0);
  const fanout = new WebSocketFanout({
    connections,
    events: { list: async () => [event] },
    now: () => new Date('2026-08-19T12:30:00.000Z'),
  });

  await fanout.process({
    eventName: 'INSERT',
    newItem: { entity: 'event', ...event },
  });

  assert.notEqual(await connections.get('pending'), null);
  assert.equal(await connections.get('expired'), null);
  assert.equal(await connections.get('gone'), null);
});

test('oversized event details are omitted while sequence metadata is delivered', async () => {
  const connections = new InMemoryConnectionAdapter();
  await connections.put(connection());
  const event = {
    ...progress(0),
    payload: { details: 'x'.repeat(64 * 1024) },
  };
  const fanout = new WebSocketFanout({
    connections,
    events: { list: async () => [event] },
    now: () => new Date('2026-08-19T12:30:00.000Z'),
  });
  await fanout.process({
    eventName: 'INSERT',
    newItem: { entity: 'event', ...event },
  });
  const message = connections.messages.get('connection-1')?.[0];
  assert.equal(message?.payload_omitted, true);
  assert.equal(message?.sequence, 0);
  assert.ok(Buffer.byteLength(JSON.stringify(message)) < 32 * 1024);
});
