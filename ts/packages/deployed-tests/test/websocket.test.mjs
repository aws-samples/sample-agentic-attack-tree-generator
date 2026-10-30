import assert from 'node:assert/strict';
import test from 'node:test';
import { expectApi } from './support/api.mjs';
import { normalizedBaseUrl, optional, skipUnless } from './support/env.mjs';
import { openWebSocket } from './support/websocket.mjs';

test(
  'signed WebSocket replay returns ordered, deduplicated run events',
  {
    skip: skipUnless(
      'TF_BASE_URL',
      'TF_TEST_USER_A_ACCESS_TOKEN',
      'TF_TEST_RUN_ID',
    ),
    timeout: 60_000,
  },
  async () => {
    const runId = optional('TF_TEST_RUN_ID');
    const { body: ticket } = await expectApi(
      `/api/runs/${encodeURIComponent(runId)}/replay-ticket`,
      optional('TF_TEST_USER_A_ACCESS_TOKEN'),
      { method: 'POST', json: { after_sequence: -1 } },
    );
    assert.ok(ticket.ticket);

    const base = new URL(normalizedBaseUrl());
    const websocketUrl = new URL(
      `/ws/runs/${encodeURIComponent(runId)}`,
      `wss://${base.host}`,
    );
    websocketUrl.searchParams.set('ticket', ticket.ticket);
    websocketUrl.searchParams.set('after_sequence', '-1');

    const connection = await openWebSocket(websocketUrl.toString(), {
      origin: normalizedBaseUrl(),
    });
    try {
      connection.sendJson({ action: 'replay', after_sequence: -1 });
      const first = JSON.parse(await connection.nextMessage(30_000));
      assert.equal(Number.isSafeInteger(first.sequence), true);
      assert.ok(first.event_id);

      const cursor = first.sequence;
      connection.sendJson({ action: 'replay', after_sequence: cursor });
      try {
        const next = JSON.parse(await connection.nextMessage(5_000));
        assert.ok(next.sequence > cursor);
        assert.notEqual(next.event_id, first.event_id);
      } catch (error) {
        assert.match(error.message, /Timed out/);
      }
    } finally {
      connection.close();
    }
  },
);
