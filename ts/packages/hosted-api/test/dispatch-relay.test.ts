import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DispatchRelay,
  type DispatchDestination,
} from '../src/dispatch-relay.js';

test('dispatch relay sends inserted outbox events exactly as recorded', async () => {
  const sent: Array<{
    destination: DispatchDestination;
    payload: Record<string, unknown>;
  }> = [];
  const relay = new DispatchRelay({
    async send(destination, payload) {
      sent.push({ destination, payload });
    },
  });
  await relay.process({
    eventName: 'INSERT',
    newItem: {
      entity: 'outbox-event',
      destination: 'run-command',
      payload: {
        schema_version: 1,
        command: 'execute',
        run_id: 'run_1',
      },
    },
  });
  await relay.process({
    eventName: 'MODIFY',
    newItem: {
      entity: 'outbox-event',
      destination: 'run-command',
      payload: { command: 'execute' },
    },
  });
  assert.deepEqual(sent, [
    {
      destination: 'run-command',
      payload: {
        schema_version: 1,
        command: 'execute',
        run_id: 'run_1',
      },
    },
  ]);
});

test('uploaded ingestion manifests dispatch once on the transition', async () => {
  const sent: Array<{
    destination: DispatchDestination;
    payload: Record<string, unknown>;
  }> = [];
  const relay = new DispatchRelay({
    async send(destination, payload) {
      sent.push({ destination, payload });
    },
  });
  const manifest = {
    ownerId: 'user_a',
    applicationId: 'app_1',
    uploadId: 'upload_1',
    attempt: 0,
    updatedAt: '2026-08-19T12:00:00.000Z',
  };
  await relay.process({
    eventName: 'MODIFY',
    oldItem: {
      entity: 'upload_manifest',
      manifest: { ...manifest, status: 'uploading' },
    },
    newItem: {
      entity: 'upload_manifest',
      manifest: { ...manifest, status: 'uploaded' },
    },
  });
  await relay.process({
    eventName: 'MODIFY',
    oldItem: {
      entity: 'upload_manifest',
      manifest: { ...manifest, status: 'uploaded' },
    },
    newItem: {
      entity: 'upload_manifest',
      manifest: { ...manifest, status: 'uploaded' },
    },
  });
  assert.equal(sent.length, 1);
  assert.equal(sent[0]?.destination, 'ingestion');
  assert.equal(sent[0]?.payload.idempotencyKey, 'upload-upload_1');
  assert.equal(sent[0]?.payload.attempt, 1);
});
