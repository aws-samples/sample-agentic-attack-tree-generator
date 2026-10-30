import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ApplicationIdSchema,
  RunIdSchema,
} from '@threatforest/types';
import type { RunRecord } from '@threatforest/control-plane';
import {
  addRuntimePrincipalHeader,
  authorizeRunCommand,
  parseRuntimeBoundary,
  RUNTIME_PRINCIPAL_HEADER,
  RuntimeClientError,
  runCommand,
  runtimeInvocationPayload,
} from '../src/lambda/run-dispatcher.js';
import { OWNER_A } from './support.js';

const APP = ApplicationIdSchema.parse('app_dispatcher');
const RUN = RunIdSchema.parse('run_dispatcher');

const RECORD: RunRecord = {
  schema_version: 1,
  owner_id: OWNER_A,
  application_id: APP,
  run_id: RUN,
  status: 'queued',
  source_artifact_ids: [],
  threat_artifact_id: null,
  current_stage_id: null,
  trace_id: '0123456789abcdef',
  revision: 1,
  last_event_sequence: -1,
  created_at: '2026-08-19T12:00:00.000Z',
  updated_at: '2026-08-19T12:00:00.000Z',
  completed_at: null,
  error_code: null,
  error_message: null,
};

test('run dispatcher parses opaque identities and accepts only canonical scope', async () => {
  const event = {
    schema_version: 1,
    command: 'execute',
    owner_id: OWNER_A,
    application_id: APP,
    run_id: RUN,
  };
  assert.deepEqual(runCommand(event), event);
  assert.deepEqual(runCommand({ body: event }), event);
  assert.deepEqual(runCommand({ body: JSON.stringify(event) }), event);
  const result = await authorizeRunCommand(event, {
    async getRun(scope, runId) {
      assert.equal(scope.owner_id, OWNER_A);
      assert.equal(scope.application_id, APP);
      assert.equal(runId, RUN);
      return RECORD;
    },
  });
  assert.equal(result.run.trace_id, RECORD.trace_id);
  assert.deepEqual(runtimeInvocationPayload(result.input, result.run), {
    operation: 'execute_run',
    application_id: APP,
    run_id: RUN,
    dispatch_generation: RECORD.revision,
  });
  const headers: Record<string, string> = {};
  addRuntimePrincipalHeader(headers, OWNER_A);
  assert.equal(headers[RUNTIME_PRINCIPAL_HEADER], OWNER_A);
});

test('run dispatcher rejects malformed and non-canonical queue commands', async () => {
  assert.throws(
    () =>
      runCommand({
        schema_version: 1,
        command: 'execute',
        owner_id: '../owner',
        application_id: APP,
        run_id: RUN,
      }),
    /invalid/i,
  );
  await assert.rejects(
    authorizeRunCommand(
      {
        schema_version: 1,
        command: 'execute',
        owner_id: OWNER_A,
        application_id: APP,
        run_id: RUN,
      },
      { async getRun() { return null; } },
    ),
    /canonical run/,
  );
});

test('run dispatcher accepts streamed JSON and rejects missing durable boundaries', () => {
  assert.deepEqual(parseRuntimeBoundary('{"boundary":"busy"}'), {
    boundary: 'busy',
  });
  assert.deepEqual(parseRuntimeBoundary('\n\n{"boundary":"completed"}'), {
    boundary: 'completed',
  });
  assert.deepEqual(
    parseRuntimeBoundary('{"error":"RuntimeFailure","message":"bounded"}'),
    {
      error: 'RuntimeFailure',
      message: 'bounded',
    },
  );
  assert.throws(() => parseRuntimeBoundary(' \n '), /empty response/);
  assert.throws(() => parseRuntimeBoundary('{}'), /no valid durable boundary/);
  assert.throws(() => parseRuntimeBoundary('not-json'), /not valid JSON/);
  assert.throws(
    () => parseRuntimeBoundary('{"error":""}'),
    { name: RuntimeClientError.name },
  );
  assert.throws(
    () => parseRuntimeBoundary('[]'),
    { name: RuntimeClientError.name },
  );
  assert.throws(
    () => parseRuntimeBoundary('{"boundary":"unknown"}'),
    { name: RuntimeClientError.name },
  );
});
