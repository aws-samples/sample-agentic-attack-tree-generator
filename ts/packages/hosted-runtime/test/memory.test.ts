import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ApplicationIdSchema,
  RunIdSchema,
} from '@threatforest/types';
import { AgentCoreApprovedFeedbackMemory } from '../src/memory.js';

test('completed threat models are stored as bounded application memory events', async () => {
  const events: Array<Record<string, unknown>> = [];
  const memory = new AgentCoreApprovedFeedbackMemory({
    memoryId: 'memory-1234567890',
    client: {
      async createEvent(input) {
        events.push(input);
      },
    },
  });
  const applicationId = ApplicationIdSchema.parse('app_memory');
  const runId = RunIdSchema.parse('run_memory');
  await memory.recordThreatModel({
    actorId: 'actor-application-hmac',
    applicationId,
    runId,
    createdAt: '2026-08-19T12:00:00.000Z',
    threatModel: {
      extraction_summary: { total_threats: 1 },
      threats: [
        {
          title: 'Credential theft',
          description: 'An attacker steals a token.',
        },
      ],
    },
  });

  assert.equal(events.length, 1);
  assert.equal(events[0]?.['actorId'], 'actor-application-hmac');
  assert.equal(events[0]?.['sessionId'], runId);
  const payload = events[0]?.['payload'] as Array<{
    conversational: { content: { text: string }; role: string };
  }>;
  assert.equal(payload[0]?.conversational.role, 'ASSISTANT');
  assert.match(payload[0]!.conversational.content.text, /Credential theft/);
  assert.ok(
    Buffer.byteLength(payload[0]!.conversational.content.text) <= 100_000,
  );
});

test('memory retrieval is confined to the actor namespaces and deduplicated', async () => {
  const requests: Array<Record<string, unknown>> = [];
  const memory = new AgentCoreApprovedFeedbackMemory({
    memoryId: 'memory-1234567890',
    client: {
      async createEvent() {},
      async retrieveMemoryRecords(input) {
        requests.push(input);
        return [
          { content: { text: 'prior threat model' }, score: 0.9 },
          { content: { text: 'prior threat model' }, score: 0.8 },
        ];
      },
    },
  });

  const context = await memory.retrieveApplicationContext({
    actorId: 'actor-application-hmac',
    applicationId: ApplicationIdSchema.parse('app_memory'),
    query: 'prior risks',
    topK: 5,
  });

  assert.deepEqual(context, ['prior threat model']);
  assert.deepEqual(
    requests.map((request) => request['namespace']),
    [
      '/threatforest/actor-application-hmac/summaries',
      '/threatforest/actor-application-hmac/approved-feedback',
    ],
  );
  assert.equal(
    requests.every(
      (request) =>
        (request['searchCriteria'] as Record<string, unknown>)['topK'] === 5,
    ),
    true,
  );
});
