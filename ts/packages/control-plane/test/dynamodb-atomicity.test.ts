import assert from 'node:assert/strict';
import test from 'node:test';
import {
  GetCommand,
  TransactWriteCommand,
  type DynamoDBDocumentClient,
  type TransactWriteCommandInput,
} from '@aws-sdk/lib-dynamodb';
import type {
  ApplicationId,
  ArtifactId,
  HitlRequest,
  HitlResponse,
  InteractionId,
  RunId,
  RunSettingsSnapshot,
  UserId,
} from '@threatforest/types';
import { DynamoControlPlane } from '../src/dynamodb.js';
import { ControlPlaneError } from '../src/errors.js';
import { encodeKeyPart } from '../src/keys.js';
import type {
  ControlPlaneScope,
  RunControlIntent,
  RunRecord,
} from '../src/models.js';

type TransactItem = NonNullable<TransactWriteCommandInput['TransactItems']>[number];
type RecordedCommand = {
  readonly input: Record<string, unknown>;
  readonly constructor: { readonly name: string };
};

const tableName = 'control-plane-table';
const ownerId = 'user_a' as UserId;
const applicationId = 'app_01' as ApplicationId;
const runId = 'run_01' as RunId;
const artifactId = 'artifact_01' as ArtifactId;
const interactionId = 'interaction_01' as InteractionId;
const start = '2026-08-19T12:00:00.000Z';
const traceId = '0123456789abcdef';
const hash = 'a'.repeat(64);

class RecordingDocumentClient {
  readonly commands: RecordedCommand[] = [];
  readonly #respond: (command: RecordedCommand) => unknown | Promise<unknown>;

  constructor(
    respond: (command: RecordedCommand) => unknown | Promise<unknown> = () => ({}),
  ) {
    this.#respond = respond;
  }

  async send(command: unknown): Promise<unknown> {
    const recorded = command as RecordedCommand;
    this.commands.push(recorded);
    return this.#respond(recorded);
  }

  asDocumentClient(): DynamoDBDocumentClient {
    return this as unknown as DynamoDBDocumentClient;
  }
}

function scope(): ControlPlaneScope {
  return { owner_id: ownerId, application_id: applicationId };
}

function run(overrides: Partial<RunRecord> = {}): RunRecord {
  return {
    schema_version: 1,
    ...scope(),
    run_id: runId,
    status: 'queued',
    source_artifact_ids: [artifactId],
    threat_artifact_id: null,
    current_stage_id: null,
    trace_id: traceId,
    revision: 1,
    last_event_sequence: -1,
    created_at: start,
    updated_at: start,
    completed_at: null,
    error_code: null,
    error_message: null,
    ...overrides,
  };
}

function settings(): RunSettingsSnapshot {
  return {
    schema_version: 1,
    ...scope(),
    run_id: runId,
    provider: 'bedrock',
    model_id: 'anthropic.claude-sonnet',
    model_parameters: { temperature: 0.1 },
    frameworks: ['STRIDE', 'MITRE ATT&CK', 'PASTA'],
    embeddings_model: 'amazon.titan-embed-text-v2:0',
    config_hash: hash,
    created_at: start,
  };
}

function hitlRequest(): HitlRequest {
  return {
    schema_version: 1,
    ...scope(),
    interaction_id: interactionId,
    run_id: runId,
    stage_id: 'threat_review',
    kind: 'threat_review',
    revision: 2,
    fencing_token: 3,
    trace_id: traceId,
    status: 'pending',
    reason: { threats: [] },
    transcript_artifact: null,
    created_at: '2026-08-19T12:02:00.000Z',
    expires_at: null,
  };
}

function hitlResponse(): HitlResponse {
  return {
    schema_version: 1,
    ...scope(),
    interaction_id: interactionId,
    run_id: runId,
    revision: 2,
    action: 'submit',
    text: 'Approved with edits',
    submitted_at: '2026-08-19T12:05:00.000Z',
  };
}

function partitionKey(): string {
  return `OWNER#${encodeKeyPart(ownerId)}#APP#${encodeKeyPart(applicationId)}`;
}

function sortKey(prefix: string, value: string): string {
  return `${prefix}#${encodeKeyPart(value)}`;
}

function transactionItems(client: RecordingDocumentClient): TransactItem[] {
  const transactions = client.commands.filter(
    (command) => command instanceof TransactWriteCommand,
  );
  assert.equal(transactions.length, 1, 'the mutation must use exactly one DynamoDB transaction');
  const items = transactions[0]?.input['TransactItems'];
  assert.ok(Array.isArray(items), 'the transaction must contain write items');
  return items as TransactItem[];
}

function requiredPut(item: TransactItem | undefined): NonNullable<TransactItem['Put']> {
  assert.ok(item?.Put, 'expected a transactional Put');
  return item.Put;
}

function requiredUpdate(
  item: TransactItem | undefined,
): NonNullable<TransactItem['Update']> {
  assert.ok(item?.Update, 'expected a transactional Update');
  return item.Update;
}

function requiredDelete(
  item: TransactItem | undefined,
): NonNullable<TransactItem['Delete']> {
  assert.ok(item?.Delete, 'expected a transactional Delete');
  return item.Delete;
}

function requiredConditionCheck(
  item: TransactItem | undefined,
): NonNullable<TransactItem['ConditionCheck']> {
  assert.ok(item?.ConditionCheck, 'expected a transactional ConditionCheck');
  return item.ConditionCheck;
}

function assertOutbox(
  item: TransactItem | undefined,
  expected: {
    eventId: string;
    command: 'execute' | 'pause' | 'stop';
    createdAt: string;
  },
): void {
  const put = requiredPut(item);
  assert.equal(put.TableName, tableName);
  assert.equal(put.ConditionExpression, 'attribute_not_exists(PK)');
  assert.deepEqual(put.Item, {
    PK: partitionKey(),
    SK: sortKey('OUTBOX', expected.eventId),
    entity: 'outbox-event',
    destination: 'run-command',
    event_id: expected.eventId,
    payload: {
      schema_version: 1,
      command: expected.command,
      owner_id: ownerId,
      application_id: applicationId,
      run_id: runId,
    },
    created_at: expected.createdAt,
    ttl: Math.floor(Date.parse(expected.createdAt) / 1000) + 30 * 24 * 60 * 60,
  });
}

function storedRun(value: RunRecord): Record<string, unknown> {
  return {
    PK: partitionKey(),
    SK: sortKey('RUN', runId),
    entity: 'run',
    ...value,
  };
}

function transactionCanceled(message = 'conditional transaction failure'): Error {
  const error = new Error(message);
  error.name = 'TransactionCanceledException';
  return error;
}

function hasControlPlaneError(
  code: ControlPlaneError['code'],
  message: RegExp,
  cause?: unknown,
): (error: unknown) => boolean {
  return (error) => {
    assert.ok(error instanceof ControlPlaneError);
    assert.equal(error.code, code);
    assert.match(error.message, message);
    if (cause !== undefined) {
      assert.equal(error.cause, cause);
    }
    return true;
  };
}

test('createRunDispatch atomically creates run state, settings, and execute outbox event', async () => {
  const client = new RecordingDocumentClient();
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });
  const runRecord = run();
  const snapshot = settings();

  await store.createRunDispatch(runRecord, snapshot);

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['TransactWriteCommand'],
  );
  const items = transactionItems(client);
  assert.equal(items.length, 3);

  const runPut = requiredPut(items[0]);
  assert.equal(runPut.TableName, tableName);
  assert.equal(runPut.ConditionExpression, 'attribute_not_exists(PK)');
  assert.deepEqual(runPut.Item, storedRun(runRecord));

  const settingsPut = requiredPut(items[1]);
  assert.equal(settingsPut.TableName, tableName);
  assert.equal(settingsPut.ConditionExpression, 'attribute_not_exists(PK)');
  assert.deepEqual(settingsPut.Item, {
    PK: partitionKey(),
    SK: `${sortKey('RUN', runId)}#SETTINGS`,
    entity: 'run-settings',
    ...snapshot,
  });

  assertOutbox(items[2], {
    eventId: `run.execute:${runId}:1`,
    command: 'execute',
    createdAt: start,
  });
});

test('createRunDispatch treats any transaction cancellation as an atomic create failure', async () => {
  const cancellation = transactionCanceled();
  const client = new RecordingDocumentClient((command) => {
    if (command instanceof TransactWriteCommand) {
      throw cancellation;
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });

  await assert.rejects(
    store.createRunDispatch(run(), settings()),
    hasControlPlaneError('already_exists', /run run_01 already exists/),
  );

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['TransactWriteCommand'],
    'a failed transaction must not retry run state or outbox as standalone writes',
  );
  assert.equal(transactionItems(client).length, 3);
});

test('requestRunControl atomically guards the control mutation and corresponding outbox event', async () => {
  const client = new RecordingDocumentClient((command) => {
    if (command instanceof GetCommand) {
      return { Item: storedRun(run()) };
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });
  const intent: RunControlIntent = {
    ...scope(),
    run_id: runId,
    action: 'stop',
    requested_at: '2026-08-19T12:03:00.000Z',
  };

  await store.requestRunControl(intent);

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['GetCommand', 'TransactWriteCommand'],
  );
  const items = transactionItems(client);
  assert.equal(items.length, 2);

  const update = requiredUpdate(items[0]);
  assert.deepEqual(update.Key, {
    PK: partitionKey(),
    SK: `${sortKey('RUN', runId)}#CONTROL`,
  });
  assert.equal(
    update.ConditionExpression,
    'attribute_not_exists(#action) OR #action = :requested OR ' +
      '(#action = :pause AND :requested = :stop)',
  );
  assert.deepEqual(update.ExpressionAttributeValues, {
    ':entity': 'run-control',
    ':owner': ownerId,
    ':application': applicationId,
    ':run': runId,
    ':requested': 'stop',
    ':requestedAt': intent.requested_at,
    ':pause': 'pause',
    ':stop': 'stop',
  });

  assertOutbox(items[1], {
    eventId: `run.control:${runId}:stop:${intent.requested_at}`,
    command: 'stop',
    createdAt: intent.requested_at,
  });
});

test('resumeRun atomically advances guarded run state, clears control, and enqueues execution', async () => {
  const resumedAt = '2026-08-19T12:04:00.000Z';
  const resumed = run({
    status: 'queued',
    revision: 4,
    updated_at: resumedAt,
    error_code: null,
    error_message: null,
  });
  const client = new RecordingDocumentClient((command) => {
    if (command instanceof GetCommand) {
      return { Item: storedRun(resumed) };
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });

  assert.deepEqual(
    await store.resumeRun({
      ...scope(),
      run_id: runId,
      expected_revision: 3,
      expected_status: 'failed',
      resumed_at: resumedAt,
    }),
    resumed,
  );

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['TransactWriteCommand', 'GetCommand'],
  );
  const items = transactionItems(client);
  assert.equal(items.length, 3);

  const update = requiredUpdate(items[0]);
  assert.deepEqual(update.Key, {
    PK: partitionKey(),
    SK: sortKey('RUN', runId),
  });
  assert.equal(
    update.ConditionExpression,
    'revision = :expected AND #status = :expectedStatus',
  );
  assert.deepEqual(update.ExpressionAttributeValues, {
    ':queued': 'queued',
    ':expectedStatus': 'failed',
    ':expected': 3,
    ':next': 4,
    ':resumed': resumedAt,
    ':null': null,
  });

  const clearControl = requiredDelete(items[1]);
  assert.deepEqual(clearControl.Key, {
    PK: partitionKey(),
    SK: `${sortKey('RUN', runId)}#CONTROL`,
  });

  assertOutbox(items[2], {
    eventId: `run.execute:${runId}:4`,
    command: 'execute',
    createdAt: resumedAt,
  });
});

test('resumeRun requires the durable pause control when resuming awaiting_input', async () => {
  const resumedAt = '2026-08-19T12:04:00.000Z';
  const resumed = run({
    status: 'queued',
    revision: 4,
    current_stage_id: 'scanner',
    updated_at: resumedAt,
  });
  const client = new RecordingDocumentClient((command) => {
    if (command instanceof GetCommand) {
      return { Item: storedRun(resumed) };
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });

  await store.resumeRun({
    ...scope(),
    run_id: runId,
    expected_revision: 3,
    expected_status: 'awaiting_input',
    resumed_at: resumedAt,
  });

  const items = transactionItems(client);
  assert.equal(items.length, 3);
  const update = requiredUpdate(items[0]);
  assert.deepEqual(update.ExpressionAttributeValues, {
    ':queued': 'queued',
    ':expectedStatus': 'awaiting_input',
    ':expected': 3,
    ':next': 4,
    ':resumed': resumedAt,
    ':null': null,
  });
  const clearControl = requiredDelete(items[1]);
  assert.deepEqual(clearControl.Key, {
    PK: partitionKey(),
    SK: `${sortKey('RUN', runId)}#CONTROL`,
  });
  assert.equal(clearControl.ConditionExpression, '#action = :pause');
  assert.deepEqual(clearControl.ExpressionAttributeValues, {
    ':pause': 'pause',
  });
  assertOutbox(items[2], {
    eventId: `run.execute:${runId}:4`,
    command: 'execute',
    createdAt: resumedAt,
  });
});

test('resumeRun reports a failed guarded transaction without retrying its outbox write', async () => {
  const cancellation = transactionCanceled('revision changed');
  const current = run({ status: 'running', revision: 4 });
  const client = new RecordingDocumentClient((command) => {
    if (command instanceof TransactWriteCommand) {
      throw cancellation;
    }
    if (command instanceof GetCommand) {
      return { Item: storedRun(current) };
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });

  await assert.rejects(
    store.resumeRun({
      ...scope(),
      run_id: runId,
      expected_revision: 3,
      expected_status: 'failed',
      resumed_at: '2026-08-19T12:04:00.000Z',
    }),
    hasControlPlaneError(
      'conflict',
      /cannot resume from revision 4 while running/,
      cancellation,
    ),
  );

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['TransactWriteCommand', 'GetCommand'],
    'only the diagnostic read may follow a canceled transaction',
  );
  assert.equal(transactionItems(client).length, 3);
});

test('respondToHitl atomically resolves the guarded request and enqueues run continuation', async () => {
  const request = hitlRequest();
  const response = hitlResponse();
  const client = new RecordingDocumentClient((command) => {
    if (!(command instanceof GetCommand)) {
      return {};
    }
    const key = command.input.Key as Record<string, unknown>;
    if (String(key['SK']).startsWith('HITL_HEAD#')) {
      return {
        Item: {
          ...key,
          entity: 'hitl-head',
          current_revision: request.revision,
        },
      };
    }
    if (String(key['SK']).startsWith('HITL_REQUEST#')) {
      return {
        Item: {
          ...key,
          entity: 'hitl-request',
          ...request,
        },
      };
    }
    return {};
  });
  const store = new DynamoControlPlane({
    tableName,
    client: client.asDocumentClient(),
  });

  await store.respondToHitl(response);

  assert.deepEqual(
    client.commands.map((command) => command.constructor.name),
    ['GetCommand', 'GetCommand', 'TransactWriteCommand'],
  );
  const items = transactionItems(client);
  assert.equal(items.length, 4);

  const headGuard = requiredConditionCheck(items[0]);
  assert.equal(headGuard.ConditionExpression, 'current_revision = :revision');
  assert.deepEqual(headGuard.ExpressionAttributeValues, { ':revision': 2 });

  const responsePut = requiredPut(items[1]);
  assert.equal(responsePut.ConditionExpression, 'attribute_not_exists(PK)');
  assert.equal(responsePut.Item?.['entity'], 'hitl-response');
  assert.deepEqual(
    {
      owner_id: responsePut.Item?.['owner_id'],
      application_id: responsePut.Item?.['application_id'],
      interaction_id: responsePut.Item?.['interaction_id'],
      run_id: responsePut.Item?.['run_id'],
      revision: responsePut.Item?.['revision'],
    },
    {
      owner_id: ownerId,
      application_id: applicationId,
      interaction_id: interactionId,
      run_id: runId,
      revision: 2,
    },
  );

  const requestUpdate = requiredUpdate(items[2]);
  assert.equal(
    requestUpdate.ConditionExpression,
    '#status = :pending AND run_id = :run AND revision = :revision',
  );
  assert.deepEqual(requestUpdate.ExpressionAttributeValues, {
    ':pending': 'pending',
    ':resolved': 'answered',
    ':run': runId,
    ':revision': 2,
  });

  assertOutbox(items[3], {
    eventId: `run.hitl:${runId}:${interactionId}:2`,
    command: 'execute',
    createdAt: response.submitted_at,
  });
});
