import { isDeepStrictEqual } from 'node:util';
import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
  type QueryCommandInput,
  type TransactWriteCommandInput,
} from '@aws-sdk/lib-dynamodb';
import type {
  HitlRequest,
  HitlResponse,
  HostedProgressEvent,
  IdempotencyRecord,
  InteractionId,
  Lease,
  RunId,
  RunSettingsSnapshot,
  StageCheckpoint,
  UserId,
} from '@threatforest/types';
import {
  alreadyExists,
  conflict,
  immutableRecord,
  invalidInput,
  leaseLost,
  notFound,
  staleRevision,
} from './errors.js';
import { encodeKeyPart, runLeaseResourceId, sequenceKey } from './keys.js';
import type {
  AcquireLeaseInput,
  ApplicationRecord,
  ApplicationSettingsRecord,
  ControlPlaneScope,
  IdempotencyClaim,
  IdempotencyCompletionInput,
  IdempotencyFailureInput,
  LeaseGuard,
  ReleaseLeaseInput,
  RenewLeaseInput,
  RunControlIntent,
  RunRecord,
  ResumeRunInput,
} from './models.js';
import type { ControlPlaneStore } from './store.js';

type Item = Record<string, unknown>;

export interface DynamoControlPlaneOptions {
  tableName: string;
  client: DynamoDBDocumentClient;
  applicationIndexName?: string;
}

const metadataFields = new Set(['PK', 'SK', 'GSI1PK', 'GSI1SK', 'entity', 'ttl']);

function partitionKey(scope: ControlPlaneScope): string {
  return `OWNER#${encodeKeyPart(scope.owner_id)}#APP#${encodeKeyPart(scope.application_id)}`;
}

function applicationSortKey(): string {
  return 'APPLICATION';
}

function settingsSortKey(): string {
  return 'APPLICATION_SETTINGS';
}

function runSortKey(runId: RunId): string {
  return `RUN#${encodeKeyPart(runId)}`;
}

function runSettingsSortKey(runId: RunId): string {
  return `${runSortKey(runId)}#SETTINGS`;
}

function runControlSortKey(runId: RunId): string {
  return `${runSortKey(runId)}#CONTROL`;
}

function checkpointPrefix(runId: RunId): string {
  return `${runSortKey(runId)}#CHECKPOINT#`;
}

function checkpointSortKey(checkpoint: StageCheckpoint): string {
  return `${checkpointPrefix(checkpoint.run_id)}${encodeKeyPart(checkpoint.stage_id)}#${sequenceKey(
    checkpoint.stage_version,
  )}#${sequenceKey(checkpoint.attempt)}`;
}

function eventPrefix(runId: RunId): string {
  return `${runSortKey(runId)}#EVENT#`;
}

function eventSortKey(event: HostedProgressEvent): string {
  return `${eventPrefix(event.run_id)}${sequenceKey(event.sequence)}`;
}

function leaseSortKey(resourceId: string): string {
  return `LEASE#${encodeKeyPart(resourceId)}`;
}

function idempotencySortKey(key: string): string {
  return `IDEMPOTENCY#${encodeKeyPart(key)}`;
}

function outboxSortKey(eventId: string): string {
  return `OUTBOX#${encodeKeyPart(eventId)}`;
}

function runCommandOutbox(
  scope: ControlPlaneScope,
  eventId: string,
  payload: Record<string, unknown>,
  createdAt: string,
): Item {
  return {
    ...key(scope, outboxSortKey(eventId)),
    entity: 'outbox-event',
    destination: 'run-command',
    event_id: eventId,
    payload,
    created_at: createdAt,
    ttl: Math.floor(Date.parse(createdAt) / 1000) + 30 * 24 * 60 * 60,
  };
}

function hitlHeadSortKey(interactionId: InteractionId): string {
  return `HITL_HEAD#${encodeKeyPart(interactionId)}`;
}

function hitlRequestPrefix(): string {
  return 'HITL_REQUEST#';
}

function hitlRequestSortKey(interactionId: InteractionId, revision: number): string {
  return `${hitlRequestPrefix()}${encodeKeyPart(interactionId)}#REV#${sequenceKey(revision)}`;
}

function hitlResponseSortKey(interactionId: InteractionId, revision: number): string {
  return `HITL_RESPONSE#${encodeKeyPart(interactionId)}#REV#${sequenceKey(revision)}`;
}

function key(scope: ControlPlaneScope, SK: string): { PK: string; SK: string } {
  return { PK: partitionKey(scope), SK };
}

function storedItem<T extends object>(
  scope: ControlPlaneScope,
  SK: string,
  entity: string,
  value: T,
  metadata: Item = {},
): Item {
  return { ...key(scope, SK), entity, ...metadata, ...value };
}

function recordFromItem<T>(item: Item): T {
  const record: Item = {};
  for (const [field, value] of Object.entries(item)) {
    if (!metadataFields.has(field)) {
      record[field] = value;
    }
  }
  return record as T;
}

function expiryTtl(expiresAt: string): number {
  const milliseconds = Date.parse(expiresAt);
  if (!Number.isFinite(milliseconds)) {
    throw invalidInput(`invalid expires_at timestamp: ${expiresAt}`);
  }
  return Math.floor(milliseconds / 1000);
}

function isConditionalFailure(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'ConditionalCheckFailedException' || error.name === 'TransactionCanceledException')
  );
}

function assertSameScope(left: ControlPlaneScope, right: ControlPlaneScope): void {
  if (left.owner_id !== right.owner_id || left.application_id !== right.application_id) {
    throw invalidInput('owner_id and application_id must match the requested scope');
  }
}

function validateRevision(nextRevision: number, expectedRevision: number): void {
  if (nextRevision !== expectedRevision + 1) {
    throw invalidInput(`revision must advance from ${expectedRevision} to ${expectedRevision + 1}`);
  }
}

function validateHitlResponse(response: HitlResponse): void {
  if (response.action === 'skip' && response.text !== null) {
    throw invalidInput('a skipped HITL response must have null text');
  }
  if (response.action === 'submit' && response.text === null) {
    throw invalidInput('a submitted HITL response must include text');
  }
}

export class DynamoControlPlane implements ControlPlaneStore {
  readonly #tableName: string;
  readonly #client: DynamoDBDocumentClient;
  readonly #applicationIndexName: string;

  constructor(options: DynamoControlPlaneOptions) {
    this.#tableName = options.tableName;
    this.#client = options.client;
    this.#applicationIndexName = options.applicationIndexName ?? 'GSI1';
  }

  async createApplication(application: ApplicationRecord): Promise<ApplicationRecord> {
    if (application.revision !== 1) {
      throw invalidInput('a new application must start at revision 1');
    }
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(application, applicationSortKey(), 'application', application, {
            GSI1PK: `OWNER#${encodeKeyPart(application.owner_id)}`,
            GSI1SK: `APP#${encodeKeyPart(application.application_id)}`,
          }),
          ConditionExpression: 'attribute_not_exists(PK)',
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw alreadyExists(`application ${application.application_id} already exists`);
      }
      throw error;
    }
    return structuredClone(application);
  }

  async getApplication(scope: ControlPlaneScope): Promise<ApplicationRecord | null> {
    return this.#get(scope, applicationSortKey());
  }

  async listApplications(ownerId: UserId): Promise<ApplicationRecord[]> {
    const items = await this.#queryAll({
      TableName: this.#tableName,
      IndexName: this.#applicationIndexName,
      KeyConditionExpression: 'GSI1PK = :owner AND begins_with(GSI1SK, :application)',
      ExpressionAttributeValues: {
        ':owner': `OWNER#${encodeKeyPart(ownerId)}`,
        ':application': 'APP#',
      },
    });
    return items
      .filter((item) => item.entity === 'application')
      .map((item) => recordFromItem<ApplicationRecord>(item))
      .sort((left, right) => left.application_id.localeCompare(right.application_id));
  }

  async updateApplication(
    application: ApplicationRecord,
    expectedRevision: number,
  ): Promise<ApplicationRecord> {
    validateRevision(application.revision, expectedRevision);
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(application, applicationSortKey(), 'application', application, {
            GSI1PK: `OWNER#${encodeKeyPart(application.owner_id)}`,
            GSI1SK: `APP#${encodeKeyPart(application.application_id)}`,
          }),
          ConditionExpression: 'revision = :expected AND created_at = :created',
          ExpressionAttributeValues: {
            ':expected': expectedRevision,
            ':created': application.created_at,
          },
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw conflict(`application revision is not ${expectedRevision}`, error);
      }
      throw error;
    }
    return structuredClone(application);
  }

  async putApplicationSettings(
    settings: ApplicationSettingsRecord,
    expectedRevision: number | null,
  ): Promise<ApplicationSettingsRecord> {
    if (expectedRevision === null && settings.revision !== 1) {
      throw invalidInput('new application settings must start at revision 1');
    }
    if (expectedRevision !== null) {
      validateRevision(settings.revision, expectedRevision);
    }
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(settings, settingsSortKey(), 'application-settings', settings),
          ConditionExpression:
            expectedRevision === null ? 'attribute_not_exists(PK)' : 'revision = :expected',
          ...(expectedRevision === null
            ? {}
            : { ExpressionAttributeValues: { ':expected': expectedRevision } }),
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw conflict(
          expectedRevision === null
            ? 'application settings already exist'
            : `settings revision is not ${expectedRevision}`,
          error,
        );
      }
      throw error;
    }
    return structuredClone(settings);
  }

  async getApplicationSettings(
    scope: ControlPlaneScope,
  ): Promise<ApplicationSettingsRecord | null> {
    return this.#get(scope, settingsSortKey());
  }

  async putRunSettingsSnapshot(snapshot: RunSettingsSnapshot): Promise<RunSettingsSnapshot> {
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(snapshot, runSettingsSortKey(snapshot.run_id), 'run-settings', snapshot),
          ConditionExpression: 'attribute_not_exists(PK)',
        }),
      );
      return structuredClone(snapshot);
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      const current = await this.getRunSettingsSnapshot(snapshot, snapshot.run_id);
      if (current !== null && isDeepStrictEqual(current, snapshot)) {
        return current;
      }
      throw immutableRecord(`settings snapshot for run ${snapshot.run_id} is immutable`);
    }
  }

  async getRunSettingsSnapshot(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunSettingsSnapshot | null> {
    return this.#get(scope, runSettingsSortKey(runId));
  }

  async createRun(run: RunRecord): Promise<RunRecord> {
    if (run.revision !== 1 || run.last_event_sequence !== -1) {
      throw invalidInput('a new run must start at revision 1 with last_event_sequence -1');
    }
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(run, runSortKey(run.run_id), 'run', run),
          ConditionExpression: 'attribute_not_exists(PK)',
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw alreadyExists(`run ${run.run_id} already exists`);
      }
      throw error;
    }
    return structuredClone(run);
  }

  async createRunDispatch(
    run: RunRecord,
    settings: RunSettingsSnapshot,
  ): Promise<RunRecord> {
    if (
      run.revision !== 1 ||
      run.last_event_sequence !== -1 ||
      settings.run_id !== run.run_id ||
      settings.owner_id !== run.owner_id ||
      settings.application_id !== run.application_id
    ) {
      throw invalidInput('run dispatch state is inconsistent');
    }
    const eventId = `run.execute:${run.run_id}:${run.revision}`;
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(run, runSortKey(run.run_id), 'run', run),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(
                  settings,
                  runSettingsSortKey(run.run_id),
                  'run-settings',
                  settings,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: runCommandOutbox(
                  run,
                  eventId,
                  {
                    schema_version: 1,
                    command: 'execute',
                    owner_id: run.owner_id,
                    application_id: run.application_id,
                    run_id: run.run_id,
                  },
                  run.created_at,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw alreadyExists(`run ${run.run_id} already exists`);
      }
      throw error;
    }
    return structuredClone(run);
  }

  async getRun(scope: ControlPlaneScope, runId: RunId): Promise<RunRecord | null> {
    return this.#get(scope, runSortKey(runId));
  }

  async requestRunControl(intent: RunControlIntent): Promise<RunControlIntent> {
    if ((await this.getRun(intent, intent.run_id)) === null) {
      throw notFound(`run ${intent.run_id} was not found`);
    }
    try {
      const eventId =
        `run.control:${intent.run_id}:${intent.action}:${intent.requested_at}`;
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.#tableName,
                Key: key(intent, runControlSortKey(intent.run_id)),
                UpdateExpression:
                  'SET entity = :entity, owner_id = :owner, application_id = :application, ' +
                  'run_id = :run, #action = :requested, requested_at = :requestedAt',
                ConditionExpression:
                  'attribute_not_exists(#action) OR #action = :requested OR ' +
                  '(#action = :pause AND :requested = :stop)',
                ExpressionAttributeNames: { '#action': 'action' },
                ExpressionAttributeValues: {
                  ':entity': 'run-control',
                  ':owner': intent.owner_id,
                  ':application': intent.application_id,
                  ':run': intent.run_id,
                  ':requested': intent.action,
                  ':requestedAt': intent.requested_at,
                  ':pause': 'pause',
                  ':stop': 'stop',
                },
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: runCommandOutbox(
                  intent,
                  eventId,
                  {
                    schema_version: 1,
                    command: intent.action,
                    owner_id: intent.owner_id,
                    application_id: intent.application_id,
                    run_id: intent.run_id,
                  },
                  intent.requested_at,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
          ],
        }),
      );
      return intent;
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      const current = await this.getRunControl(intent, intent.run_id);
      if (current !== null && current.action === 'stop') {
        return current;
      }
      throw conflict(`run control for ${intent.run_id} could not be persisted`, error);
    }
  }

  async getRunControl(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<RunControlIntent | null> {
    return this.#get(scope, runControlSortKey(runId));
  }

  async updateRun(run: RunRecord, expectedRevision: number, lease: LeaseGuard): Promise<RunRecord> {
    assertSameScope(run, lease);
    this.#validateRunLeaseResource(lease, run.run_id);
    validateRevision(run.revision, expectedRevision);
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            this.#leaseCondition(lease),
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(run, runSortKey(run.run_id), 'run', run),
                ConditionExpression:
                  'revision = :expected AND created_at = :created AND last_event_sequence = :last',
                ExpressionAttributeValues: {
                  ':expected': expectedRevision,
                  ':created': run.created_at,
                  ':last': run.last_event_sequence,
                },
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        await this.#throwIfLeaseLost(lease, error);
        throw conflict(`run revision is not ${expectedRevision}`, error);
      }
      throw error;
    }
    return structuredClone(run);
  }

  async resumeRun(input: ResumeRunInput): Promise<RunRecord> {
    const manuallyPaused = input.expected_status === 'awaiting_input';
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.#tableName,
                Key: key(input, runSortKey(input.run_id)),
                UpdateExpression:
                  'SET #status = :queued, revision = :next, updated_at = :resumed, ' +
                  'completed_at = :null, error_code = :null, error_message = :null',
                ConditionExpression:
                  'revision = :expected AND #status = :expectedStatus',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':queued': 'queued',
                  ':expectedStatus': input.expected_status,
                  ':expected': input.expected_revision,
                  ':next': input.expected_revision + 1,
                  ':resumed': input.resumed_at,
                  ':null': null,
                },
              },
            },
            {
              Delete: {
                TableName: this.#tableName,
                Key: key(input, runControlSortKey(input.run_id)),
                ...(manuallyPaused
                  ? {
                      ConditionExpression: '#action = :pause',
                      ExpressionAttributeNames: { '#action': 'action' },
                      ExpressionAttributeValues: { ':pause': 'pause' },
                    }
                  : {}),
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: runCommandOutbox(
                  input,
                  `run.execute:${input.run_id}:${input.expected_revision + 1}`,
                  {
                    schema_version: 1,
                    command: 'execute',
                    owner_id: input.owner_id,
                    application_id: input.application_id,
                    run_id: input.run_id,
                  },
                  input.resumed_at,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        const current = await this.getRun(input, input.run_id);
        if (current === null) {
          throw notFound(`run ${input.run_id} was not found`);
        }
        throw conflict(
          `run ${input.run_id} cannot resume from revision ${current.revision} while ${current.status}`,
          error,
        );
      }
      throw error;
    }
    const resumed = await this.getRun(input, input.run_id);
    if (resumed === null) {
      throw notFound(`run ${input.run_id} was not found after resume`);
    }
    return resumed;
  }

  async putCheckpoint(checkpoint: StageCheckpoint, lease: LeaseGuard): Promise<StageCheckpoint> {
    assertSameScope(checkpoint, lease);
    this.#validateRunLeaseResource(lease, checkpoint.run_id);
    if (checkpoint.fencing_token !== lease.fencing_token) {
      throw leaseLost('checkpoint fencing_token does not match the active lease');
    }
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            this.#leaseCondition(lease),
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(
                  checkpoint,
                  checkpointSortKey(checkpoint),
                  'checkpoint',
                  checkpoint,
                ),
                ConditionExpression:
                  'attribute_not_exists(PK) OR (#status <> :completed AND fencing_token <= :token)',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':completed': 'completed',
                  ':token': checkpoint.fencing_token,
                },
              },
            },
          ],
        }),
      );
      return structuredClone(checkpoint);
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      await this.#throwIfLeaseLost(lease, error);
      const current = await this.#get<StageCheckpoint>(checkpoint, checkpointSortKey(checkpoint));
      if (current?.status === 'completed') {
        if (isDeepStrictEqual(current, checkpoint)) {
          return current;
        }
        throw immutableRecord('a completed checkpoint cannot be changed');
      }
      if (current !== null && current.fencing_token > checkpoint.fencing_token) {
        throw leaseLost('checkpoint was already written by a newer lease holder', error);
      }
      throw conflict('checkpoint conditional write failed', error);
    }
  }

  async listCheckpoints(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<StageCheckpoint[]> {
    const items = await this.#queryByPrefix(scope, checkpointPrefix(runId));
    return items
      .filter((item) => item.entity === 'checkpoint')
      .map((item) => recordFromItem<StageCheckpoint>(item))
      .sort(
        (left, right) =>
          left.started_at.localeCompare(right.started_at) ||
          left.stage_id.localeCompare(right.stage_id) ||
          left.attempt - right.attempt,
      );
  }

  async appendEvent(event: HostedProgressEvent, lease: LeaseGuard): Promise<HostedProgressEvent> {
    assertSameScope(event, lease);
    this.#validateRunLeaseResource(lease, event.run_id);
    const previousSequence = event.sequence - 1;
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            this.#leaseCondition(lease),
            {
              Update: {
                TableName: this.#tableName,
                Key: key(event, runSortKey(event.run_id)),
                UpdateExpression: 'SET last_event_sequence = :sequence',
                ConditionExpression:
                  'attribute_exists(PK) AND last_event_sequence = :previous_sequence',
                ExpressionAttributeValues: {
                  ':sequence': event.sequence,
                  ':previous_sequence': previousSequence,
                },
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(event, eventSortKey(event), 'event', event),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        await this.#throwIfLeaseLost(lease, error);
        const run = await this.getRun(event, event.run_id);
        const expected = (run?.last_event_sequence ?? -1) + 1;
        throw conflict(`event sequence must be ${expected}, not ${event.sequence}`, error);
      }
      throw error;
    }
    return structuredClone(event);
  }

  async listEvents(
    scope: ControlPlaneScope,
    runId: RunId,
    afterSequence = -1,
  ): Promise<HostedProgressEvent[]> {
    const items = await this.#queryByPrefix(scope, eventPrefix(runId));
    return items
      .filter((item) => item.entity === 'event')
      .map((item) => recordFromItem<HostedProgressEvent>(item))
      .filter((event) => event.sequence > afterSequence)
      .sort((left, right) => left.sequence - right.sequence);
  }

  async acquireLease(input: AcquireLeaseInput): Promise<Lease> {
    if (input.expires_at <= input.acquired_at) {
      throw invalidInput('lease expires_at must be after acquired_at');
    }
    try {
      const result = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key(input, leaseSortKey(input.resource_id)),
          UpdateExpression:
            'SET entity = :entity, schema_version = :schema, owner_id = :owner, application_id = :application, resource_id = :resource, lease_owner_id = :lease_owner, acquired_at = :acquired, expires_at = :expires, fencing_token = if_not_exists(fencing_token, :zero) + :one',
          ConditionExpression: 'attribute_not_exists(PK) OR expires_at <= :acquired',
          ExpressionAttributeValues: {
            ':entity': 'lease',
            ':schema': 1,
            ':owner': input.owner_id,
            ':application': input.application_id,
            ':resource': input.resource_id,
            ':lease_owner': input.lease_owner_id,
            ':acquired': input.acquired_at,
            ':expires': input.expires_at,
            ':zero': 0,
            ':one': 1,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return recordFromItem<Lease>(result.Attributes as Item);
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw conflict(`resource ${input.resource_id} is already leased`, error);
      }
      throw error;
    }
  }

  async renewLease(input: RenewLeaseInput): Promise<Lease> {
    if (input.expires_at <= input.observed_at) {
      throw invalidInput('renewed expires_at must be after observed_at');
    }
    try {
      const result = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key(input, leaseSortKey(input.resource_id)),
          UpdateExpression: 'SET expires_at = :expires',
          ConditionExpression:
            'lease_owner_id = :owner AND fencing_token = :token AND expires_at > :observed',
          ExpressionAttributeValues: {
            ':owner': input.lease_owner_id,
            ':token': input.fencing_token,
            ':observed': input.observed_at,
            ':expires': input.expires_at,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return recordFromItem<Lease>(result.Attributes as Item);
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw leaseLost(`lease for ${input.resource_id} is no longer active`, error);
      }
      throw error;
    }
  }

  async releaseLease(input: ReleaseLeaseInput): Promise<Lease> {
    try {
      const result = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key(input, leaseSortKey(input.resource_id)),
          UpdateExpression: 'SET expires_at = :released',
          ConditionExpression:
            'lease_owner_id = :owner AND fencing_token = :token AND expires_at > :released',
          ExpressionAttributeValues: {
            ':owner': input.lease_owner_id,
            ':token': input.fencing_token,
            ':released': input.released_at,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return recordFromItem<Lease>(result.Attributes as Item);
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw leaseLost(`lease for ${input.resource_id} is no longer active`, error);
      }
      throw error;
    }
  }

  async getLease(scope: ControlPlaneScope, resourceId: string): Promise<Lease | null> {
    return this.#get(scope, leaseSortKey(resourceId));
  }

  async claimIdempotency(
    record: IdempotencyRecord,
    observedAt: string,
  ): Promise<IdempotencyClaim> {
    if (record.status !== 'in_progress') {
      throw invalidInput('a new idempotency claim must be in_progress');
    }
    if (record.expires_at <= observedAt) {
      throw invalidInput('idempotency record must expire after observedAt');
    }
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: storedItem(record, idempotencySortKey(record.key), 'idempotency', record, {
            ttl: expiryTtl(record.expires_at),
          }),
          ConditionExpression: 'attribute_not_exists(PK) OR expires_at <= :observed',
          ExpressionAttributeValues: { ':observed': observedAt },
        }),
      );
      return { acquired: true, record: structuredClone(record) };
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      const current = await this.getIdempotency(record, record.key);
      if (
        current !== null &&
        current.expires_at > observedAt &&
        current.operation === record.operation &&
        current.request_hash === record.request_hash
      ) {
        return { acquired: false, record: current };
      }
      throw conflict(`idempotency key ${record.key} was used for a different request`, error);
    }
  }

  async completeIdempotency(input: IdempotencyCompletionInput): Promise<IdempotencyRecord> {
    try {
      const result = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key(input, idempotencySortKey(input.key)),
          UpdateExpression: 'SET #status = :completed, response_artifact = :artifact',
          ConditionExpression:
            '#status = :in_progress AND request_hash = :hash AND created_at = :created',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':in_progress': 'in_progress',
            ':completed': 'completed',
            ':hash': input.request_hash,
            ':created': input.claim_created_at,
            ':artifact': input.response_artifact,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return recordFromItem<IdempotencyRecord>(result.Attributes as Item);
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      const current = await this.getIdempotency(input, input.key);
      if (
        current?.status === 'completed' &&
        current.request_hash === input.request_hash &&
        current.created_at === input.claim_created_at &&
        isDeepStrictEqual(current.response_artifact, input.response_artifact)
      ) {
        return current;
      }
      throw conflict(`idempotency claim for ${input.key} is stale or already resolved`, error);
    }
  }

  async failIdempotency(input: IdempotencyFailureInput): Promise<IdempotencyRecord> {
    try {
      const result = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key(input, idempotencySortKey(input.key)),
          UpdateExpression: 'SET #status = :failed, expires_at = :expired',
          ConditionExpression:
            '#status = :in_progress AND request_hash = :hash AND created_at = :created',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':in_progress': 'in_progress',
            ':failed': 'failed',
            ':expired': input.claim_created_at,
            ':hash': input.request_hash,
            ':created': input.claim_created_at,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return recordFromItem<IdempotencyRecord>(result.Attributes as Item);
    } catch (error) {
      if (isConditionalFailure(error)) {
        throw conflict(`idempotency claim for ${input.key} is stale or already resolved`, error);
      }
      throw error;
    }
  }

  async getIdempotency(
    scope: ControlPlaneScope,
    idempotencyKey: string,
  ): Promise<IdempotencyRecord | null> {
    return this.#get(scope, idempotencySortKey(idempotencyKey));
  }

  async createHitlRequest(request: HitlRequest, lease: LeaseGuard): Promise<HitlRequest> {
    assertSameScope(request, lease);
    this.#validateRunLeaseResource(lease, request.run_id);
    if (request.fencing_token !== lease.fencing_token) {
      throw leaseLost('HITL request fencing_token does not match the active lease');
    }
    if (request.status !== 'pending') {
      throw invalidInput('a new HITL request must be pending');
    }

    const headKey = hitlHeadSortKey(request.interaction_id);
    const head = await this.#getRaw(request, headKey);
    const currentRevision = head?.current_revision as number | undefined;
    const expectedRevision = currentRevision === undefined ? 1 : currentRevision + 1;
    if (request.revision !== expectedRevision) {
      throw staleRevision(`HITL revision must be ${expectedRevision}, not ${request.revision}`);
    }

    let previous: HitlRequest | null = null;
    if (currentRevision !== undefined) {
      previous = await this.#get(
        request,
        hitlRequestSortKey(request.interaction_id, currentRevision),
      );
      if (previous === null || previous.run_id !== request.run_id) {
        throw conflict('an interaction_id cannot be reused for a different run');
      }
    }

    const items: NonNullable<TransactWriteCommandInput['TransactItems']> = [
      this.#leaseCondition(lease),
      {
        Put: {
          TableName: this.#tableName,
          Item: storedItem(
            request,
            hitlRequestSortKey(request.interaction_id, request.revision),
            'hitl-request',
            request,
          ),
          ConditionExpression: 'attribute_not_exists(PK)',
        },
      },
      {
        Put: {
          TableName: this.#tableName,
          Item: {
            ...key(request, headKey),
            entity: 'hitl-head',
            owner_id: request.owner_id,
            application_id: request.application_id,
            interaction_id: request.interaction_id,
            run_id: request.run_id,
            current_revision: request.revision,
          },
          ConditionExpression:
            currentRevision === undefined
              ? 'attribute_not_exists(PK)'
              : 'current_revision = :current',
          ...(currentRevision === undefined
            ? {}
            : { ExpressionAttributeValues: { ':current': currentRevision } }),
        },
      },
    ];
    if (previous?.status === 'pending' && currentRevision !== undefined) {
      items.push({
        Update: {
          TableName: this.#tableName,
          Key: key(request, hitlRequestSortKey(request.interaction_id, currentRevision)),
          UpdateExpression: 'SET #status = :superseded',
          ConditionExpression: '#status = :pending',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: { ':pending': 'pending', ':superseded': 'superseded' },
        },
      });
    }

    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: items,
        }),
      );
    } catch (error) {
      if (isConditionalFailure(error)) {
        await this.#throwIfLeaseLost(lease, error);
        const latestHead = await this.#getRaw(request, headKey);
        if (latestHead?.current_revision !== currentRevision) {
          throw staleRevision('HITL interaction was revised concurrently');
        }
        throw conflict('HITL request conditional write failed', error);
      }
      throw error;
    }
    return structuredClone(request);
  }

  async respondToHitl(response: HitlResponse): Promise<HitlResponse> {
    validateHitlResponse(response);
    const headKey = hitlHeadSortKey(response.interaction_id);
    const head = await this.#getRaw(response, headKey);
    if (head?.current_revision !== response.revision) {
      throw staleRevision(`HITL revision ${response.revision} is no longer current`);
    }
    const request = await this.#get<HitlRequest>(
      response,
      hitlRequestSortKey(response.interaction_id, response.revision),
    );
    if (request === null || request.run_id !== response.run_id) {
      throw notFound('matching HITL request was not found');
    }
    if (request.status !== 'pending') {
      const existing = await this.getHitlResponse(
        response,
        response.interaction_id,
        response.revision,
      );
      if (existing !== null) {
        throw alreadyExists('HITL request already has a response');
      }
      throw conflict(`HITL request is ${request.status}`);
    }

    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              ConditionCheck: {
                TableName: this.#tableName,
                Key: key(response, headKey),
                ConditionExpression: 'current_revision = :revision',
                ExpressionAttributeValues: { ':revision': response.revision },
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: storedItem(
                  response,
                  hitlResponseSortKey(response.interaction_id, response.revision),
                  'hitl-response',
                  response,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
            {
              Update: {
                TableName: this.#tableName,
                Key: key(
                  response,
                  hitlRequestSortKey(response.interaction_id, response.revision),
                ),
                UpdateExpression: 'SET #status = :resolved',
                ConditionExpression:
                  '#status = :pending AND run_id = :run AND revision = :revision',
                ExpressionAttributeNames: { '#status': 'status' },
                ExpressionAttributeValues: {
                  ':pending': 'pending',
                  ':resolved': response.action === 'skip' ? 'skipped' : 'answered',
                  ':run': response.run_id,
                  ':revision': response.revision,
                },
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: runCommandOutbox(
                  response,
                  `run.hitl:${response.run_id}:${response.interaction_id}:${response.revision}`,
                  {
                    schema_version: 1,
                    command: 'execute',
                    owner_id: response.owner_id,
                    application_id: response.application_id,
                    run_id: response.run_id,
                  },
                  response.submitted_at,
                ),
                ConditionExpression: 'attribute_not_exists(PK)',
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (!isConditionalFailure(error)) {
        throw error;
      }
      const existing = await this.getHitlResponse(
        response,
        response.interaction_id,
        response.revision,
      );
      if (existing !== null) {
        throw alreadyExists('HITL request already has a response');
      }
      const latestHead = await this.#getRaw(response, headKey);
      if (latestHead?.current_revision !== response.revision) {
        throw staleRevision(`HITL revision ${response.revision} is no longer current`);
      }
      throw conflict('HITL response conditional write failed', error);
    }
    return structuredClone(response);
  }

  async getHitlRequest(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision?: number,
  ): Promise<HitlRequest | null> {
    let resolvedRevision = revision;
    if (resolvedRevision === undefined) {
      const head = await this.#getRaw(scope, hitlHeadSortKey(interactionId));
      resolvedRevision = head?.current_revision as number | undefined;
    }
    if (resolvedRevision === undefined) {
      return null;
    }
    return this.#get(scope, hitlRequestSortKey(interactionId, resolvedRevision));
  }

  async getHitlResponse(
    scope: ControlPlaneScope,
    interactionId: InteractionId,
    revision: number,
  ): Promise<HitlResponse | null> {
    return this.#get(scope, hitlResponseSortKey(interactionId, revision));
  }

  async listPendingHitl(scope: ControlPlaneScope, runId: RunId): Promise<HitlRequest[]> {
    const items = await this.#queryByPrefix(scope, hitlRequestPrefix());
    return items
      .filter((item) => item.entity === 'hitl-request')
      .map((item) => recordFromItem<HitlRequest>(item))
      .filter((request) => request.run_id === runId && request.status === 'pending')
      .sort((left, right) => left.created_at.localeCompare(right.created_at));
  }

  async #get<T>(scope: ControlPlaneScope, SK: string): Promise<T | null> {
    const item = await this.#getRaw(scope, SK);
    return item === null ? null : recordFromItem<T>(item);
  }

  async #getRaw(scope: ControlPlaneScope, SK: string): Promise<Item | null> {
    const result = await this.#client.send(
      new GetCommand({
        TableName: this.#tableName,
        Key: key(scope, SK),
        ConsistentRead: true,
      }),
    );
    return (result.Item as Item | undefined) ?? null;
  }

  async #queryByPrefix(scope: ControlPlaneScope, prefix: string): Promise<Item[]> {
    return this.#queryAll({
      TableName: this.#tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
      ExpressionAttributeValues: { ':pk': partitionKey(scope), ':prefix': prefix },
      ConsistentRead: true,
    });
  }

  async #queryAll(input: QueryCommandInput): Promise<Item[]> {
    const items: Item[] = [];
    let ExclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const result = await this.#client.send(
        new QueryCommand({ ...input, ExclusiveStartKey }),
      );
      items.push(...((result.Items as Item[] | undefined) ?? []));
      ExclusiveStartKey = result.LastEvaluatedKey;
    } while (ExclusiveStartKey !== undefined);
    return items;
  }

  #validateRunLeaseResource(lease: LeaseGuard, runId: RunId): void {
    if (lease.resource_id !== runLeaseResourceId(runId)) {
      throw invalidInput(`run mutations require lease resource ${runLeaseResourceId(runId)}`);
    }
  }

  #leaseCondition(lease: LeaseGuard): NonNullable<TransactWriteCommandInput['TransactItems']>[number] {
    return {
      ConditionCheck: {
        TableName: this.#tableName,
        Key: key(lease, leaseSortKey(lease.resource_id)),
        ConditionExpression:
          'lease_owner_id = :lease_owner AND fencing_token = :token AND expires_at > :observed',
        ExpressionAttributeValues: {
          ':lease_owner': lease.lease_owner_id,
          ':token': lease.fencing_token,
          ':observed': lease.observed_at,
        },
      },
    };
  }

  async #throwIfLeaseLost(lease: LeaseGuard, cause: unknown): Promise<void> {
    const current = await this.getLease(lease, lease.resource_id);
    if (
      current === null ||
      current.lease_owner_id !== lease.lease_owner_id ||
      current.fencing_token !== lease.fencing_token ||
      current.expires_at <= lease.observed_at
    ) {
      throw leaseLost(`lease for ${lease.resource_id} is no longer active`, cause);
    }
  }
}
