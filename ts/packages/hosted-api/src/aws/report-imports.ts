import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import { SendMessageCommand, type SQSClient } from '@aws-sdk/client-sqs';
import type { UploadId, UserId } from '@threatforest/types';
import { encodeKeyPart } from '@threatforest/control-plane';
import type {
  MultipartCompletionRecord,
  SignedMultipartPart,
} from '../contracts.js';
import type {
  ReportImportDispatcher,
  ReportImportSession,
  ReportImportStore,
  ReportImportWorkerLease,
} from '../report-import-service.js';

function partition(ownerId: UserId): string {
  return `HOSTED#OWNER#${encodeKeyPart(ownerId)}`;
}

function sortKey(importId: UploadId): string {
  return `REPORT_IMPORT#${encodeKeyPart(importId)}`;
}

export class DynamoReportImportStore implements ReportImportStore {
  readonly #tableName: string;
  readonly #client: DynamoDBDocumentClient;

  constructor(tableName: string, client: DynamoDBDocumentClient) {
    this.#tableName = tableName;
    this.#client = client;
  }

  async get(
    ownerId: UserId,
    importId: UploadId,
  ): Promise<ReportImportSession | null> {
    const response = await this.#client.send(
      new GetCommand({
        TableName: this.#tableName,
        Key: { PK: partition(ownerId), SK: sortKey(importId) },
        ConsistentRead: true,
      }),
    );
    return response.Item === undefined
      ? null
      : structuredClone(response.Item.session as ReportImportSession);
  }

  async put(session: ReportImportSession): Promise<void> {
    const item = {
      PK: partition(session.ownerId),
      SK: sortKey(session.importId),
      entity: 'hosted-report-import',
      owner_id: session.ownerId,
      import_id: session.importId,
      status: session.status,
      created_at: session.createdAt,
      updated_at: session.updatedAt,
      session,
    };
    if (session.status !== 'processing') {
      await this.#client.send(
        new PutCommand({ TableName: this.#tableName, Item: item }),
      );
      return;
    }
    const eventId = `report.import:${session.ownerId}:${session.importId}`;
    await this.#client.send(
      new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: this.#tableName, Item: item } },
          {
            Put: {
              TableName: this.#tableName,
              Item: {
                PK: partition(session.ownerId),
                SK: `OUTBOX#${encodeKeyPart(eventId)}`,
                entity: 'outbox-event',
                destination: 'report-import',
                event_id: eventId,
                payload: {
                  schemaVersion: 1,
                  ownerId: session.ownerId,
                  importId: session.importId,
                  enqueuedAt: session.updatedAt,
                },
                created_at: session.updatedAt,
                ttl:
                  Math.floor(Date.parse(session.updatedAt) / 1000) +
                  30 * 24 * 60 * 60,
              },
            },
          },
        ],
      }),
    );
  }

  async recordSignedPart(
    ownerId: UserId,
    importId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<ReportImportSession | null> {
    try {
      const response = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: { PK: partition(ownerId), SK: sortKey(importId) },
          UpdateExpression:
            'SET #session.#signedParts.#partNumber = :signedPart, ' +
            '#session.#sessionStatus = :uploading, ' +
            '#session.#sessionUpdatedAt = :signedAt, ' +
            '#status = :uploading, #itemUpdatedAt = :signedAt',
          ConditionExpression:
            '#status IN (:pending, :uploading) AND ' +
            'attribute_not_exists(#session.#completion)',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#signedParts': 'signedParts',
            '#partNumber': String(part.partNumber),
            '#completion': 'completion',
            '#sessionStatus': 'status',
            '#sessionUpdatedAt': 'updatedAt',
            '#status': 'status',
            '#itemUpdatedAt': 'updated_at',
          },
          ExpressionAttributeValues: {
            ':signedPart': {
              sizeBytes: part.sizeBytes,
              checksumSha256: part.checksumSha256,
              signedAt,
            },
            ':signedAt': signedAt,
            ':pending': 'pending',
            ':uploading': 'uploading',
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return response.Attributes?.session === undefined
        ? null
        : structuredClone(
            response.Attributes.session as ReportImportSession,
          );
    } catch (error) {
      if (isConditionalFailure(error)) {
        return null;
      }
      throw error;
    }
  }

  async claimCompletion(
    ownerId: UserId,
    importId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<ReportImportSession | null> {
    try {
      const response = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: { PK: partition(ownerId), SK: sortKey(importId) },
          UpdateExpression:
            'SET #session.#completion = :completion, ' +
            '#session.#sessionUpdatedAt = :claimedAt, ' +
            '#itemUpdatedAt = :claimedAt',
          ConditionExpression:
            '#status IN (:pending, :uploading) AND (' +
            'attribute_not_exists(#session.#completion) OR ' +
            'attribute_not_exists(#session.#completion.#claimId) OR ' +
            '#session.#completion.#claimId = :claimId OR ' +
            '#session.#completion.#claimExpiresAt <= :claimedAt)',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#completion': 'completion',
            '#claimId': 'claimId',
            '#claimExpiresAt': 'claimExpiresAt',
            '#sessionUpdatedAt': 'updatedAt',
            '#itemUpdatedAt': 'updated_at',
            '#status': 'status',
          },
          ExpressionAttributeValues: {
            ':completion': completion,
            ':claimedAt': claimedAt,
            ':claimId': completion.claimId,
            ':pending': 'pending',
            ':uploading': 'uploading',
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return response.Attributes?.session === undefined
        ? null
        : structuredClone(
            response.Attributes.session as ReportImportSession,
          );
    } catch (error) {
      if (isConditionalFailure(error)) {
        return null;
      }
      throw error;
    }
  }

  async acquireProcessingLease(
    ownerId: UserId,
    importId: UploadId,
    lease: ReportImportWorkerLease,
  ): Promise<ReportImportSession | null> {
    try {
      const response = await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: { PK: partition(ownerId), SK: sortKey(importId) },
          UpdateExpression:
            'SET #session.#workerLease = :lease, ' +
            '#session.#sessionUpdatedAt = :updatedAt, ' +
            '#itemUpdatedAt = :updatedAt',
          ConditionExpression:
            '#status = :processing AND ' +
            '(attribute_not_exists(#session.#workerLease) OR ' +
            '#session.#workerLease = :null OR ' +
            '#session.#workerLease.#expiresAt <= :acquiredAt)',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#workerLease': 'workerLease',
            '#expiresAt': 'expiresAt',
            '#status': 'status',
            '#sessionUpdatedAt': 'updatedAt',
            '#itemUpdatedAt': 'updated_at',
          },
          ExpressionAttributeValues: {
            ':lease': lease,
            ':updatedAt': lease.acquiredAt,
            ':acquiredAt': lease.acquiredAt,
            ':processing': 'processing',
            ':null': null,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      if (response.Attributes?.session === undefined) {
        throw new Error('DynamoDB did not return the acquired report import.');
      }
      return structuredClone(response.Attributes.session as ReportImportSession);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  async saveLeased(
    session: ReportImportSession,
    leaseId: string,
  ): Promise<boolean> {
    try {
      await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: {
            PK: partition(session.ownerId),
            SK: sortKey(session.importId),
          },
          UpdateExpression:
            'SET #session = :session, #status = :status, ' +
            '#updatedAt = :updatedAt',
          ConditionExpression:
            '#session.#workerLease.#leaseId = :leaseId',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#workerLease': 'workerLease',
            '#leaseId': 'leaseId',
            '#status': 'status',
            '#updatedAt': 'updated_at',
          },
          ExpressionAttributeValues: {
            ':session': session,
            ':status': session.status,
            ':updatedAt': session.updatedAt,
            ':leaseId': leaseId,
          },
        }),
      );
      return true;
    } catch (error) {
      if (isConditionalFailure(error)) return false;
      throw error;
    }
  }

  async list(ownerId: UserId): Promise<ReportImportSession[]> {
    const sessions: ReportImportSession[] = [];
    let startKey: Record<string, unknown> | undefined;
    do {
      const response = await this.#client.send(
        new QueryCommand({
          TableName: this.#tableName,
          KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
          ExpressionAttributeValues: {
            ':pk': partition(ownerId),
            ':prefix': 'REPORT_IMPORT#',
          },
          ExclusiveStartKey: startKey,
          ConsistentRead: true,
        }),
      );
      sessions.push(
        ...(response.Items ?? []).map(
          (item) => structuredClone(item.session as ReportImportSession),
        ),
      );
      startKey = response.LastEvaluatedKey;
    } while (startKey !== undefined);
    return sessions.sort((left, right) =>
      right.createdAt.localeCompare(left.createdAt),
    );
  }
}

export class SqsReportImportDispatcher implements ReportImportDispatcher {
  readonly #client: SQSClient;
  readonly #queueUrl: string;
  readonly #now: () => Date;

  constructor(client: SQSClient, queueUrl: string, now = () => new Date()) {
    this.#client = client;
    this.#queueUrl = queueUrl;
    this.#now = now;
  }

  async dispatch(ownerId: UserId, importId: UploadId): Promise<void> {
    await this.#client.send(
      new SendMessageCommand({
        QueueUrl: this.#queueUrl,
        MessageBody: JSON.stringify({
          schemaVersion: 1,
          ownerId,
          importId,
          enqueuedAt: this.#now().toISOString(),
        }),
      }),
    );
  }
}

export class StreamReportImportDispatcher implements ReportImportDispatcher {
  async dispatch(_ownerId: UserId, _importId: UploadId): Promise<void> {}
}

function isConditionalFailure(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'ConditionalCheckFailedException' ||
      error.name === 'TransactionCanceledException')
  );
}
