import {
  DeleteCommand,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import {
  GetObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import {
  PostToConnectionCommand,
  type ApiGatewayManagementApiClient,
} from '@aws-sdk/client-apigatewaymanagementapi';
import {
  BusinessContextSchema,
  VersionSummarySchema,
  type ApplicationId,
  type ArtifactId,
  type HostedProgressEvent,
  type RunId,
  type UploadId,
  type UserId,
  type VersionSummary,
} from '@threatforest/types';
import {
  encodeKeyPart,
  type ControlPlaneScope,
} from '@threatforest/control-plane';
import { conflict, notFound } from '../errors.js';
import { asUploadId } from '../runtime.js';
import type {
  ApplicationCompatibilityMetadata,
  ApplicationMetadataStore,
  ArtifactResolver,
  ConnectionAdapter,
  MultipartCompletionRecord,
  MutationResponseRecord,
  MutationResponseStore,
  NormalizationOrchestrator,
  ReportPayload,
  RunIndex,
  RunIndexEntry,
  SignedMultipartPart,
  UploadSessionRecord,
  UploadSessionStore,
  VersionStore,
  WebSocketConnection,
} from '../contracts.js';

type Item = Record<string, unknown>;

export interface DynamoHostedStateOptions {
  tableName: string;
  documentClient: DynamoDBDocumentClient;
  s3?: S3Client;
  artifactsBucket?: string;
  webSocketManagementClient?: ApiGatewayManagementApiClient;
  reportUrlLifetimeSeconds?: number;
  prepareApplicationReport?: (scope: ControlPlaneScope) => Promise<void>;
}

interface StoredReport {
  key: string;
  content_type: string;
  filename: string;
  metadata: Record<string, unknown>;
}

function applicationPartition(scope: ControlPlaneScope): string {
  return `HOSTED#OWNER#${encodeKeyPart(scope.owner_id)}#APP#${encodeKeyPart(
    scope.application_id,
  )}`;
}

function ownerPartition(ownerId: UserId): string {
  return `HOSTED#OWNER#${encodeKeyPart(ownerId)}`;
}

function connectionPartition(connectionId: string): string {
  return `HOSTED#CONNECTION#${encodeKeyPart(connectionId)}`;
}

function controlPlanePartition(scope: ControlPlaneScope): string {
  return `OWNER#${encodeKeyPart(scope.owner_id)}#APP#${encodeKeyPart(
    scope.application_id,
  )}`;
}

function connectionSubscriptionSortKey(
  runId: RunId,
  connectionId: string,
): string {
  return (
    `RUN#${encodeKeyPart(runId)}#CONNECTION#` +
    encodeKeyPart(connectionId)
  );
}

function asItem(value: unknown, message: string): Item {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Item;
}

function asString(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  return value;
}

function isTransactionConflict(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'TransactionCanceledException' ||
      error.name === 'ConditionalCheckFailedException')
  );
}

function storedReport(value: unknown): StoredReport | null {
  if (value === undefined || value === null) {
    return null;
  }
  const item = asItem(value, 'stored report metadata is malformed');
  return {
    key: asString(item.key, 'stored report key is malformed'),
    content_type: asString(
      item.content_type,
      'stored report content type is malformed',
    ),
    filename: asString(item.filename, 'stored report filename is malformed'),
    metadata: asItem(item.metadata ?? {}, 'stored report metadata is malformed'),
  };
}

function hydrateSignedUploadParts(
  session: UploadSessionRecord,
): UploadSessionRecord {
  if (
    session.completion !== undefined ||
    !['pending', 'uploading'].includes(session.manifest.status)
  ) {
    return session;
  }
  session.manifest.parts = Object.entries(session.signedParts)
    .map(([partNumber, signed]) => ({
      part_number: Number(partNumber),
      size_bytes: signed.sizeBytes,
      etag: null,
      checksum_sha256: signed.checksumSha256,
    }))
    .sort((left, right) => left.part_number - right.part_number);
  return session;
}

async function bodyText(body: unknown): Promise<string> {
  if (
    typeof body === 'object' &&
    body !== null &&
    'transformToString' in body &&
    typeof (body as { transformToString?: unknown }).transformToString === 'function'
  ) {
    return (body as { transformToString(): Promise<string> }).transformToString();
  }
  throw new Error('S3 response body is not readable');
}

export class DynamoHostedState {
  readonly #tableName: string;
  readonly #documentClient: DynamoDBDocumentClient;
  readonly #s3: S3Client | undefined;
  readonly #artifactsBucket: string | undefined;
  readonly #webSocketManagementClient:
    | ApiGatewayManagementApiClient
    | undefined;
  readonly #reportUrlLifetimeSeconds: number;
  readonly #prepareApplicationReport: DynamoHostedStateOptions['prepareApplicationReport'];

  constructor(options: DynamoHostedStateOptions) {
    this.#tableName = options.tableName;
    this.#documentClient = options.documentClient;
    this.#s3 = options.s3;
    this.#artifactsBucket = options.artifactsBucket;
    this.#webSocketManagementClient = options.webSocketManagementClient;
    this.#reportUrlLifetimeSeconds = options.reportUrlLifetimeSeconds ?? 300;
    this.#prepareApplicationReport = options.prepareApplicationReport;
  }

  async get(
    scopeOrConnectionId: ControlPlaneScope | string,
    uploadId?: UploadId,
  ): Promise<
    | ApplicationCompatibilityMetadata
    | UploadSessionRecord
    | WebSocketConnection
    | null
  > {
    if (typeof scopeOrConnectionId === 'string') {
      const item = await this.#get(connectionPartition(scopeOrConnectionId), 'STATE');
      return item === null
        ? null
        : (item.connection as WebSocketConnection);
    }
    if (uploadId !== undefined) {
      const item = await this.#get(
        applicationPartition(scopeOrConnectionId),
        `UPLOAD#${encodeKeyPart(uploadId)}`,
      );
      return item === null
        ? null
        : hydrateSignedUploadParts(
            structuredClone(item.session as UploadSessionRecord),
          );
    }
    const item = await this.#get(applicationPartition(scopeOrConnectionId), 'METADATA');
    if (item === null) {
      return null;
    }
    return {
      businessContext: BusinessContextSchema.parse(item.business_context),
      projectPath: asString(item.project_path, 'application project path is malformed'),
      deleted: item.deleted === true,
      importedFromAppId:
        typeof item.imported_from_app_id === 'string'
          ? item.imported_from_app_id
          : null,
      importedFromAppName:
        typeof item.imported_from_app_name === 'string'
          ? item.imported_from_app_name
          : null,
      importedAt:
        typeof item.imported_at === 'string' ? item.imported_at : null,
      lastImportedAt:
        typeof item.last_imported_at === 'string'
          ? item.last_imported_at
          : null,
    };
  }

  async put(
    scopeOrValue: ControlPlaneScope | RunIndexEntry | WebSocketConnection,
    value?: ApplicationCompatibilityMetadata | UploadSessionRecord,
  ): Promise<ApplicationCompatibilityMetadata | void> {
    if ('connectionId' in scopeOrValue) {
      await this.putConnection(scopeOrValue);
      return;
    }
    if ('ownerId' in scopeOrValue) {
      await this.#put({
        PK: ownerPartition(scopeOrValue.ownerId),
        SK: `RUN#${encodeKeyPart(scopeOrValue.runId)}`,
        entity: 'hosted-run-index',
        owner_id: scopeOrValue.ownerId,
        application_id: scopeOrValue.applicationId,
        run_id: scopeOrValue.runId,
      });
      return;
    }
    if (value === undefined) {
      throw new Error('DynamoHostedState.put value is required');
    }
    if ('manifest' in value) {
      await this.#put({
        PK: applicationPartition(scopeOrValue),
        SK: `UPLOAD#${encodeKeyPart(value.manifest.upload_id)}`,
        entity: 'hosted-upload-session',
        session: value,
        updated_at: value.manifest.updated_at,
      });
      return;
    }
    await this.#put({
      PK: applicationPartition(scopeOrValue),
      SK: 'METADATA',
      entity: 'hosted-application-metadata',
      business_context: value.businessContext,
      project_path: value.projectPath,
      deleted: value.deleted,
      imported_from_app_id: value.importedFromAppId,
      imported_from_app_name: value.importedFromAppName,
      imported_at: value.importedAt,
      last_imported_at: value.lastImportedAt,
    });
    return value;
  }

  async claimUploadCompletion(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<UploadSessionRecord | null> {
    try {
      const response = await this.#documentClient.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: {
            PK: applicationPartition(scope),
            SK: `UPLOAD#${encodeKeyPart(uploadId)}`,
          },
          UpdateExpression:
            'SET #session.#completion = :completion, ' +
            '#session.#manifest.#manifestUpdatedAt = :claimedAt, ' +
            '#itemUpdatedAt = :claimedAt',
          ConditionExpression:
            'attribute_exists(#session) AND (' +
            'attribute_not_exists(#session.#completion) OR ' +
            'attribute_not_exists(#session.#completion.#claimId) OR ' +
            '#session.#completion.#claimId = :claimId OR ' +
            '#session.#completion.#claimExpiresAt <= :claimedAt)',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#completion': 'completion',
            '#manifest': 'manifest',
            '#manifestUpdatedAt': 'updated_at',
            '#itemUpdatedAt': 'updated_at',
            '#claimId': 'claimId',
            '#claimExpiresAt': 'claimExpiresAt',
          },
          ExpressionAttributeValues: {
            ':completion': completion,
            ':claimedAt': claimedAt,
            ':claimId': completion.claimId,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      return response.Attributes?.session === undefined
        ? null
        : structuredClone(
            response.Attributes.session as UploadSessionRecord,
          );
    } catch (error) {
      if (isTransactionConflict(error)) {
        return null;
      }
      throw error;
    }
  }

  async recordSignedUploadPart(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<UploadSessionRecord | null> {
    try {
      const response = await this.#documentClient.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: {
            PK: applicationPartition(scope),
            SK: `UPLOAD#${encodeKeyPart(uploadId)}`,
          },
          UpdateExpression:
            'SET #session.#signedParts.#partNumber = :signedPart, ' +
            '#session.#manifest.#status = :uploading, ' +
            '#session.#manifest.#manifestUpdatedAt = :signedAt, ' +
            '#itemUpdatedAt = :signedAt',
          ConditionExpression:
            'attribute_exists(#session) AND ' +
            'attribute_not_exists(#session.#completion) AND ' +
            '#session.#manifest.#status IN (:pending, :uploading)',
          ExpressionAttributeNames: {
            '#session': 'session',
            '#signedParts': 'signedParts',
            '#partNumber': String(part.partNumber),
            '#completion': 'completion',
            '#manifest': 'manifest',
            '#status': 'status',
            '#manifestUpdatedAt': 'updated_at',
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
        : hydrateSignedUploadParts(
            structuredClone(
              response.Attributes.session as UploadSessionRecord,
            ),
          );
    } catch (error) {
      if (isTransactionConflict(error)) {
        return null;
      }
      throw error;
    }
  }

  async list(scopeOrOwnerId: ControlPlaneScope | UserId): Promise<VersionSummary[] | RunIndexEntry[]> {
    if (typeof scopeOrOwnerId === 'string') {
      const items = await this.#query(ownerPartition(scopeOrOwnerId), 'RUN#');
      return items.map((item) => ({
        ownerId: scopeOrOwnerId,
        applicationId: item.application_id as ApplicationId,
        runId: item.run_id as RunId,
      }));
    }
    const items = await this.#query(applicationPartition(scopeOrOwnerId), 'VERSION#');
    return items
      .map((item) => VersionSummarySchema.parse(item.summary))
      .sort((left, right) => right.run_date.localeCompare(left.run_date));
  }

  async locate(ownerId: UserId, runId: RunId): Promise<RunIndexEntry | null> {
    const item = await this.#get(
      ownerPartition(ownerId),
      `RUN#${encodeKeyPart(runId)}`,
    );
    return item === null
      ? null
      : {
          ownerId,
          applicationId: item.application_id as ApplicationId,
          runId,
        };
  }

  async getData(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, unknown> | null> {
    const item = await this.#versionItem(scope, versionId);
    if (item === null) {
      return null;
    }
    const key = asString(item.data_key, 'version data key is malformed');
    const { s3, artifactsBucket } = this.#requireArtifactStorage();
    const response = await s3.send(
      new GetObjectCommand({ Bucket: artifactsBucket, Key: key }),
    );
    return asItem(
      JSON.parse(await bodyText(response.Body)) as unknown,
      'version data is not a JSON object',
    );
  }

  async delete(scope: ControlPlaneScope | string, versionId?: string): Promise<boolean | void> {
    if (typeof scope === 'string') {
      await this.deleteConnection(scope);
      return;
    }
    if (versionId === undefined) {
      throw new Error('versionId is required');
    }
    const item = await this.#versionItem(scope, versionId);
    if (item === null) {
      return false;
    }
    await Promise.all([
      this.#documentClient.send(
        new DeleteCommand({
          TableName: this.#tableName,
          Key: {
            PK: applicationPartition(scope),
            SK: `VERSION#${encodeKeyPart(versionId)}`,
          },
        }),
      ),
      this.#documentClient.send(
        new DeleteCommand({
          TableName: this.#tableName,
          Key: {
            PK: applicationPartition(scope),
            SK: `OVERRIDES#${encodeKeyPart(versionId)}`,
          },
        }),
      ),
    ]);
    return true;
  }

  async getReport(
    scope: ControlPlaneScope,
    versionId: string | null,
    includeScannerContext: boolean,
  ): Promise<ReportPayload | null> {
    if (versionId === null) await this.#prepareApplicationReport?.(scope);
    const item =
      versionId === null
        ? await this.#get(applicationPartition(scope), 'APPLICATION_REPORT')
        : await this.#versionItem(scope, versionId);
    const stored =
      item === null
        ? null
        : storedReport(
            includeScannerContext
              ? item.report
              : (item.report_without_scanner ?? item.report),
          );
    if (stored === null) {
      return null;
    }
    const { s3, artifactsBucket } = this.#requireArtifactStorage();
    const redirectUrl = await getSignedUrl(
      s3,
      new GetObjectCommand({
        Bucket: artifactsBucket,
        Key: stored.key,
        ResponseContentType: stored.content_type,
        ResponseContentDisposition: `attachment; filename="${stored.filename.replaceAll('"', '')}"`,
      }),
      { expiresIn: this.#reportUrlLifetimeSeconds },
    );
    return {
      contentType: stored.content_type,
      filename: stored.filename,
      redirectUrl,
      metadata: stored.metadata,
    };
  }

  async getMitigationOverrides(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, Record<string, unknown>>> {
    const item = await this.#get(
      applicationPartition(scope),
      `OVERRIDES#${encodeKeyPart(versionId)}`,
    );
    return item === null
      ? {}
      : (asItem(item.overrides ?? {}, 'mitigation overrides are malformed') as Record<
          string,
          Record<string, unknown>
        >);
  }

  async setMitigationOverride(
    scope: ControlPlaneScope,
    versionId: string,
    key: string,
    value: Record<string, unknown> | null,
  ): Promise<Record<string, unknown> | null> {
    if ((await this.#versionItem(scope, versionId)) === null) {
      return null;
    }
    const overrides = await this.getMitigationOverrides(scope, versionId);
    if (value === null) {
      delete overrides[key];
    } else {
      overrides[key] = value;
    }
    await this.#put({
      PK: applicationPartition(scope),
      SK: `OVERRIDES#${encodeKeyPart(versionId)}`,
      entity: 'hosted-mitigation-overrides',
      overrides,
    });
    return value ?? {};
  }

  async getResponse(
    scope: ControlPlaneScope,
    idempotencyKey: string,
  ): Promise<MutationResponseRecord | null> {
    const item = await this.#get(
      applicationPartition(scope),
      `RESPONSE#${encodeKeyPart(idempotencyKey)}`,
    );
    return item === null
      ? null
      : (JSON.parse(
          asString(item.response_json, 'idempotency response is malformed'),
        ) as MutationResponseRecord);
  }

  async putResponse(
    scope: ControlPlaneScope,
    idempotencyKey: string,
    response: MutationResponseRecord,
  ): Promise<void> {
    await this.#put({
      PK: applicationPartition(scope),
      SK: `RESPONSE#${encodeKeyPart(idempotencyKey)}`,
      entity: 'hosted-idempotency-response',
      response_json: JSON.stringify(response),
      ttl: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
    });
  }

  async listReadySourceArtifacts(scope: ControlPlaneScope): Promise<ArtifactId[]> {
    return this.#listSourceArtifacts(scope, true);
  }

  async describeSources(scope: ControlPlaneScope): Promise<Array<{ artifact_id: ArtifactId; filename: string; created_at: string }>> {
    const sessions = await this.#query(applicationPartition(scope), 'UPLOAD#');
    return sessions.flatMap(item => {
      const { manifest } = item.session as UploadSessionRecord;
      return manifest.source_artifact ? [{
        artifact_id: manifest.source_artifact.artifact_id,
        filename: manifest.filename,
        created_at: manifest.created_at,
      }] : [];
    });
  }

  async listSourceArtifactCandidates(
    scope: ControlPlaneScope,
  ): Promise<ArtifactId[]> {
    return this.#listSourceArtifacts(scope, false);
  }

  async #listSourceArtifacts(
    scope: ControlPlaneScope,
    readyOnly: boolean,
  ): Promise<ArtifactId[]> {
    const sessions = await this.#query(applicationPartition(scope), 'UPLOAD#');
    const artifacts: ArtifactId[] = [];
    for (const item of sessions) {
      const session = item.session as UploadSessionRecord;
      if (
        (!readyOnly || session.manifest.status === 'ready') &&
        session.manifest.source_artifact !== null
      ) {
        artifacts.push(session.manifest.source_artifact.artifact_id);
      }
    }
    return artifacts;
  }

  async assertReadable(scope: ControlPlaneScope, artifactIds: ArtifactId[]): Promise<void> {
    const readable = new Set(await this.listReadySourceArtifacts(scope));
    const denied = artifactIds.find((artifactId) => !readable.has(artifactId));
    if (denied !== undefined) {
      throw notFound(`Artifact ${denied} is not available in this application.`);
    }
  }

  async post(connectionId: string, value: Record<string, unknown>): Promise<void> {
    if (this.#webSocketManagementClient === undefined) {
      throw new Error(
        'WebSocket management is unavailable in this service composition.',
      );
    }
    await this.#webSocketManagementClient.send(
      new PostToConnectionCommand({
        ConnectionId: connectionId,
        Data: Buffer.from(JSON.stringify(value)),
      }),
    );
  }

  async putConnection(connection: WebSocketConnection): Promise<void> {
    const ttl = Math.floor(Date.parse(connection.expiresAt) / 1000);
    if (!Number.isSafeInteger(ttl)) {
      throw new Error('WebSocket connection expiry is invalid');
    }
    const locator = {
      PK: connectionPartition(connection.connectionId),
      SK: 'STATE',
      entity: 'hosted-websocket-connection',
      connection,
      ttl,
    };
    const subscription = {
      PK: controlPlanePartition({
        owner_id: connection.ownerId,
        application_id: connection.applicationId,
      }),
      SK: connectionSubscriptionSortKey(
        connection.runId,
        connection.connectionId,
      ),
      entity: 'hosted-websocket-subscription',
      connection,
      ttl,
    };
    await this.#documentClient.send(
      new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: this.#tableName, Item: locator } },
          { Put: { TableName: this.#tableName, Item: subscription } },
        ],
      }),
    );
  }

  async activateConnection(
    connectionId: string,
    expectedCursor: number,
  ): Promise<WebSocketConnection> {
    const current = (await this.get(connectionId)) as WebSocketConnection | null;
    if (current === null) {
      throw notFound('WebSocket connection does not exist.');
    }
    if (current.cursor !== expectedCursor) {
      throw conflict('WebSocket replay cursor changed before activation.');
    }
    if (current.phase === 'live') {
      return current;
    }
    const next: WebSocketConnection = { ...current, phase: 'live' };
    try {
      await this.#replaceConnection(current, next);
      return next;
    } catch (error) {
      if (!isTransactionConflict(error)) throw error;
      const raced = (await this.get(connectionId)) as WebSocketConnection | null;
      if (
        raced !== null &&
        raced.phase === 'live' &&
        raced.cursor === expectedCursor
      ) {
        return raced;
      }
      throw conflict('WebSocket connection activation raced another update.');
    }
  }

  async listConnections(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<WebSocketConnection[]> {
    const items = await this.#query(
      controlPlanePartition(scope),
      `${connectionSubscriptionSortKey(runId, '')}`,
    );
    return items
      .filter((item) => item.entity === 'hosted-websocket-subscription')
      .map((item) =>
        asItem(item.connection, 'WebSocket subscription is malformed'),
      ) as unknown as WebSocketConnection[];
  }

  async advanceConnection(
    connection: WebSocketConnection,
    event: HostedProgressEvent,
  ): Promise<WebSocketConnection | null> {
    if (event.sequence <= connection.cursor) {
      return connection;
    }
    const next: WebSocketConnection = {
      ...connection,
      cursor: event.sequence,
      seenEventIds: [
        ...connection.seenEventIds.filter(
          (eventId) => eventId !== event.event_id,
        ),
        event.event_id,
      ].slice(-256),
    };
    try {
      await this.#replaceConnection(connection, next);
      return next;
    } catch (error) {
      if (!isTransactionConflict(error)) throw error;
      return (await this.get(
        connection.connectionId,
      )) as WebSocketConnection | null;
    }
  }

  async deleteConnection(connectionId: string): Promise<void> {
    const current = (await this.get(connectionId)) as WebSocketConnection | null;
    if (current === null) {
      await this.#documentClient.send(
        new DeleteCommand({
          TableName: this.#tableName,
          Key: { PK: connectionPartition(connectionId), SK: 'STATE' },
        }),
      );
      return;
    }
    await this.#documentClient.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Delete: {
              TableName: this.#tableName,
              Key: { PK: connectionPartition(connectionId), SK: 'STATE' },
            },
          },
          {
            Delete: {
              TableName: this.#tableName,
              Key: {
                PK: controlPlanePartition({
                  owner_id: current.ownerId,
                  application_id: current.applicationId,
                }),
                SK: connectionSubscriptionSortKey(
                  current.runId,
                  connectionId,
                ),
              },
            },
          },
        ],
      }),
    );
  }

  async #replaceConnection(
    current: WebSocketConnection,
    next: WebSocketConnection,
  ): Promise<void> {
    const ttl = Math.floor(Date.parse(next.expiresAt) / 1000);
    const condition =
      '#connection.#phase = :phase AND #connection.#cursor = :cursor ' +
      'AND #connection.ticketId = :ticket';
    const names = {
      '#connection': 'connection',
      '#phase': 'phase',
      '#cursor': 'cursor',
    };
    const values = {
      ':phase': current.phase,
      ':cursor': current.cursor,
      ':ticket': current.ticketId,
    };
    await this.#documentClient.send(
      new TransactWriteCommand({
        TransactItems: [
          {
            Put: {
              TableName: this.#tableName,
              Item: {
                PK: connectionPartition(next.connectionId),
                SK: 'STATE',
                entity: 'hosted-websocket-connection',
                connection: next,
                ttl,
              },
              ConditionExpression: condition,
              ExpressionAttributeNames: names,
              ExpressionAttributeValues: values,
            },
          },
          {
            Put: {
              TableName: this.#tableName,
              Item: {
                PK: controlPlanePartition({
                  owner_id: next.ownerId,
                  application_id: next.applicationId,
                }),
                SK: connectionSubscriptionSortKey(
                  next.runId,
                  next.connectionId,
                ),
                entity: 'hosted-websocket-subscription',
                connection: next,
                ttl,
              },
              ConditionExpression: condition,
              ExpressionAttributeNames: names,
              ExpressionAttributeValues: values,
            },
          },
        ],
      }),
    );
  }

  async #get(pk: string, sk: string): Promise<Item | null> {
    const response = await this.#documentClient.send(
      new GetCommand({
        TableName: this.#tableName,
        Key: { PK: pk, SK: sk },
        ConsistentRead: true,
      }),
    );
    return response.Item ?? null;
  }

  #requireArtifactStorage(): {
    s3: S3Client;
    artifactsBucket: string;
  } {
    if (this.#s3 === undefined || this.#artifactsBucket === undefined) {
      throw new Error(
        'Artifact storage is unavailable in this service composition.',
      );
    }
    return { s3: this.#s3, artifactsBucket: this.#artifactsBucket };
  }

  async #put(item: Item): Promise<void> {
    await this.#documentClient.send(
      new PutCommand({ TableName: this.#tableName, Item: item }),
    );
  }

  async #query(pk: string, prefix: string): Promise<Item[]> {
    const items: Item[] = [];
    let startKey: Record<string, unknown> | undefined;
    do {
      const response = await this.#documentClient.send(
        new QueryCommand({
          TableName: this.#tableName,
          KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
          ExpressionAttributeValues: { ':pk': pk, ':prefix': prefix },
          ExclusiveStartKey: startKey,
          ConsistentRead: true,
        }),
      );
      items.push(...(response.Items ?? []));
      startKey = response.LastEvaluatedKey;
    } while (startKey !== undefined);
    return items;
  }

  async #versionItem(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Item | null> {
    if (versionId !== 'latest') {
      return this.#get(
        applicationPartition(scope),
        `VERSION#${encodeKeyPart(versionId)}`,
      );
    }
    const items = await this.#query(applicationPartition(scope), 'VERSION#');
    return (
      items.sort((left, right) => {
        const leftSummary = VersionSummarySchema.parse(left.summary);
        const rightSummary = VersionSummarySchema.parse(right.summary);
        return rightSummary.run_date.localeCompare(leftSummary.run_date);
      })[0] ?? null
    );
  }
}

export class DynamoApplicationMetadataStore implements ApplicationMetadataStore {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  async get(scope: ControlPlaneScope): Promise<ApplicationCompatibilityMetadata | null> {
    return (await this.#state.get(scope)) as ApplicationCompatibilityMetadata | null;
  }

  put(
    scope: ControlPlaneScope,
    metadata: ApplicationCompatibilityMetadata,
  ): Promise<ApplicationCompatibilityMetadata> {
    return this.#state.put(scope, metadata) as Promise<ApplicationCompatibilityMetadata>;
  }
}

export class DynamoUploadSessionStore implements UploadSessionStore {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  async get(
    scope: ControlPlaneScope,
    uploadId: UploadId,
  ): Promise<UploadSessionRecord | null> {
    return (await this.#state.get(scope, uploadId)) as UploadSessionRecord | null;
  }

  async put(scope: ControlPlaneScope, session: UploadSessionRecord): Promise<void> {
    await this.#state.put(scope, session);
  }

  recordSignedPart(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<UploadSessionRecord | null> {
    return this.#state.recordSignedUploadPart(
      scope,
      uploadId,
      part,
      signedAt,
    );
  }

  claimCompletion(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<UploadSessionRecord | null> {
    return this.#state.claimUploadCompletion(
      scope,
      uploadId,
      completion,
      claimedAt,
    );
  }
}

export class DynamoRunIndex implements RunIndex {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  async put(entry: RunIndexEntry): Promise<void> {
    await this.#state.put(entry);
  }

  locate(ownerId: UserId, runId: RunId): Promise<RunIndexEntry | null> {
    return this.#state.locate(ownerId, runId);
  }

  async list(ownerId: UserId): Promise<RunIndexEntry[]> {
    return (await this.#state.list(ownerId)) as RunIndexEntry[];
  }
}

export class DynamoMutationResponseStore implements MutationResponseStore {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  get(
    scope: ControlPlaneScope,
    idempotencyKey: string,
  ): Promise<MutationResponseRecord | null> {
    return this.#state.getResponse(scope, idempotencyKey);
  }

  put(
    scope: ControlPlaneScope,
    idempotencyKey: string,
    response: MutationResponseRecord,
  ): Promise<void> {
    return this.#state.putResponse(scope, idempotencyKey, response);
  }
}

export class DynamoConnectionAdapter implements ConnectionAdapter {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  async get(connectionId: string): Promise<WebSocketConnection | null> {
    return (await this.#state.get(connectionId)) as WebSocketConnection | null;
  }

  async put(connection: WebSocketConnection): Promise<void> {
    await this.#state.putConnection(connection);
  }

  activate(
    connectionId: string,
    expectedCursor: number,
  ): Promise<WebSocketConnection> {
    return this.#state.activateConnection(connectionId, expectedCursor);
  }

  listForRun(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<WebSocketConnection[]> {
    return this.#state.listConnections(scope, runId);
  }

  advance(
    connection: WebSocketConnection,
    event: HostedProgressEvent,
  ): Promise<WebSocketConnection | null> {
    return this.#state.advanceConnection(connection, event);
  }

  async delete(connectionId: string): Promise<void> {
    await this.#state.deleteConnection(connectionId);
  }

  post(connectionId: string, value: Record<string, unknown>): Promise<void> {
    return this.#state.post(connectionId, value);
  }
}

export class DynamoVersionStore implements VersionStore {
  readonly #state: DynamoHostedState;

  constructor(state: DynamoHostedState) {
    this.#state = state;
  }

  async list(scope: ControlPlaneScope): Promise<VersionSummary[]> {
    return (await this.#state.list(scope)) as VersionSummary[];
  }

  getData(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, unknown> | null> {
    return this.#state.getData(scope, versionId);
  }

  async delete(scope: ControlPlaneScope, versionId: string): Promise<boolean> {
    return (await this.#state.delete(scope, versionId)) as boolean;
  }

  getReport(
    scope: ControlPlaneScope,
    versionId: string | null,
    includeScannerContext: boolean,
  ): Promise<ReportPayload | null> {
    return this.#state.getReport(scope, versionId, includeScannerContext);
  }

  getMitigationOverrides(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, Record<string, unknown>>> {
    return this.#state.getMitigationOverrides(scope, versionId);
  }

  setMitigationOverride(
    scope: ControlPlaneScope,
    versionId: string,
    key: string,
    value: Record<string, unknown> | null,
  ): Promise<Record<string, unknown> | null> {
    return this.#state.setMitigationOverride(scope, versionId, key, value);
  }
}

export class DynamoArtifactResolver implements ArtifactResolver {
  readonly #state: DynamoHostedState;
  readonly #normalization: NormalizationOrchestrator | undefined;

  constructor(
    state: DynamoHostedState,
    normalization?: NormalizationOrchestrator,
  ) {
    this.#state = state;
    this.#normalization = normalization;
  }

  async listReadySourceArtifacts(scope: ControlPlaneScope): Promise<ArtifactId[]> {
    if (this.#normalization === undefined) {
      return this.#state.listReadySourceArtifacts(scope);
    }
    const candidates =
      await this.#state.listSourceArtifactCandidates(scope);
    const normalization = this.#normalization;
    const statuses = await Promise.all(
      candidates.map(async (artifactId) => ({
        artifactId,
        status: await normalization.status(scope, asUploadId(artifactId)),
      })),
    );
    return statuses
      .filter((entry) => entry.status?.status === 'ready')
      .map((entry) => entry.artifactId);
  }

  async assertReadable(
    scope: ControlPlaneScope,
    artifactIds: ArtifactId[],
  ): Promise<void> {
    const readable = new Set(await this.listReadySourceArtifacts(scope));
    const denied = artifactIds.find((artifactId) => !readable.has(artifactId));
    if (denied !== undefined) {
      throw notFound(`Artifact ${denied} is not ready in this application.`);
    }
  }

  async describeSources(scope: ControlPlaneScope) {
    return this.#state.describeSources(scope);
  }
}
