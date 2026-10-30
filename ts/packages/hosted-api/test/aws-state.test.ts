import assert from 'node:assert/strict';
import test from 'node:test';
import type { ApiGatewayManagementApiClient } from '@aws-sdk/client-apigatewaymanagementapi';
import type { S3Client } from '@aws-sdk/client-s3';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import {
  ApplicationIdSchema,
  ArtifactIdSchema,
  ArtifactRefSchema,
  UploadIdSchema,
  UploadManifestSchema,
  UserIdSchema,
  type UploadStatus,
} from '@threatforest/types';
import {
  DynamoArtifactResolver,
  DynamoHostedState,
} from '../src/aws/state.js';
import type {
  NormalizationOrchestrator,
  UploadSessionRecord,
  WebSocketConnection,
} from '../src/contracts.js';

const ownerId = UserIdSchema.parse('usr_ready_artifacts');
const applicationId = ApplicationIdSchema.parse('app_ready_artifacts');
const scope = { owner_id: ownerId, application_id: applicationId };

test('Dynamo hosted artifact state exposes only ready upload manifests', async () => {
  const sessions = [
    uploadSession('upload-uploaded', 'uploaded'),
    uploadSession('upload-normalizing', 'normalizing'),
    uploadSession('upload-ready', 'ready'),
    uploadSession('upload-failed', 'failed'),
  ];
  const state = hostedState(sessions);

  assert.deepEqual(await state.listReadySourceArtifacts(scope), [
    ArtifactIdSchema.parse('upload-ready'),
  ]);
  await state.assertReadable(scope, [ArtifactIdSchema.parse('upload-ready')]);
  await assert.rejects(
    state.assertReadable(scope, [ArtifactIdSchema.parse('upload-uploaded')]),
    /is not available in this application/,
  );
  await assert.rejects(
    state.assertReadable(scope, [
      ArtifactIdSchema.parse('upload-normalizing'),
    ]),
    /is not available in this application/,
  );
});

test('Dynamo artifact resolution also requires the normalizer to report ready', async () => {
  const state = hostedState([uploadSession('upload-ready', 'uploaded')]);
  let normalizationStatus: UploadStatus = 'normalizing';
  const normalization = {
    async status() {
      return {
        status: normalizationStatus,
        normalizedObjectIds: [],
        authoritativeThreatObjectIds: [],
        failureCode: null,
      };
    },
  } as unknown as NormalizationOrchestrator;
  const resolver = new DynamoArtifactResolver(state, normalization);

  assert.deepEqual(await resolver.listReadySourceArtifacts(scope), []);
  normalizationStatus = 'ready';
  assert.deepEqual(await resolver.listReadySourceArtifacts(scope), [
    ArtifactIdSchema.parse('upload-ready'),
  ]);
});

test('Dynamo hosted state supports Dynamo-only compositions with guarded optional adapters', async () => {
  const state = new DynamoHostedState({
    tableName: 'state-table',
    documentClient: {
      async send(command: unknown) {
        const input = (command as { input?: Record<string, unknown> }).input;
        const key = input?.['Key'] as
          | { SK?: string }
          | undefined;
        if (key?.SK?.startsWith('VERSION#') === true) {
          return { Item: { data_key: 'reports/version-1.json' } };
        }
        return {};
      },
    } as unknown as DynamoDBDocumentClient,
  });

  assert.equal(await state.get(scope), null);
  await assert.rejects(
    state.post('connection-1', { type: 'test' }),
    /WebSocket management is unavailable/,
  );
  await assert.rejects(
    state.getData(scope, 'version-1'),
    /Artifact storage is unavailable/,
  );
});

test('Dynamo connection transitions alias reserved attributes in both writes', async () => {
  const commands: Array<{ input?: Record<string, unknown> }> = [];
  const connection: WebSocketConnection = {
    connectionId: 'connection-1',
    ownerId,
    applicationId,
    runId: 'run-1' as WebSocketConnection['runId'],
    phase: 'replay_pending',
    cursor: -1,
    seenEventIds: [],
    ticketId: 'ticket-1',
    connectedAt: '2026-08-19T12:00:00.000Z',
    expiresAt: '2026-08-20T12:00:00.000Z',
  };
  const state = new DynamoHostedState({
    tableName: 'state-table',
    documentClient: {
      async send(command: { input?: Record<string, unknown> }) {
        commands.push(command);
        return commands.length === 1
          ? { Item: { connection } }
          : {};
      },
    } as unknown as DynamoDBDocumentClient,
  });

  assert.equal(
    (await state.activateConnection('connection-1', -1)).phase,
    'live',
  );
  const transaction = commands[1]?.input?.['TransactItems'] as
    | Array<{
        Put?: {
          ConditionExpression?: string;
          ExpressionAttributeNames?: Record<string, string>;
        };
      }>
    | undefined;
  assert.equal(transaction?.length, 2);
  for (const item of transaction ?? []) {
    assert.match(item.Put?.ConditionExpression ?? '', /#connection\.#phase/);
    assert.equal(
      item.Put?.ExpressionAttributeNames?.['#connection'],
      'connection',
    );
  }
});

test('Dynamo upload completion claims are conditional and re-entrant by claim ID', async () => {
  const commands: Array<{ input?: Record<string, unknown> }> = [];
  const session = uploadSession('upload-claim', 'uploading');
  const completion = {
    state: 'completing' as const,
    parts: [],
    startedAt: '2026-08-19T12:00:00.000Z',
    completedAt: null,
    storageVersionId: null,
    claimId: 'completion-claim',
    claimExpiresAt: '2026-08-19T12:01:00.000Z',
  };
  const state = new DynamoHostedState({
    tableName: 'state-table',
    documentClient: {
      async send(command: { input?: Record<string, unknown> }) {
        commands.push(command);
        return { Attributes: { session: { ...session, completion } } };
      },
    } as unknown as DynamoDBDocumentClient,
  });

  const claimed = await state.claimUploadCompletion(
    scope,
    session.manifest.upload_id,
    completion,
    completion.startedAt,
  );
  assert.equal(claimed?.completion?.claimId, 'completion-claim');
  assert.match(
    String(commands[0]?.input?.['ConditionExpression']),
    /claimId.*claimExpiresAt/,
  );
  assert.equal(
    (
      commands[0]?.input?.['ExpressionAttributeValues'] as
        | Record<string, unknown>
        | undefined
    )?.[':claimId'],
    'completion-claim',
  );
});

test('Dynamo upload part signing is a merge update fenced against completion', async () => {
  const commands: Array<{ input?: Record<string, unknown> }> = [];
  const session = uploadSession('upload-presign', 'uploading');
  session.signedParts['1'] = {
    sizeBytes: 10,
    checksumSha256: 'b'.repeat(64),
    signedAt: '2026-08-19T12:01:00.000Z',
  };
  const state = new DynamoHostedState({
    tableName: 'state-table',
    documentClient: {
      async send(command: { input?: Record<string, unknown> }) {
        commands.push(command);
        return { Attributes: { session } };
      },
    } as unknown as DynamoDBDocumentClient,
  });

  const updated = await state.recordSignedUploadPart(
    scope,
    session.manifest.upload_id,
    {
      partNumber: 1,
      sizeBytes: 10,
      checksumSha256: 'b'.repeat(64),
    },
    '2026-08-19T12:01:00.000Z',
  );

  assert.equal(updated?.signedParts['1']?.sizeBytes, 10);
  assert.match(
    String(commands[0]?.input?.['UpdateExpression']),
    /signedParts.*partNumber/,
  );
  assert.doesNotMatch(
    String(commands[0]?.input?.['UpdateExpression']),
    /#session\s*=\s*:session/,
  );
  assert.match(
    String(commands[0]?.input?.['ConditionExpression']),
    /attribute_not_exists.*completion/,
  );
});

function hostedState(sessions: readonly UploadSessionRecord[]): DynamoHostedState {
  const documentClient = {
    async send(command: unknown) {
      const input = (command as { input?: Record<string, unknown> }).input;
      if (input?.['KeyConditionExpression'] !== undefined) {
        return {
          Items: sessions.map((session) => ({ session })),
        };
      }
      return {};
    },
  } as unknown as DynamoDBDocumentClient;
  return new DynamoHostedState({
    tableName: 'state-table',
    documentClient,
    s3: { send: async () => ({}) } as unknown as S3Client,
    artifactsBucket: 'artifacts',
    webSocketManagementClient: {
      send: async () => ({}),
    } as unknown as ApiGatewayManagementApiClient,
  });
}

function uploadSession(
  id: string,
  status: UploadStatus,
): UploadSessionRecord {
  const uploadId = UploadIdSchema.parse(id);
  const now = '2026-08-19T12:00:00.000Z';
  const sourceArtifact = ArtifactRefSchema.parse({
    artifact_id: uploadId,
    kind: 'source',
    version: 1,
    content_type: 'application/octet-stream',
    size_bytes: 10,
    sha256: 'a'.repeat(64),
    created_at: now,
  });
  return {
    manifest: UploadManifestSchema.parse({
      schema_version: 1,
      owner_id: ownerId,
      upload_id: uploadId,
      application_id: applicationId,
      filename: `${id}.bin`,
      content_type: 'application/octet-stream',
      size_bytes: 10,
      status,
      parts: [],
      source_artifact: sourceArtifact,
      normalized_artifacts: [],
      created_at: now,
      updated_at: now,
      failure_reason: status === 'failed' ? 'normalization failed' : null,
    }),
    bucket: 'artifacts',
    key: `uploads/${id}`,
    sourceObjectId: id,
    kmsKeyId: 'alias/artifacts',
    checksumSha256: 'a'.repeat(64),
    storageUploadId: `multipart-${id}`,
    partSizeBytes: 5 * 1024 * 1024,
    partCount: 1,
    signedParts: {},
  };
}
