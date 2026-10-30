import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import {
  DynamoIngestionStore,
  canonicalObjectKey,
  createObjectId,
  createUploadManifest,
  stableJson,
  transitionUploadManifest,
  type UploadManifest as IngestionUploadManifest,
} from '@threatforest/ingestion';
import type {
  ApplicationId,
  UploadId,
  UserId,
} from '@threatforest/types';
import type {
  CompletedPart,
  NormalizationOrchestrator,
  NormalizationStatus,
} from '../contracts.js';

type IngestionCommandConstructor = new (
  input: Record<string, unknown>,
) => { readonly input?: unknown };

export interface AwsNormalizationOrchestratorOptions {
  tableName: string;
  queueUrl: string;
  documentClient: DynamoDBDocumentClient;
  sqsClient: SQSClient;
  now?: () => Date;
  dispatchViaStream?: boolean;
}

function sameUploadedManifest(
  manifest: IngestionUploadManifest,
  sourceObjectId: string,
  sourceSha256: string,
): boolean {
  return (
    ['uploaded', 'normalizing', 'ready'].includes(manifest.status) &&
    manifest.sourceObjectId === sourceObjectId &&
    manifest.sourceSha256 === sourceSha256
  );
}

function ingestionParts(parts: CompletedPart[]): IngestionUploadManifest['parts'] {
  return parts.map((part) => ({
    partNumber: part.partNumber,
    sizeBytes: part.sizeBytes,
    etag: part.etag,
    checksumSha256: part.checksumSha256,
  }));
}

export class AwsNormalizationOrchestrator
  implements NormalizationOrchestrator
{
  readonly #store: DynamoIngestionStore;
  readonly #queueUrl: string;
  readonly #sqs: SQSClient;
  readonly #now: () => Date;
  readonly #dispatchViaStream: boolean;

  constructor(options: AwsNormalizationOrchestratorOptions) {
    this.#store = new DynamoIngestionStore(
      options.tableName,
      options.documentClient,
      {
        get: GetCommand as unknown as IngestionCommandConstructor,
        put: PutCommand as unknown as IngestionCommandConstructor,
        update: UpdateCommand as unknown as IngestionCommandConstructor,
      },
    );
    this.#queueUrl = options.queueUrl;
    this.#sqs = options.sqsClient;
    this.#now = options.now ?? (() => new Date());
    this.#dispatchViaStream = options.dispatchViaStream ?? false;
  }

  describeSource(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    checksumSha256: string;
  }): { sourceObjectId: string; objectKey: string } {
    const sourceObjectId = createObjectId(
      'source',
      stableJson({
        uploadId: input.uploadId,
        sha256: input.checksumSha256,
      }),
    );
    return {
      sourceObjectId,
      objectKey: canonicalObjectKey({
        scope: 'upload',
        ownerId: input.ownerId,
        applicationId: input.applicationId,
        uploadId: input.uploadId,
        area: 'original',
        objectId: sourceObjectId,
      }),
    };
  }

  async createPending(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    filename: string;
    contentType: string;
    sizeBytes: number;
  }): Promise<void> {
    const scope = {
      ownerId: input.ownerId,
      applicationId: input.applicationId,
      uploadId: input.uploadId,
    };
    const existing = await this.#store.get(scope);
    if (existing !== null) {
      if (
        existing.filename !== input.filename ||
        existing.declaredContentType !== input.contentType ||
        existing.declaredSizeBytes !== input.sizeBytes
      ) {
        throw new Error('Upload normalization manifest conflicts with the upload request');
      }
      return;
    }
    await this.#store.create(
      createUploadManifest({
        ...scope,
        filename: input.filename,
        declaredContentType: input.contentType,
        declaredSizeBytes: input.sizeBytes,
        now: this.#now().toISOString(),
      }),
    );
  }

  async markUploaded(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    sourceObjectId: string;
    sourceSha256: string;
    parts: CompletedPart[];
  }): Promise<void> {
    const scope = {
      ownerId: input.ownerId,
      applicationId: input.applicationId,
      uploadId: input.uploadId,
    };
    const manifest = await this.#store.get(scope);
    if (manifest === null) {
      throw new Error('Upload normalization manifest does not exist');
    }
    if (sameUploadedManifest(manifest, input.sourceObjectId, input.sourceSha256)) {
      return;
    }
    if (manifest.status !== 'pending' && manifest.status !== 'uploading') {
      throw new Error(
        `Cannot reconcile normalization manifest while it is ${manifest.status}`,
      );
    }
    const parts = ingestionParts(input.parts);
    const uploading =
      manifest.status === 'pending'
        ? transitionUploadManifest(manifest, 'uploading', {
            parts,
            now: this.#now().toISOString(),
          })
        : manifest;
    const uploaded = transitionUploadManifest(uploading, 'uploaded', {
      parts,
      sourceObjectId: input.sourceObjectId,
      sourceSha256: input.sourceSha256,
      now: this.#now().toISOString(),
    });
    await this.#store.put(uploaded, manifest.revision);
  }

  async dispatch(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
  }): Promise<void> {
    if (this.#dispatchViaStream) return;
    const now = this.#now();
    await this.#sqs.send(
      new SendMessageCommand({
        QueueUrl: this.#queueUrl,
        MessageBody: JSON.stringify({
          schemaVersion: 1,
          jobId: `ingest-${input.uploadId}`,
          idempotencyKey: `upload-${input.uploadId}`,
          ownerId: input.ownerId,
          applicationId: input.applicationId,
          uploadId: input.uploadId,
          attempt: 1,
          enqueuedAt: now.toISOString(),
        }),
      }),
    );
  }

  async status(
    scope: { owner_id: UserId; application_id: ApplicationId },
    uploadId: UploadId,
  ): Promise<NormalizationStatus | null> {
    const manifest = await this.#store.get({
      ownerId: scope.owner_id,
      applicationId: scope.application_id,
      uploadId,
    });
    return manifest === null
      ? null
      : {
          status: manifest.status,
          normalizedObjectIds: [...manifest.normalizedObjectIds],
          authoritativeThreatObjectIds: [
            ...manifest.authoritativeThreatObjectIds,
          ],
          failureCode: manifest.failureCode,
        };
  }
}
