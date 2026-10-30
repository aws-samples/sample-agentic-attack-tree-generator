import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import {
  UploadIdSchema,
  UserIdSchema,
  type ApplicationId,
  type UserId,
} from '@threatforest/types';
import { encodeKeyPart } from '@threatforest/control-plane';
import { DynamoReportImportStore } from '../aws/report-imports.js';
import { S3ReportImportSourceReader } from '../aws/report-import-source.js';
import {
  DurableReportImportCommitter,
  ReportImportWorker,
  type ReportImportObjectWriter,
  type ReportImportStateClient,
} from '../report-import-worker.js';

const region = process.env.AWS_REGION ?? 'eu-west-2';
const tableName = required('CONTROL_PLANE_TABLE_NAME');
const bucketName = required('ARTIFACTS_BUCKET_NAME');
const kmsKeyId = required('ARTIFACTS_KMS_KEY_ID');
const documentClient = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region }),
  { marshallOptions: { removeUndefinedValues: true } },
);
const s3 = new S3Client({ region });
const store = new DynamoReportImportStore(tableName, documentClient);
const objectWriter = awsObjectWriter();
const worker = new ReportImportWorker(
  store,
  new S3ReportImportSourceReader(s3),
  new DurableReportImportCommitter(objectWriter, awsStateClient()),
);

interface ReportImportSqsEvent {
  Records: Array<{ messageId: string; body: string }>;
}

interface ReportImportSqsBatchResponse {
  batchItemFailures: Array<{ itemIdentifier: string }>;
}

export async function handler(
  event: ReportImportSqsEvent,
): Promise<ReportImportSqsBatchResponse> {
  const batchItemFailures: Array<{ itemIdentifier: string }> = [];
  for (const record of event.Records) {
    try {
      const body = JSON.parse(record.body) as Record<string, unknown>;
      if (body.schemaVersion !== 1) {
        throw new Error('Unsupported report import message schema.');
      }
      await worker.process(
        UserIdSchema.parse(body.ownerId),
        UploadIdSchema.parse(body.importId),
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'threatforest.report_import.failed',
          messageId: record.messageId,
          errorName: error instanceof Error ? error.name : 'UnknownError',
          errorMessage:
            error instanceof Error ? error.message : 'Unknown report import failure',
        }),
      );
      batchItemFailures.push({ itemIdentifier: record.messageId });
    }
  }
  return { batchItemFailures };
}

function awsObjectWriter(): ReportImportObjectWriter {
  return {
    async putImmutable(input) {
      try {
        await s3.send(
          new PutObjectCommand({
            Bucket: bucketName,
            Key: input.key,
            Body: input.body,
            ContentType: input.contentType,
            ChecksumSHA256: Buffer.from(
              input.checksumSha256,
              'hex',
            ).toString('base64'),
            ServerSideEncryption: 'aws:kms',
            SSEKMSKeyId: kmsKeyId,
            BucketKeyEnabled: true,
            IfNoneMatch: '*',
            Metadata: input.metadata,
          }),
        );
      } catch (error) {
        if (!isPreconditionFailure(error)) throw error;
        const existing = await s3.send(
          new HeadObjectCommand({ Bucket: bucketName, Key: input.key }),
        );
        if (
          existing.ContentLength !== input.body.byteLength ||
          existing.Metadata?.sha256 !== input.checksumSha256 ||
          existing.ServerSideEncryption !== 'aws:kms' ||
          existing.SSEKMSKeyId !== kmsKeyId ||
          existing.BucketKeyEnabled !== true
        ) {
          throw new Error(`Report output key contains different content: ${input.key}`);
        }
      }
    },
    async get(key) {
      const response = await s3.send(
        new GetObjectCommand({ Bucket: bucketName, Key: key }),
      );
      if (
        response.Body === undefined ||
        typeof response.Body.transformToByteArray !== 'function'
      ) {
        throw new Error(`Report entry is not readable: ${key}`);
      }
      return response.Body.transformToByteArray();
    },
  };
}

function awsStateClient(): ReportImportStateClient {
  return {
    async listApplications(ownerId) {
      return queryAll({
        TableName: tableName,
        IndexName: 'GSI1',
        KeyConditionExpression:
          'GSI1PK = :owner AND begins_with(GSI1SK, :application)',
        ExpressionAttributeValues: {
          ':owner': `OWNER#${encodeKeyPart(ownerId)}`,
          ':application': 'APP#',
        },
      });
    },
    async getMetadata(ownerId, applicationId) {
      const response = await documentClient.send(
        new GetCommand({
          TableName: tableName,
          Key: {
            PK: hostedPartition(ownerId, applicationId),
            SK: 'METADATA',
          },
          ConsistentRead: true,
        }),
      );
      return response.Item ?? null;
    },
    async putMetadata(ownerId, applicationId, metadata) {
      await documentClient.send(
        new PutCommand({
          TableName: tableName,
          Item: {
            PK: hostedPartition(ownerId, applicationId),
            SK: 'METADATA',
            entity: 'hosted-application-metadata',
            ...metadata,
          },
        }),
      );
    },
    async createApplication(item) {
      await documentClient.send(
        new PutCommand({
          TableName: tableName,
          Item: item,
          ConditionExpression:
            'attribute_not_exists(PK) AND attribute_not_exists(SK)',
        }),
      );
    },
    async getVersion(ownerId, applicationId, versionId) {
      const response = await documentClient.send(
        new GetCommand({
          TableName: tableName,
          Key: {
            PK: hostedPartition(ownerId, applicationId),
            SK: `VERSION#${encodeKeyPart(versionId)}`,
          },
          ConsistentRead: true,
        }),
      );
      return response.Item ?? null;
    },
    async putVersion(item) {
      try {
        await documentClient.send(
          new PutCommand({
            TableName: tableName,
            Item: item,
            ConditionExpression:
              'attribute_not_exists(PK) AND attribute_not_exists(SK)',
          }),
        );
        return true;
      } catch (error) {
        if (
          error instanceof Error &&
          error.name === 'ConditionalCheckFailedException'
        ) {
          return false;
        }
        throw error;
      }
    },
    async listVersions(ownerId, applicationId) {
      return queryAll({
        TableName: tableName,
        KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
        ExpressionAttributeValues: {
          ':pk': hostedPartition(ownerId, applicationId),
          ':prefix': 'VERSION#',
        },
        ConsistentRead: true,
      });
    },
    async putApplicationReport(item) {
      await documentClient.send(
        new PutCommand({ TableName: tableName, Item: item }),
      );
    },
  };
}

async function queryAll(
  base: Record<string, unknown>,
): Promise<Array<Record<string, unknown>>> {
  const items: Array<Record<string, unknown>> = [];
  let startKey: Record<string, unknown> | undefined;
  do {
    const response = await documentClient.send(
      new QueryCommand({
        ...(base as {
          TableName: string;
          KeyConditionExpression: string;
        }),
        ExclusiveStartKey: startKey,
      }),
    );
    items.push(...(response.Items ?? []));
    startKey = response.LastEvaluatedKey;
  } while (startKey !== undefined);
  return items;
}

function hostedPartition(ownerId: UserId, applicationId: ApplicationId): string {
  return (
    `HOSTED#OWNER#${encodeKeyPart(ownerId)}` +
    `#APP#${encodeKeyPart(applicationId)}`
  );
}

function isPreconditionFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const status = (error as Error & {
    $metadata?: { httpStatusCode?: number };
  }).$metadata?.httpStatusCode;
  return error.name === 'PreconditionFailed' || status === 412;
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(`${name} environment variable is required.`);
  }
  return value;
}
