import { SafeZipExtractor, type ArchiveLimits } from './archive.js';
import { createAwsDynamoIngestionStore } from './dynamo-store.js';
import { createAwsS3ObjectAdapter } from './aws-s3-adapter.js';
import { createAwsTextractOcrAdapter } from './aws-textract-adapter.js';
import { ExtractorRegistry } from './extractors.js';
import { OpenXmlOfficeAdapter } from './office.js';
import { UploadNormalizer } from './normalizer.js';
import { IngestionWorker } from './worker.js';
import { S3Workspace } from './workspace.js';

export interface IngestionEnvironment {
  readonly region: string;
  readonly bucket: string;
  readonly kmsKeyId: string;
  readonly tableName: string;
  readonly s3Endpoint?: string;
  readonly dynamoEndpoint?: string;
  readonly textractEndpoint?: string;
  readonly s3ForcePathStyle: boolean;
  readonly textractEnabled: boolean;
  readonly textractPollIntervalMs: number;
  readonly textractMaximumWaitMs: number;
  readonly idempotencyTtlSeconds: number;
  readonly processingLeaseSeconds: number;
  readonly archiveLimits: Partial<ArchiveLimits>;
}

export function loadIngestionEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): IngestionEnvironment {
  const region = required(environment, 'AWS_REGION');
  return {
    region,
    bucket: required(environment, 'INGESTION_BUCKET'),
    kmsKeyId: required(environment, 'INGESTION_KMS_KEY_ID'),
    tableName: required(environment, 'INGESTION_TABLE_NAME'),
    ...optionalValue(environment, 'INGESTION_S3_ENDPOINT', 's3Endpoint'),
    ...optionalValue(environment, 'INGESTION_DYNAMODB_ENDPOINT', 'dynamoEndpoint'),
    ...optionalValue(environment, 'INGESTION_TEXTRACT_ENDPOINT', 'textractEndpoint'),
    s3ForcePathStyle: booleanValue(environment, 'INGESTION_S3_FORCE_PATH_STYLE', false),
    textractEnabled: booleanValue(environment, 'INGESTION_TEXTRACT_ENABLED', true),
    textractPollIntervalMs: integerValue(
      environment,
      'INGESTION_TEXTRACT_POLL_INTERVAL_MS',
      2_000,
      100,
    ),
    textractMaximumWaitMs: integerValue(
      environment,
      'INGESTION_TEXTRACT_MAXIMUM_WAIT_MS',
      10 * 60 * 1_000,
      1_000,
    ),
    idempotencyTtlSeconds: integerValue(
      environment,
      'INGESTION_IDEMPOTENCY_TTL_SECONDS',
      30 * 24 * 60 * 60,
      60,
    ),
    processingLeaseSeconds: integerValue(
      environment,
      'INGESTION_PROCESSING_LEASE_SECONDS',
      15 * 60,
      30,
    ),
    archiveLimits: {
      maximumFiles: integerValue(environment, 'INGESTION_ARCHIVE_MAX_FILES', 5_000, 1),
      maximumFileBytes: integerValue(
        environment,
        'INGESTION_ARCHIVE_MAX_FILE_BYTES',
        64 * 1024 * 1024,
        1,
      ),
      maximumExpandedBytes: integerValue(
        environment,
        'INGESTION_ARCHIVE_MAX_EXPANDED_BYTES',
        512 * 1024 * 1024,
        1,
      ),
      maximumPathDepth: integerValue(
        environment,
        'INGESTION_ARCHIVE_MAX_PATH_DEPTH',
        24,
        1,
      ),
      maximumPathLength: integerValue(
        environment,
        'INGESTION_ARCHIVE_MAX_PATH_LENGTH',
        1_024,
        1,
      ),
      maximumArchiveNesting: integerValue(
        environment,
        'INGESTION_ARCHIVE_MAX_NESTING',
        3,
        0,
      ),
      maximumCompressionRatio: numberValue(
        environment,
        'INGESTION_ARCHIVE_MAX_COMPRESSION_RATIO',
        200,
        1,
      ),
      duplicatePolicy: duplicatePolicy(environment['INGESTION_ARCHIVE_DUPLICATE_POLICY']),
    },
  };
}

export async function createProductionIngestionWorker(
  configuration = loadIngestionEnvironment(),
): Promise<IngestionWorker> {
  const [s3Adapter, dynamoStore, ocrAdapter] = await Promise.all([
    createAwsS3ObjectAdapter({
      bucket: configuration.bucket,
      region: configuration.region,
      ...(configuration.s3Endpoint === undefined
        ? {}
        : { endpoint: configuration.s3Endpoint }),
      forcePathStyle: configuration.s3ForcePathStyle,
    }),
    createAwsDynamoIngestionStore({
      tableName: configuration.tableName,
      region: configuration.region,
      ...(configuration.dynamoEndpoint === undefined
        ? {}
        : { endpoint: configuration.dynamoEndpoint }),
      idempotencyTtlSeconds: configuration.idempotencyTtlSeconds,
      processingLeaseSeconds: configuration.processingLeaseSeconds,
    }),
    configuration.textractEnabled
      ? createAwsTextractOcrAdapter({
          bucket: configuration.bucket,
          region: configuration.region,
          ...(configuration.textractEndpoint === undefined
            ? {}
            : { endpoint: configuration.textractEndpoint }),
          pollIntervalMs: configuration.textractPollIntervalMs,
          maximumWaitMs: configuration.textractMaximumWaitMs,
        })
      : Promise.resolve(undefined),
  ]);
  const workspace = new S3Workspace(s3Adapter, configuration.kmsKeyId);
  const normalizer = new UploadNormalizer(workspace, {
    extractors: new ExtractorRegistry({ ocrAdapter, officeAdapter: new OpenXmlOfficeAdapter() }),
    archiveExtractor: new SafeZipExtractor(configuration.archiveLimits),
  });
  return new IngestionWorker(dynamoStore, dynamoStore, normalizer);
}

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

function optionalValue(
  environment: NodeJS.ProcessEnv,
  name: string,
  property: 's3Endpoint' | 'dynamoEndpoint' | 'textractEndpoint',
): Partial<Record<typeof property, string>> {
  const value = environment[name]?.trim();
  return value === undefined || value.length === 0 ? {} : { [property]: value };
}

function booleanValue(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: boolean,
): boolean {
  const value = environment[name];
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }
  if (value.toLowerCase() === 'true') {
    return true;
  }
  if (value.toLowerCase() === 'false') {
    return false;
  }
  throw new Error(`${name} must be true or false`);
}

function integerValue(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
): number {
  const value = environment[name];
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new Error(`${name} must be a safe integer greater than or equal to ${minimum}`);
  }
  return parsed;
}

function numberValue(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  minimum: number,
): number {
  const value = environment[name];
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum) {
    throw new Error(`${name} must be a number greater than or equal to ${minimum}`);
  }
  return parsed;
}

function duplicatePolicy(value: string | undefined): ArchiveLimits['duplicatePolicy'] {
  const normalized = value?.trim().toLowerCase() ?? 'reject';
  if (normalized === 'reject' || normalized === 'keep-first' || normalized === 'rename') {
    return normalized;
  }
  throw new Error(
    'INGESTION_ARCHIVE_DUPLICATE_POLICY must be reject, keep-first, or rename',
  );
}
