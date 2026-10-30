import {
  DynamoControlPlane,
  type ControlPlaneStore,
} from '@threatforest/control-plane';
import {
  ArtifactIdSchema,
  ArtifactRefSchema,
  type ArtifactRef,
} from '@threatforest/types';
import type {
  ArtifactStore,
  Clock,
  TranscriptWriteInput,
} from './contracts.js';
import { systemClock } from './contracts.js';
import type { GenerateMacClient, GenerateMacInput } from './identity.js';
import { canonicalJson, sha256 } from './util.js';

interface AwsCommandClient {
  send(command: unknown): Promise<Record<string, unknown>>;
}

interface AwsClientConstructor {
  new (configuration: Record<string, unknown>): AwsCommandClient;
}

interface AwsCommandConstructor {
  new (input: Record<string, unknown>): unknown;
}

interface KmsModule {
  KMSClient: AwsClientConstructor;
  GenerateMacCommand: AwsCommandConstructor;
}

export interface AwsKmsGenerateMacClientOptions {
  region?: string;
  clientConfig?: Record<string, unknown>;
}

export class AwsKmsGenerateMacClient implements GenerateMacClient {
  readonly #client: AwsCommandClient;
  readonly #command: AwsCommandConstructor;

  private constructor(client: AwsCommandClient, command: AwsCommandConstructor) {
    this.#client = client;
    this.#command = command;
  }

  static async create(
    options: AwsKmsGenerateMacClientOptions = {},
  ): Promise<AwsKmsGenerateMacClient> {
    const packageName: string = '@aws-sdk/client-kms';
    const module = (await import(packageName)) as unknown as KmsModule;
    const client = new module.KMSClient({
      ...(options.region === undefined ? {} : { region: options.region }),
      ...options.clientConfig,
    });
    return new AwsKmsGenerateMacClient(client, module.GenerateMacCommand);
  }

  async generateMac(input: GenerateMacInput): Promise<Uint8Array> {
    const output = await this.#client.send(
      new this.#command({
        KeyId: input.keyId,
        Message: input.message,
        MacAlgorithm: input.algorithm,
      }),
    );
    const mac = output['Mac'];
    if (!(mac instanceof Uint8Array)) {
      throw new Error('KMS GenerateMac response did not include Mac bytes');
    }
    return mac;
  }
}

interface DynamoModule {
  DynamoDBClient: AwsClientConstructor;
}

interface DocumentClientModule {
  DynamoDBDocumentClient: {
    from(
      client: AwsCommandClient,
      translateConfig?: Record<string, unknown>,
    ): AwsCommandClient;
  };
}

export interface DynamoControlPlaneFactoryOptions {
  tableName: string;
  region?: string;
  applicationIndexName?: string;
  clientConfig?: Record<string, unknown>;
}

export async function createDynamoControlPlaneStore(
  options: DynamoControlPlaneFactoryOptions,
): Promise<ControlPlaneStore> {
  const dynamoPackage: string = '@aws-sdk/client-dynamodb';
  const documentPackage: string = '@aws-sdk/lib-dynamodb';
  const [dynamo, document] = (await Promise.all([
    import(dynamoPackage),
    import(documentPackage),
  ])) as unknown as [DynamoModule, DocumentClientModule];
  const lowLevel = new dynamo.DynamoDBClient({
    ...(options.region === undefined ? {} : { region: options.region }),
    ...options.clientConfig,
  });
  const client = document.DynamoDBDocumentClient.from(lowLevel, {
    marshallOptions: {
      removeUndefinedValues: true,
    },
  });
  return new DynamoControlPlane({
    tableName: options.tableName,
    client: client as never,
    applicationIndexName: options.applicationIndexName,
  });
}

interface S3Module {
  S3Client: AwsClientConstructor;
  PutObjectCommand: AwsCommandConstructor;
  HeadObjectCommand: AwsCommandConstructor;
}

interface S3ObjectClient {
  put(input: Record<string, unknown>): Promise<void>;
  head(input: Record<string, unknown>): Promise<Record<string, unknown>>;
}

class AwsS3ObjectClient implements S3ObjectClient {
  readonly #client: AwsCommandClient;
  readonly #putCommand: AwsCommandConstructor;
  readonly #headCommand: AwsCommandConstructor;

  private constructor(
    client: AwsCommandClient,
    putCommand: AwsCommandConstructor,
    headCommand: AwsCommandConstructor,
  ) {
    this.#client = client;
    this.#putCommand = putCommand;
    this.#headCommand = headCommand;
  }

  static async create(
    region: string | undefined,
    clientConfig: Record<string, unknown> | undefined,
  ): Promise<AwsS3ObjectClient> {
    const packageName: string = '@aws-sdk/client-s3';
    const module = (await import(packageName)) as unknown as S3Module;
    return new AwsS3ObjectClient(
      new module.S3Client({
        ...(region === undefined ? {} : { region }),
        ...clientConfig,
      }),
      module.PutObjectCommand,
      module.HeadObjectCommand,
    );
  }

  async put(input: Record<string, unknown>): Promise<void> {
    await this.#client.send(new this.#putCommand(input));
  }

  head(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.#client.send(new this.#headCommand(input));
  }
}

export interface S3TranscriptArtifactStoreOptions {
  bucketName: string;
  kmsKeyId: string;
  region?: string;
  keyPrefix?: string;
  clientConfig?: Record<string, unknown>;
  clock?: Clock;
}

class S3TranscriptArtifactStore implements ArtifactStore {
  readonly #client: S3ObjectClient;
  readonly #bucketName: string;
  readonly #kmsKeyId: string;
  readonly #prefix: string;
  readonly #clock: Clock;

  constructor(
    client: S3ObjectClient,
    options: S3TranscriptArtifactStoreOptions,
  ) {
    this.#client = client;
    this.#bucketName = options.bucketName;
    this.#kmsKeyId = options.kmsKeyId;
    this.#prefix = (options.keyPrefix ?? 'hosted').replace(/^\/+|\/+$/g, '');
    this.#clock = options.clock ?? systemClock;
  }

  async putTranscript(input: TranscriptWriteInput): Promise<ArtifactRef> {
    const content = canonicalJson(input.transcript);
    const body = Buffer.from(content, 'utf8');
    const digest = sha256(body);
    const artifactId = ArtifactIdSchema.parse(
      `transcript_${sha256(`${input.idempotency_key}\0${digest}`).slice(0, 48)}`,
    );
    const key = [
      this.#prefix,
      input.owner_id,
      input.application_id,
      input.run_id,
      'transcripts',
      `${input.interaction_id}-r${input.revision}.json`,
    ].join('/');
    try {
      await this.#client.put({
        Bucket: this.#bucketName,
        Key: key,
        Body: body,
        ContentType: 'application/json',
        ChecksumSHA256: Buffer.from(digest, 'hex').toString('base64'),
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: this.#kmsKeyId,
        BucketKeyEnabled: true,
        IfNoneMatch: '*',
        Metadata: {
          sha256: digest,
          artifact_id: artifactId,
          run_id: input.run_id,
        },
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : '';
      if (name !== 'PreconditionFailed' && name !== 'PreconditionFailedException') {
        throw error;
      }
      const existing = await this.#client.head({
        Bucket: this.#bucketName,
        Key: key,
      });
      const metadata = existing['Metadata'];
      const existingHash =
        metadata !== null && typeof metadata === 'object'
          ? (metadata as Record<string, unknown>)['sha256']
          : undefined;
      if (existingHash !== digest || existing['ContentLength'] !== body.byteLength) {
        throw new Error(`S3 transcript key ${key} already contains different content`);
      }
    }
    return ArtifactRefSchema.parse({
      artifact_id: artifactId,
      kind: 'transcript',
      version: input.revision,
      content_type: 'application/json',
      size_bytes: body.byteLength,
      sha256: digest,
      created_at: this.#clock.now().toISOString(),
    });
  }
}

export async function createS3TranscriptArtifactStore(
  options: S3TranscriptArtifactStoreOptions,
): Promise<ArtifactStore> {
  const client = await AwsS3ObjectClient.create(options.region, options.clientConfig);
  return new S3TranscriptArtifactStore(client, options);
}
