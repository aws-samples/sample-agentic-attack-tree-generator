import {
  ObjectAlreadyExistsError,
  type AdapterCopyInput,
  type AdapterGetInput,
  type AdapterHeadInput,
  type AdapterListInput,
  type AdapterObject,
  type AdapterObjectSummary,
  type AdapterPutInput,
  type ObjectAdapter,
} from './workspace.js';

interface SdkCommand {
  readonly input?: unknown;
}

interface SdkCommandConstructor {
  new (input: Record<string, unknown>): SdkCommand;
}

interface SdkClient {
  send(command: SdkCommand): Promise<Record<string, unknown>>;
}

interface S3SdkModule {
  readonly S3Client: new (configuration: Record<string, unknown>) => SdkClient;
  readonly PutObjectCommand: SdkCommandConstructor;
  readonly GetObjectCommand: SdkCommandConstructor;
  readonly HeadObjectCommand: SdkCommandConstructor;
  readonly ListObjectsV2Command: SdkCommandConstructor;
  readonly CopyObjectCommand: SdkCommandConstructor;
}

interface AwsAdapterCommands {
  readonly put: SdkCommandConstructor;
  readonly get: SdkCommandConstructor;
  readonly head: SdkCommandConstructor;
  readonly list: SdkCommandConstructor;
  readonly copy: SdkCommandConstructor;
}

export interface AwsS3AdapterConfiguration {
  readonly bucket: string;
  readonly region?: string;
  readonly endpoint?: string;
  readonly forcePathStyle?: boolean;
  readonly clientConfiguration?: Readonly<Record<string, unknown>>;
}

/**
 * Loads the AWS SDK only when the production adapter is constructed. This
 * keeps in-memory unit tests independent from AWS while package.json still
 * declares the runtime dependency.
 */
export async function createAwsS3ObjectAdapter(
  configuration: AwsS3AdapterConfiguration,
): Promise<ObjectAdapter> {
  const packageName = '@aws-sdk/client-s3';
  const sdk = (await import(packageName)) as unknown as S3SdkModule;
  const client = new sdk.S3Client({
    ...configuration.clientConfiguration,
    ...(configuration.region === undefined ? {} : { region: configuration.region }),
    ...(configuration.endpoint === undefined ? {} : { endpoint: configuration.endpoint }),
    ...(configuration.forcePathStyle === undefined
      ? {}
      : { forcePathStyle: configuration.forcePathStyle }),
  });
  return new AwsSdkV3S3ObjectAdapter(configuration.bucket, client, {
    put: sdk.PutObjectCommand,
    get: sdk.GetObjectCommand,
    head: sdk.HeadObjectCommand,
    list: sdk.ListObjectsV2Command,
    copy: sdk.CopyObjectCommand,
  });
}

export class AwsSdkV3S3ObjectAdapter implements ObjectAdapter {
  public constructor(
    private readonly bucket: string,
    private readonly client: SdkClient,
    private readonly commands: AwsAdapterCommands,
  ) {
    if (bucket.trim().length === 0) {
      throw new Error('S3 bucket is required');
    }
  }

  public async put(input: AdapterPutInput): Promise<{ readonly etag?: string }> {
    try {
      const response = await this.client.send(
        new this.commands.put({
          Bucket: this.bucket,
          Key: input.key,
          Body: input.body,
          ContentType: input.contentType,
          Metadata: input.metadata,
          ChecksumAlgorithm: 'SHA256',
          ChecksumSHA256: input.checksumSha256,
          ServerSideEncryption: input.serverSideEncryption,
          SSEKMSKeyId: input.ssekmsKeyId,
          ...(input.ifNoneMatch === undefined ? {} : { IfNoneMatch: input.ifNoneMatch }),
        }),
      );
      return optionalEtag(response);
    } catch (error) {
      translateConditionalError(input.key, error);
    }
  }

  public async get(input: AdapterGetInput): Promise<AdapterObject | null> {
    try {
      const response = await this.client.send(
        new this.commands.get({ Bucket: this.bucket, Key: input.key }),
      );
      const body = await bodyToBytes(response['Body']);
      return {
        key: input.key,
        body,
        contentType: asString(response['ContentType']) ?? 'application/octet-stream',
        sizeBytes: body.byteLength,
        metadata: asMetadata(response['Metadata']),
        ...(asString(response['ETag']) === undefined
          ? {}
          : { etag: asString(response['ETag']) }),
      };
    } catch (error) {
      if (isMissingError(error)) {
        return null;
      }
      throw error;
    }
  }

  public async head(input: AdapterHeadInput): Promise<AdapterObjectSummary | null> {
    try {
      const response = await this.client.send(
        new this.commands.head({ Bucket: this.bucket, Key: input.key }),
      );
      return {
        key: input.key,
        contentType: asString(response['ContentType']) ?? 'application/octet-stream',
        sizeBytes: asNumber(response['ContentLength']) ?? 0,
        metadata: asMetadata(response['Metadata']),
        ...(asString(response['ETag']) === undefined
          ? {}
          : { etag: asString(response['ETag']) }),
      };
    } catch (error) {
      if (isMissingError(error)) {
        return null;
      }
      throw error;
    }
  }

  public async list(input: AdapterListInput): Promise<readonly AdapterObjectSummary[]> {
    const objects: AdapterObjectSummary[] = [];
    let continuationToken: string | undefined;
    do {
      const response = await this.client.send(
        new this.commands.list({
          Bucket: this.bucket,
          Prefix: input.prefix,
          ...(continuationToken === undefined ? {} : { ContinuationToken: continuationToken }),
        }),
      );
      const contents = Array.isArray(response['Contents']) ? response['Contents'] : [];
      for (const value of contents) {
        if (value === null || typeof value !== 'object') {
          continue;
        }
        const record = value as Record<string, unknown>;
        const key = asString(record['Key']);
        if (key === undefined) {
          continue;
        }
        const head = await this.head({ key });
        if (head !== null) {
          objects.push(head);
        }
      }
      continuationToken = asString(response['NextContinuationToken']);
    } while (continuationToken !== undefined);
    return objects;
  }

  public async copy(input: AdapterCopyInput): Promise<{ readonly etag?: string }> {
    if (input.ifNoneMatch === '*') {
      // CopyObject has no destination If-None-Match. A conditional PutObject
      // preserves immutable-write semantics at the cost of streaming the body.
      const source = await this.get({ key: input.sourceKey });
      if (source === null) {
        throw new Error(`Source object does not exist: ${input.sourceKey}`);
      }
      return this.put({
        key: input.destinationKey,
        body: source.body,
        contentType: input.contentType,
        metadata: input.metadata,
        checksumSha256: input.checksumSha256,
        serverSideEncryption: input.serverSideEncryption,
        ssekmsKeyId: input.ssekmsKeyId,
        ifNoneMatch: '*',
      });
    }

    const response = await this.client.send(
      new this.commands.copy({
        Bucket: this.bucket,
        Key: input.destinationKey,
        CopySource: encodeCopySource(this.bucket, input.sourceKey),
        ContentType: input.contentType,
        Metadata: input.metadata,
        MetadataDirective: 'REPLACE',
        ServerSideEncryption: input.serverSideEncryption,
        SSEKMSKeyId: input.ssekmsKeyId,
      }),
    );
    const copyResult =
      response['CopyObjectResult'] !== null && typeof response['CopyObjectResult'] === 'object'
        ? (response['CopyObjectResult'] as Record<string, unknown>)
        : {};
    const etag = asString(copyResult['ETag']);
    return etag === undefined ? {} : { etag };
  }
}

function optionalEtag(response: Readonly<Record<string, unknown>>): { readonly etag?: string } {
  const etag = asString(response['ETag']);
  return etag === undefined ? {} : { etag };
}

function translateConditionalError(key: string, error: unknown): never {
  const name = errorName(error);
  const status = errorStatus(error);
  if (name === 'PreconditionFailed' || name === 'ConditionalRequestConflict' || status === 412) {
    throw new ObjectAlreadyExistsError(key);
  }
  throw error;
}

function isMissingError(error: unknown): boolean {
  const name = errorName(error);
  const status = errorStatus(error);
  return name === 'NoSuchKey' || name === 'NotFound' || status === 404;
}

function errorName(error: unknown): string | undefined {
  if (error === null || typeof error !== 'object') {
    return undefined;
  }
  const record = error as Record<string, unknown>;
  return asString(record['name']) ?? asString(record['Code']);
}

function errorStatus(error: unknown): number | undefined {
  if (error === null || typeof error !== 'object') {
    return undefined;
  }
  const metadata = (error as Record<string, unknown>)['$metadata'];
  return metadata !== null && typeof metadata === 'object'
    ? asNumber((metadata as Record<string, unknown>)['httpStatusCode'])
    : undefined;
}

async function bodyToBytes(body: unknown): Promise<Uint8Array> {
  if (body instanceof Uint8Array) {
    return Uint8Array.from(body);
  }
  if (
    body !== null &&
    typeof body === 'object' &&
    'transformToByteArray' in body &&
    typeof (body as { transformToByteArray?: unknown }).transformToByteArray === 'function'
  ) {
    return Uint8Array.from(
      await (body as { transformToByteArray(): Promise<Uint8Array> }).transformToByteArray(),
    );
  }
  if (isAsyncIterable(body)) {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of body) {
      const bytes =
        typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : Uint8Array.from(chunk as Uint8Array);
      chunks.push(bytes);
      total += bytes.byteLength;
    }
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  }
  throw new Error('Unsupported S3 response body');
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    Symbol.asyncIterator in value &&
    typeof (value as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function'
  );
}

function asMetadata(value: unknown): Readonly<Record<string, string>> {
  if (value === null || typeof value !== 'object') {
    return {};
  }
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (typeof item === 'string') {
      output[key.toLowerCase()] = item;
    }
  }
  return output;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function encodeCopySource(bucket: string, key: string): string {
  return `${encodeURIComponent(bucket)}/${key.split('/').map(encodeURIComponent).join('/')}`;
}
