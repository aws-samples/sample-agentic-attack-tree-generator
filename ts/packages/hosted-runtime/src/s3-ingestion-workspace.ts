import { createHash, randomUUID } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  type FileHandle,
} from 'node:fs/promises';
import {
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path';
import {
  ArtifactIdSchema,
  ArtifactRefSchema,
  type ArtifactRef,
  type StageCheckpoint,
} from '@threatforest/types';
import type { StageExecutionContext } from './contracts.js';
import type {
  MaterializedWorkspace,
  RecoveredWorkspace,
  WorkspaceResolver,
} from './engine-adapter.js';
import { sha256 } from './util.js';

const SAFE_INGESTION_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;

export const INGESTION_WORKSPACE_MANIFEST = 'workspace-manifest.json';
export const AUTHORITATIVE_THREAT_INPUTS_MANIFEST =
  'authoritative-threat-inputs.json';
export const WORKSPACE_CHECKPOINT_CONTENT_TYPE =
  'application/vnd.threatforest.workspace-checkpoint+json';
const WORKSPACE_CHECKPOINT_MARKER = '.workspace-checkpoint.json';

export interface ManifestGetInput {
  readonly tableName: string;
  readonly partitionKey: string;
  readonly sortKey: string;
}

export interface ManifestGetOutput {
  readonly item: unknown | null;
}

export interface IngestionManifestClient {
  getManifest(input: ManifestGetInput): Promise<ManifestGetOutput>;
}

export interface NormalizedObjectGetInput {
  readonly bucketName: string;
  readonly key: string;
}

export interface NormalizedObjectGetOutput {
  readonly body: unknown;
  readonly metadata: Readonly<Record<string, string | undefined>>;
  readonly contentType?: string;
  readonly contentLength?: number;
}

export interface IngestionObjectClient {
  getNormalizedObject(
    input: NormalizedObjectGetInput,
  ): Promise<NormalizedObjectGetOutput | null>;
}

export interface WorkspaceCheckpointGetInput {
  readonly bucketName: string;
  readonly key: string;
}

export interface WorkspaceCheckpointPutInput {
  readonly bucketName: string;
  readonly key: string;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly checksumSha256: string;
  readonly kmsKeyId: string;
  readonly metadata: Readonly<Record<string, string>>;
}

export interface WorkspaceCheckpointClient {
  getObject(
    input: WorkspaceCheckpointGetInput,
  ): Promise<NormalizedObjectGetOutput | null>;
  putObject(input: WorkspaceCheckpointPutInput): Promise<void>;
}

export interface S3IngestionWorkspaceResolverOptions {
  readonly tableName: string;
  readonly bucketName: string;
  readonly workspaceRoot?: string;
  readonly manifestClient: IngestionManifestClient;
  readonly objectClient: IngestionObjectClient;
  readonly checkpointClient?: WorkspaceCheckpointClient;
  readonly checkpointKmsKeyId?: string;
  readonly checkpointKeyPrefix?: string;
}

export interface AwsS3IngestionWorkspaceResolverOptions {
  readonly tableName: string;
  readonly bucketName: string;
  readonly kmsKeyId: string;
  readonly keyPrefix?: string;
  readonly workspaceRoot?: string;
  readonly region?: string;
  readonly dynamoClientConfiguration?: Readonly<Record<string, unknown>>;
  readonly s3ClientConfiguration?: Readonly<Record<string, unknown>>;
}

interface UploadManifest {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly ownerId: string;
  readonly applicationId: string;
  readonly uploadId: string;
  readonly status: 'ready';
  readonly normalizedObjectIds: readonly string[];
  readonly authoritativeThreatObjectIds: readonly string[];
}

interface UploadSelection {
  readonly uploadId: string;
  readonly source: boolean;
  readonly threat: boolean;
}

interface MaterializedInput {
  readonly relative_path: string;
  readonly upload_id: string;
  readonly object_id: string;
  readonly source_roles: readonly ('source' | 'threat')[];
  readonly authoritative_threat_input: boolean;
  readonly sha256: string;
  readonly size_bytes: number;
  readonly content_type: string;
  readonly s3_key: string;
  readonly metadata: Readonly<Record<string, string>>;
}

interface AwsCommandClient {
  send(command: unknown): Promise<Record<string, unknown>>;
}

interface AwsCommandConstructor {
  new (input: Record<string, unknown>): unknown;
}

interface DynamoClientModule {
  DynamoDBClient: new (configuration: Record<string, unknown>) => unknown;
}

interface DynamoDocumentModule {
  DynamoDBDocumentClient: {
    from(client: unknown, options?: Record<string, unknown>): AwsCommandClient;
  };
  GetCommand: AwsCommandConstructor;
}

interface S3ClientModule {
  S3Client: new (configuration: Record<string, unknown>) => AwsCommandClient;
  GetObjectCommand: AwsCommandConstructor;
  PutObjectCommand: AwsCommandConstructor;
}

interface WorkspaceSnapshotFile {
  readonly path: string;
  readonly size_bytes: number;
  readonly sha256: string;
}

interface LocalWorkspaceSnapshotFile extends WorkspaceSnapshotFile {
  readonly absolute_path: string;
}

interface WorkspaceSnapshotManifest {
  readonly schema_version: 1;
  readonly owner_id: string;
  readonly application_id: string;
  readonly run_id: string;
  readonly stage_id: string;
  readonly stage_version: number;
  readonly attempt: number;
  readonly boundary: 'completed' | 'awaiting_input';
  readonly files: readonly WorkspaceSnapshotFile[];
}

/**
 * Materializes normalized ingestion objects into a per-owner, per-application,
 * per-run source snapshot. Engine state lives beside the source snapshot and
 * is intentionally retained when later stages resolve the same run again.
 */
export class S3IngestionWorkspaceResolver implements WorkspaceResolver {
  readonly #tableName: string;
  readonly #bucketName: string;
  readonly #workspaceRoot: string;
  readonly #manifestClient: IngestionManifestClient;
  readonly #objectClient: IngestionObjectClient;
  readonly #checkpointClient: WorkspaceCheckpointClient | null;
  readonly #checkpointKmsKeyId: string | null;
  readonly #checkpointKeyPrefix: string;
  readonly #sourceCache = new Map<string, readonly MaterializedInput[]>();
  readonly #publishedBlobs = new Set<string>();
  readonly checkpoint:
    | ((
        context: StageExecutionContext,
        workspace: MaterializedWorkspace,
        boundary: 'completed' | 'awaiting_input',
      ) => Promise<ArtifactRef>)
    | undefined;
  readonly recover:
    | ((
        context: StageExecutionContext,
        checkpoint: StageCheckpoint,
      ) => Promise<RecoveredWorkspace | null>)
    | undefined;

  public constructor(options: S3IngestionWorkspaceResolverOptions) {
    this.#tableName = requiredConfiguration(options.tableName, 'tableName');
    this.#bucketName = requiredConfiguration(options.bucketName, 'bucketName');
    this.#workspaceRoot = resolve(
      options.workspaceRoot ?? '/tmp/threatforest-ingestion',
    );
    if (this.#workspaceRoot === '/') {
      throw new Error('workspaceRoot must not be the filesystem root');
    }
    this.#manifestClient = options.manifestClient;
    this.#objectClient = options.objectClient;
    this.#checkpointClient = options.checkpointClient ?? null;
    this.#checkpointKmsKeyId =
      options.checkpointKmsKeyId === undefined
        ? null
        : requiredConfiguration(
            options.checkpointKmsKeyId,
            'checkpointKmsKeyId',
          );
    this.#checkpointKeyPrefix = (
      options.checkpointKeyPrefix ?? 'hosted'
    ).replace(/^\/+|\/+$/g, '');
    if (
      (this.#checkpointClient === null) !==
      (this.#checkpointKmsKeyId === null)
    ) {
      throw new Error(
        'checkpointClient and checkpointKmsKeyId must be configured together',
      );
    }
    this.checkpoint =
      this.#checkpointClient === null
        ? undefined
        : (context, workspace, boundary) =>
            this.#publishCheckpoint(context, workspace, boundary);
    this.recover =
      this.#checkpointClient === null
        ? undefined
        : (context, checkpoint) =>
            this.#recoverCompletedCheckpoint(context, checkpoint);
  }

  public async resolve(
    context: StageExecutionContext,
  ): Promise<MaterializedWorkspace> {
    const ownerId = validateIdentifier(context.scope.owner_id, 'owner_id');
    const applicationId = validateIdentifier(
      context.scope.application_id,
      'application_id',
    );
    const runId = validateOpaqueValue(context.run.run_id, 'run_id');
    const uploads = selectUploads(
      context.run.source_artifact_ids,
      context.run.threat_artifact_id,
    );
    if (uploads.length === 0) {
      throw new Error('run has no ingestion upload IDs to materialize');
    }

    const runRoot = join(
      this.#workspaceRoot,
      'owners',
      digestPathSegment(ownerId),
      'applications',
      digestPathSegment(applicationId),
      'runs',
      digestPathSegment(runId),
    );
    const repoPath = join(runRoot, 'source');
    const runDir = join(runRoot, 'engine');
    const inputDir = join(runDir, 'input');
    assertContained(this.#workspaceRoot, runRoot);

    await ensureDirectory(this.#workspaceRoot);
    await ensureDirectory(join(this.#workspaceRoot, 'owners'));
    await ensureDirectory(join(this.#workspaceRoot, 'owners', digestPathSegment(ownerId)));
    await ensureDirectory(
      join(
        this.#workspaceRoot,
        'owners',
        digestPathSegment(ownerId),
        'applications',
      ),
    );
    await ensureDirectory(
      join(
        this.#workspaceRoot,
        'owners',
        digestPathSegment(ownerId),
        'applications',
        digestPathSegment(applicationId),
      ),
    );
    await ensureDirectory(
      join(
        this.#workspaceRoot,
        'owners',
        digestPathSegment(ownerId),
        'applications',
        digestPathSegment(applicationId),
        'runs',
      ),
    );
    await ensureDirectory(runRoot);
    await ensureDirectory(runDir);
    await ensureDirectory(inputDir);
    await assertSafeMetadataDestination(
      join(inputDir, INGESTION_WORKSPACE_MANIFEST),
    );
    await assertSafeMetadataDestination(
      join(inputDir, AUTHORITATIVE_THREAT_INPUTS_MANIFEST),
    );

    const manifests = await Promise.all(uploads.map(upload =>
      this.#readManifest(ownerId, applicationId, upload.uploadId)));
    const cacheKey = JSON.stringify([ownerId, applicationId, runId, uploads, manifests]);
    const cached = this.#sourceCache.get(cacheKey);
    if (cached) {
      let valid = false;
      try {
        const root = await lstat(repoPath);
        const names = await readdir(repoPath);
        valid = root.isDirectory() && !root.isSymbolicLink() && names.length === cached.length;
        for (const file of cached) {
          const path = join(repoPath, file.relative_path);
          const info = await lstat(path);
          if (!info.isFile() || info.isSymbolicLink() ||
              info.size !== file.size_bytes || sha256(await readFile(path)) !== file.sha256) {
            valid = false;
            break;
          }
        }
      } catch { valid = false; }
      if (valid) {
        await this.#restoreReferencedCheckpoint(context, runRoot, runDir);
        return {
          repoPath, runDir,
          authoritativeThreatInputPaths: cached.filter(file => file.authoritative_threat_input)
            .map(file => join(repoPath, file.relative_path)),
        };
      }
      this.#sourceCache.delete(cacheKey);
    }

    const staging = await mkdtemp(join(runRoot, '.source-staging-'));
    const materialized: MaterializedInput[] = [];
    const collisionKeys = new Set<string>();
    let published = false;
    try {
      for (const [uploadIndex, upload] of uploads.entries()) {
        const manifest = manifests[uploadIndex]!;
        const authoritativeIds = new Set(
          manifest.authoritativeThreatObjectIds,
        );
        const objectIds = [...manifest.normalizedObjectIds].sort((left, right) =>
          left.localeCompare(right),
        );
        for (const [objectIndex, objectId] of objectIds.entries()) {
          const key = canonicalNormalizedKey(
            ownerId,
            applicationId,
            upload.uploadId,
            objectId,
          );
          const object = await this.#objectClient.getNormalizedObject({
            bucketName: this.#bucketName,
            key,
          });
          if (object === null) {
            throw new Error(`normalized ingestion object is missing: ${key}`);
          }
          const metadata = normalizeMetadata(object.metadata, key);
          const filename = deterministicFilename(
            uploadIndex,
            upload.uploadId,
            objectIndex,
            objectId,
            metadata,
            object.contentType,
          );
          const collisionKey = filename.normalize('NFC').toLowerCase();
          if (collisionKeys.has(collisionKey)) {
            throw new Error(`materialized filename collision: ${filename}`);
          }
          collisionKeys.add(collisionKey);
          const destination = join(staging, filename);
          assertContained(staging, destination);
          const verified = await writeVerifiedObject(
            destination,
            object,
            metadata,
            key,
          );
          const sourceRoles: ('source' | 'threat')[] = [];
          if (upload.source) {
            sourceRoles.push('source');
          }
          if (upload.threat) {
            sourceRoles.push('threat');
          }
          materialized.push({
            relative_path: filename,
            upload_id: upload.uploadId,
            object_id: objectId,
            source_roles: sourceRoles,
            authoritative_threat_input:
              upload.threat ||
              authoritativeIds.has(objectId) ||
              metadata['input-class'] === 'authoritative-threat',
            sha256: verified.sha256,
            size_bytes: verified.sizeBytes,
            content_type:
              object.contentType?.trim() || 'application/octet-stream',
            s3_key: key,
            metadata,
          });
        }
      }

      await publishSourceSnapshot(staging, repoPath, runRoot);
      published = true;
      const generatedAt = context.run.updated_at;
      await writeAtomicJson(join(inputDir, INGESTION_WORKSPACE_MANIFEST), {
        schema_version: 1,
        owner_id: ownerId,
        application_id: applicationId,
        run_id: runId,
        generated_at: generatedAt,
        source_root: repoPath,
        files: materialized,
      });
      await writeAtomicJson(
        join(inputDir, AUTHORITATIVE_THREAT_INPUTS_MANIFEST),
        {
          schema_version: 1,
          owner_id: ownerId,
          application_id: applicationId,
          run_id: runId,
          threat_artifact_id: context.run.threat_artifact_id,
          files: materialized.filter(
            (file) => file.authoritative_threat_input,
          ),
        },
      );
      await this.#restoreReferencedCheckpoint(context, runRoot, runDir);
      this.#sourceCache.set(cacheKey, materialized);
      return {
        repoPath,
        runDir,
        authoritativeThreatInputPaths: materialized
          .filter((file) => file.authoritative_threat_input)
          .map((file) => join(repoPath, file.relative_path)),
      };
    } finally {
      if (!published) {
        await rm(staging, { recursive: true, force: true });
      }
    }
  }

  async #publishCheckpoint(
    context: StageExecutionContext,
    workspace: MaterializedWorkspace,
    boundary: 'completed' | 'awaiting_input',
  ): Promise<ArtifactRef> {
    if (
      this.#checkpointClient === null ||
      this.#checkpointKmsKeyId === null ||
      workspace.runDir === undefined
    ) {
      throw new Error('durable workspace checkpointing is not configured');
    }
    const files = await readWorkspaceFiles(workspace.runDir);
    for (const file of files) {
      const body = await readFile(file.absolute_path);
      if (
        body.byteLength !== file.size_bytes ||
        sha256(body) !== file.sha256
      ) {
        throw new Error(
          `workspace file changed while checkpointing: ${file.path}`,
        );
      }
      const blobKey = this.#blobKey(context, file.sha256);
      if (this.#publishedBlobs.has(blobKey)) continue;
      await this.#putImmutable(
        blobKey,
        body,
        'application/octet-stream',
        {
          sha256: file.sha256,
          run_id: context.run.run_id,
          artifact_kind: 'workspace-blob',
        },
      );
      this.#publishedBlobs.add(blobKey);
    }
    const manifest: WorkspaceSnapshotManifest = {
      schema_version: 1,
      owner_id: context.scope.owner_id,
      application_id: context.scope.application_id,
      run_id: context.run.run_id,
      stage_id: context.stage.id,
      stage_version: context.stage.version,
      attempt: context.checkpoint.attempt,
      boundary,
      files: files.map(({ path, size_bytes, sha256: digest }) => ({
        path,
        size_bytes,
        sha256: digest,
      })),
    };
    const manifestBody = Buffer.from(JSON.stringify(manifest), 'utf8');
    const manifestSha256 = sha256(manifestBody);
    const artifactId = ArtifactIdSchema.parse(
      `checkpoint_${sha256(
        `${context.checkpoint.idempotency_key}\0${boundary}\0${manifestSha256}`,
      ).slice(0, 48)}`,
    );
    const artifact = ArtifactRefSchema.parse({
      artifact_id: artifactId,
      kind: 'checkpoint',
      version: context.stage.version,
      content_type: WORKSPACE_CHECKPOINT_CONTENT_TYPE,
      size_bytes: manifestBody.byteLength,
      sha256: manifestSha256,
      created_at: context.checkpoint.started_at,
    });
    await this.#putImmutable(
      this.#manifestKey(context, artifactId),
      manifestBody,
      WORKSPACE_CHECKPOINT_CONTENT_TYPE,
      {
        sha256: manifestSha256,
        artifact_id: artifactId,
        run_id: context.run.run_id,
        artifact_kind: 'workspace-checkpoint',
      },
    );
    if (boundary === 'completed') {
      const receiptBody = Buffer.from(JSON.stringify(artifact), 'utf8');
      await this.#putImmutable(
        this.#completionReceiptKey(context, context.checkpoint),
        receiptBody,
        'application/json',
        {
          sha256: sha256(receiptBody),
          artifact_id: artifactId,
          run_id: context.run.run_id,
          artifact_kind: 'workspace-completion-receipt',
        },
      );
    }
    return artifact;
  }

  async #recoverCompletedCheckpoint(
    context: StageExecutionContext,
    checkpoint: StageCheckpoint,
  ): Promise<RecoveredWorkspace | null> {
    const workspace = await this.resolve(context);
    const receiptKey = this.#completionReceiptKey(context, checkpoint);
    const receipt = await this.#getCheckpointObject(receiptKey);
    if (receipt === null) {
      return null;
    }
    const receiptBytes = await objectBytes(receipt, receiptKey);
    let artifact: ArtifactRef;
    try {
      artifact = ArtifactRefSchema.parse(
        JSON.parse(Buffer.from(receiptBytes).toString('utf8')),
      );
    } catch (error) {
      throw new Error('workspace completion receipt is malformed', {
        cause: error,
      });
    }
    assertWorkspaceCheckpointArtifact(artifact);
    await this.#restoreCheckpointArtifact(
      context,
      workspace.runDir!,
      artifact,
    );
    return { workspace, checkpointArtifact: artifact };
  }

  async #restoreReferencedCheckpoint(
    context: StageExecutionContext,
    runRoot: string,
    runDir: string,
  ): Promise<void> {
    if (this.#checkpointClient === null) {
      return;
    }
    const candidates = [
      ...context.checkpoint.input_artifacts,
      ...context.checkpoint.output_artifacts,
    ].filter(isWorkspaceCheckpointArtifact);
    const artifact = candidates.at(-1);
    if (artifact === undefined) {
      return;
    }
    assertContained(runRoot, runDir);
    await this.#restoreCheckpointArtifact(context, runDir, artifact);
  }

  async #restoreCheckpointArtifact(
    context: StageExecutionContext,
    runDir: string,
    artifact: ArtifactRef,
  ): Promise<void> {
    if (await hasCheckpointMarker(runDir, artifact)) {
      return;
    }
    const key = this.#manifestKey(context, artifact.artifact_id);
    const stored = await this.#getCheckpointObject(key);
    if (stored === null) {
      throw new Error(
        `workspace checkpoint manifest is missing: ${artifact.artifact_id}`,
      );
    }
    const manifestBytes = await objectBytes(stored, key);
    if (
      manifestBytes.byteLength !== artifact.size_bytes ||
      sha256(manifestBytes) !== artifact.sha256
    ) {
      throw new Error(
        `workspace checkpoint manifest failed integrity validation: ${artifact.artifact_id}`,
      );
    }
    const manifest = parseWorkspaceManifest(manifestBytes, context);
    const runRoot = resolve(runDir, '..');
    const staging = await mkdtemp(join(runRoot, '.engine-restore-'));
    let published = false;
    try {
      for (const file of manifest.files) {
        const destination = safeSnapshotDestination(staging, file.path);
        await mkdir(resolve(destination, '..'), {
          recursive: true,
          mode: 0o700,
        });
        const blobKey = this.#blobKey(context, file.sha256);
        const object = await this.#getCheckpointObject(blobKey);
        if (object === null) {
          throw new Error(
            `workspace checkpoint blob is missing: ${file.sha256}`,
          );
        }
        await writeVerifiedObject(
          destination,
          object,
          { sha256: file.sha256 },
          blobKey,
        );
        const restored = await stat(destination);
        if (restored.size !== file.size_bytes) {
          throw new Error(
            `workspace checkpoint file size mismatch: ${file.path}`,
          );
        }
      }
      await writeAtomicJson(join(staging, WORKSPACE_CHECKPOINT_MARKER), {
        schema_version: 1,
        artifact_id: artifact.artifact_id,
        sha256: artifact.sha256,
      });
      await publishEngineSnapshot(staging, runDir, runRoot);
      published = true;
    } finally {
      if (!published) {
        await rm(staging, { recursive: true, force: true });
      }
    }
  }

  async #putImmutable(
    key: string,
    body: Uint8Array,
    contentType: string,
    metadata: Readonly<Record<string, string>>,
  ): Promise<void> {
    if (
      this.#checkpointClient === null ||
      this.#checkpointKmsKeyId === null
    ) {
      throw new Error('durable workspace checkpointing is not configured');
    }
    try {
      await this.#checkpointClient.putObject({
        bucketName: this.#bucketName,
        key,
        body,
        contentType,
        checksumSha256: sha256(body),
        kmsKeyId: this.#checkpointKmsKeyId,
        metadata,
      });
    } catch (error) {
      if (!isAwsPreconditionFailure(error)) {
        throw error;
      }
      const existing = await this.#getCheckpointObject(key);
      if (existing === null) {
        throw error;
      }
      const bytes = await objectBytes(existing, key);
      if (!Buffer.from(bytes).equals(Buffer.from(body))) {
        throw new Error(
          `workspace checkpoint key already contains different content: ${key}`,
        );
      }
    }
  }

  #getCheckpointObject(
    key: string,
  ): Promise<NormalizedObjectGetOutput | null> {
    if (this.#checkpointClient === null) {
      throw new Error('durable workspace checkpointing is not configured');
    }
    return this.#checkpointClient.getObject({
      bucketName: this.#bucketName,
      key,
    });
  }

  #checkpointBase(context: StageExecutionContext): string {
    return [
      this.#checkpointKeyPrefix,
      context.scope.owner_id,
      context.scope.application_id,
      context.run.run_id,
      'workspace',
    ].join('/');
  }

  #blobKey(context: StageExecutionContext, digest: string): string {
    return `${this.#checkpointBase(context)}/blobs/${digest}`;
  }

  #manifestKey(
    context: StageExecutionContext,
    artifactId: string,
  ): string {
    return `${this.#checkpointBase(context)}/snapshots/${artifactId}.json`;
  }

  #completionReceiptKey(
    context: StageExecutionContext,
    checkpoint: StageCheckpoint,
  ): string {
    return (
      `${this.#checkpointBase(context)}/receipts/` +
      `${Buffer.from(checkpoint.stage_id, 'utf8').toString('base64url')}/` +
      `v${checkpoint.stage_version}-a${checkpoint.attempt}-completed.json`
    );
  }

  async #readManifest(
    ownerId: string,
    applicationId: string,
    uploadId: string,
  ): Promise<UploadManifest> {
    const partitionKey =
      `OWNER#${encodeKeyPart(ownerId)}#APP#${encodeKeyPart(applicationId)}`;
    const sortKey = `UPLOAD#${encodeKeyPart(uploadId)}#MANIFEST`;
    const result = await this.#manifestClient.getManifest({
      tableName: this.#tableName,
      partitionKey,
      sortKey,
    });
    if (result.item === null) {
      throw new Error(`ingestion upload manifest was not found: ${uploadId}`);
    }
    return parseReadyManifest(
      result.item,
      ownerId,
      applicationId,
      uploadId,
    );
  }
}

export async function createAwsS3IngestionWorkspaceResolver(
  options: AwsS3IngestionWorkspaceResolverOptions,
): Promise<S3IngestionWorkspaceResolver> {
  const dynamoPackage = '@aws-sdk/client-dynamodb';
  const documentPackage = '@aws-sdk/lib-dynamodb';
  const s3Package = '@aws-sdk/client-s3';
  const [dynamo, document, s3] = (await Promise.all([
    import(dynamoPackage),
    import(documentPackage),
    import(s3Package),
  ])) as unknown as [
    DynamoClientModule,
    DynamoDocumentModule,
    S3ClientModule,
  ];
  const baseDynamo = new dynamo.DynamoDBClient({
    ...options.dynamoClientConfiguration,
    ...(options.region === undefined ? {} : { region: options.region }),
  });
  const documentClient = document.DynamoDBDocumentClient.from(baseDynamo, {
    marshallOptions: {
      removeUndefinedValues: true,
      convertClassInstanceToMap: false,
    },
  });
  const s3Client = new s3.S3Client({
    ...options.s3ClientConfiguration,
    ...(options.region === undefined ? {} : { region: options.region }),
  });
  const getObject = async (
    bucket: string,
    key: string,
  ): Promise<NormalizedObjectGetOutput | null> => {
    try {
      const response = await s3Client.send(
        new s3.GetObjectCommand({
          Bucket: bucket,
          Key: key,
        }),
      );
      return {
        body: response['Body'],
        metadata: asStringMetadata(response['Metadata']),
        ...(typeof response['ContentType'] === 'string'
          ? { contentType: response['ContentType'] }
          : {}),
        ...(typeof response['ContentLength'] === 'number'
          ? { contentLength: response['ContentLength'] }
          : {}),
      };
    } catch (error) {
      if (isAwsMissingObject(error)) {
        return null;
      }
      throw error;
    }
  };
  return new S3IngestionWorkspaceResolver({
    tableName: options.tableName,
    bucketName: options.bucketName,
    ...(options.workspaceRoot === undefined
      ? {}
      : { workspaceRoot: options.workspaceRoot }),
    manifestClient: {
      async getManifest(input) {
        const response = await documentClient.send(
          new document.GetCommand({
            TableName: input.tableName,
            Key: { PK: input.partitionKey, SK: input.sortKey },
            ConsistentRead: true,
          }),
        );
        return { item: response['Item'] ?? null };
      },
    },
    objectClient: {
      async getNormalizedObject(input) {
        return getObject(input.bucketName, input.key);
      },
    },
    checkpointClient: {
      async getObject(input) {
        return getObject(input.bucketName, input.key);
      },
      async putObject(input) {
        await s3Client.send(
          new s3.PutObjectCommand({
            Bucket: input.bucketName,
            Key: input.key,
            Body: input.body,
            ContentType: input.contentType,
            ChecksumSHA256: Buffer.from(
              input.checksumSha256,
              'hex',
            ).toString('base64'),
            ServerSideEncryption: 'aws:kms',
            SSEKMSKeyId: input.kmsKeyId,
            BucketKeyEnabled: true,
            IfNoneMatch: '*',
            Metadata: input.metadata,
          }),
        );
      },
    },
    checkpointKmsKeyId: options.kmsKeyId,
    ...(options.keyPrefix === undefined
      ? {}
      : { checkpointKeyPrefix: options.keyPrefix }),
  });
}

async function readWorkspaceFiles(
  runDir: string,
): Promise<LocalWorkspaceSnapshotFile[]> {
  const output: LocalWorkspaceSnapshotFile[] = [];
  const queue: Array<{ absolute: string; relative: string }> = [
    { absolute: runDir, relative: '' },
  ];
  while (queue.length > 0) {
    const current = queue.shift()!;
    const entries = await readdir(current.absolute, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const relativePath =
        current.relative.length === 0
          ? entry.name
          : `${current.relative}/${entry.name}`;
      if (relativePath === WORKSPACE_CHECKPOINT_MARKER) {
        continue;
      }
      const absolutePath = join(current.absolute, entry.name);
      const details = await lstat(absolutePath);
      if (details.isSymbolicLink()) {
        throw new Error(
          `workspace checkpoint refuses symbolic links: ${relativePath}`,
        );
      }
      if (details.isDirectory()) {
        queue.push({ absolute: absolutePath, relative: relativePath });
        continue;
      }
      if (!details.isFile()) {
        throw new Error(
          `workspace checkpoint refuses non-regular files: ${relativePath}`,
        );
      }
      const body = await readFile(absolutePath);
      output.push({
        path: relativePath,
        size_bytes: body.byteLength,
        sha256: sha256(body),
        absolute_path: absolutePath,
      });
    }
  }
  output.sort((left, right) => left.path.localeCompare(right.path));
  return output;
}

function isWorkspaceCheckpointArtifact(
  artifact: ArtifactRef,
): boolean {
  return (
    artifact.kind === 'checkpoint' &&
    artifact.content_type === WORKSPACE_CHECKPOINT_CONTENT_TYPE
  );
}

function assertWorkspaceCheckpointArtifact(
  artifact: ArtifactRef,
): void {
  if (!isWorkspaceCheckpointArtifact(artifact)) {
    throw new Error(
      `artifact ${artifact.artifact_id} is not a workspace checkpoint`,
    );
  }
}

async function hasCheckpointMarker(
  runDir: string,
  artifact: ArtifactRef,
): Promise<boolean> {
  try {
    const value = JSON.parse(
      await readFile(join(runDir, WORKSPACE_CHECKPOINT_MARKER), 'utf8'),
    ) as Record<string, unknown>;
    return (
      value['schema_version'] === 1 &&
      value['artifact_id'] === artifact.artifact_id &&
      value['sha256'] === artifact.sha256
    );
  } catch {
    return false;
  }
}

function parseWorkspaceManifest(
  bytes: Uint8Array,
  context: StageExecutionContext,
): WorkspaceSnapshotManifest {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch (error) {
    throw new Error('workspace checkpoint manifest is malformed', {
      cause: error,
    });
  }
  const record = asRecord(value);
  if (
    record === null ||
    record['schema_version'] !== 1 ||
    record['owner_id'] !== context.scope.owner_id ||
    record['application_id'] !== context.scope.application_id ||
    record['run_id'] !== context.run.run_id ||
    typeof record['stage_id'] !== 'string' ||
    !Number.isSafeInteger(record['stage_version']) ||
    !Number.isSafeInteger(record['attempt']) ||
    (record['boundary'] !== 'completed' &&
      record['boundary'] !== 'awaiting_input') ||
    !Array.isArray(record['files'])
  ) {
    throw new Error('workspace checkpoint manifest scope or schema is invalid');
  }
  const seen = new Set<string>();
  const files = record['files'].map((item): WorkspaceSnapshotFile => {
    const file = asRecord(item);
    if (
      file === null ||
      typeof file['path'] !== 'string' ||
      !Number.isSafeInteger(file['size_bytes']) ||
      (file['size_bytes'] as number) < 0 ||
      typeof file['sha256'] !== 'string' ||
      !SHA256_HEX.test(file['sha256'])
    ) {
      throw new Error('workspace checkpoint file entry is invalid');
    }
    validateSnapshotPath(file['path']);
    if (seen.has(file['path'])) {
      throw new Error(
        `workspace checkpoint has duplicate file path: ${file['path']}`,
      );
    }
    seen.add(file['path']);
    return {
      path: file['path'],
      size_bytes: file['size_bytes'] as number,
      sha256: file['sha256'],
    };
  });
  return {
    schema_version: 1,
    owner_id: context.scope.owner_id,
    application_id: context.scope.application_id,
    run_id: context.run.run_id,
    stage_id: record['stage_id'],
    stage_version: record['stage_version'] as number,
    attempt: record['attempt'] as number,
    boundary: record['boundary'],
    files,
  };
}

function validateSnapshotPath(path: string): void {
  if (
    path.length === 0 ||
    path.length > 4096 ||
    path.includes('\\') ||
    path.startsWith('/') ||
    path.split('/').some((part) => part.length === 0 || part === '.' || part === '..') ||
    /[\u0000-\u001f\u007f-\u009f]/.test(path)
  ) {
    throw new Error(`workspace checkpoint path is unsafe: ${path}`);
  }
}

function safeSnapshotDestination(root: string, path: string): string {
  validateSnapshotPath(path);
  const destination = join(root, ...path.split('/'));
  assertContained(root, destination);
  return destination;
}

async function objectBytes(
  object: NormalizedObjectGetOutput,
  key: string,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  for await (const chunk of bodyChunks(object.body, key)) {
    chunks.push(chunk);
    length += chunk.byteLength;
  }
  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), length);
  if (
    object.contentLength !== undefined &&
    object.contentLength !== body.byteLength
  ) {
    throw new Error(
      `content length mismatch for workspace object ${key}: ` +
        `expected ${object.contentLength}, received ${body.byteLength}`,
    );
  }
  return body;
}

async function publishEngineSnapshot(
  staging: string,
  destination: string,
  runRoot: string,
): Promise<void> {
  assertContained(runRoot, staging);
  assertContained(runRoot, destination);
  const existing = await pathKind(destination);
  if (existing === 'symlink') {
    throw new Error(
      `refusing to replace a symbolic-link engine workspace: ${destination}`,
    );
  }
  if (existing === 'other') {
    throw new Error(`engine workspace path is not a directory: ${destination}`);
  }
  if (existing === 'missing') {
    await rename(staging, destination);
    return;
  }
  const backup = join(runRoot, `.engine-backup-${randomUUID()}`);
  assertContained(runRoot, backup);
  await rename(destination, backup);
  try {
    await rename(staging, destination);
  } catch (error) {
    await rename(backup, destination);
    throw error;
  }
  await rm(backup, { recursive: true, force: true });
}

function isAwsPreconditionFailure(error: unknown): boolean {
  if (error === null || typeof error !== 'object') {
    return false;
  }
  const record = error as Record<string, unknown>;
  if (
    record['name'] === 'PreconditionFailed' ||
    record['name'] === 'PreconditionFailedException'
  ) {
    return true;
  }
  const metadata = asRecord(record['$metadata']);
  return metadata?.['httpStatusCode'] === 412;
}

function selectUploads(
  sourceArtifactIds: readonly string[],
  threatArtifactId: string | null,
): readonly UploadSelection[] {
  const selections = new Map<
    string,
    { uploadId: string; source: boolean; threat: boolean }
  >();
  for (const rawId of sourceArtifactIds) {
    const uploadId = validateIdentifier(rawId, 'source_artifact_id');
    const current = selections.get(uploadId);
    selections.set(uploadId, {
      uploadId,
      source: true,
      threat: current?.threat ?? false,
    });
  }
  if (threatArtifactId !== null) {
    const uploadId = validateIdentifier(
      threatArtifactId,
      'threat_artifact_id',
    );
    const current = selections.get(uploadId);
    selections.set(uploadId, {
      uploadId,
      source: current?.source ?? false,
      threat: true,
    });
  }
  return [...selections.values()];
}

function parseReadyManifest(
  item: unknown,
  ownerId: string,
  applicationId: string,
  uploadId: string,
): UploadManifest {
  const itemRecord = asRecord(item);
  const manifest = asRecord(itemRecord?.['manifest']);
  if (manifest === null) {
    throw new Error(`invalid ingestion upload manifest item: ${uploadId}`);
  }
  if (manifest['schemaVersion'] !== 1) {
    throw new Error(`unsupported ingestion manifest schema: ${uploadId}`);
  }
  if (
    !Number.isSafeInteger(manifest['revision']) ||
    (manifest['revision'] as number) < 1
  ) {
    throw new Error(`invalid ingestion manifest revision: ${uploadId}`);
  }
  if (
    manifest['ownerId'] !== ownerId ||
    manifest['applicationId'] !== applicationId ||
    manifest['uploadId'] !== uploadId
  ) {
    throw new Error(
      `ingestion manifest scope does not match the requested owner/application/upload: ${uploadId}`,
    );
  }
  if (manifest['status'] !== 'ready') {
    throw new Error(
      `ingestion upload is not ready: ${uploadId} (${String(manifest['status'])})`,
    );
  }
  const normalizedObjectIds = validatedIdentifierArray(
    manifest['normalizedObjectIds'],
    'normalizedObjectIds',
  );
  if (normalizedObjectIds.length === 0) {
    throw new Error(`ingestion upload has no usable normalized evidence: ${uploadId}`);
  }
  const authoritativeThreatObjectIds = validatedIdentifierArray(
    manifest['authoritativeThreatObjectIds'],
    'authoritativeThreatObjectIds',
  );
  const normalizedSet = new Set(normalizedObjectIds);
  if (normalizedSet.size !== normalizedObjectIds.length) {
    throw new Error(`ingestion manifest has duplicate normalized object IDs: ${uploadId}`);
  }
  if (
    authoritativeThreatObjectIds.some(
      (objectId) => !normalizedSet.has(objectId),
    )
  ) {
    throw new Error(
      `ingestion manifest references an authoritative object outside its normalized objects: ${uploadId}`,
    );
  }
  return {
    schemaVersion: 1,
    revision: manifest['revision'] as number,
    ownerId,
    applicationId,
    uploadId,
    status: 'ready',
    normalizedObjectIds,
    authoritativeThreatObjectIds,
  };
}

function validatedIdentifierArray(
  value: unknown,
  field: string,
): readonly string[] {
  if (!Array.isArray(value)) {
    throw new Error(`invalid ingestion manifest ${field}`);
  }
  return value.map((item) => {
    if (typeof item !== 'string') {
      throw new Error(`invalid ingestion manifest ${field}`);
    }
    return validateIdentifier(item, field);
  });
}

function canonicalNormalizedKey(
  ownerId: string,
  applicationId: string,
  uploadId: string,
  objectId: string,
): string {
  return (
    `v1/owners/${ownerId}/applications/${applicationId}` +
    `/uploads/${uploadId}/normalized/${objectId}`
  );
}

function deterministicFilename(
  uploadIndex: number,
  uploadId: string,
  objectIndex: number,
  objectId: string,
  metadata: Readonly<Record<string, string>>,
  contentType: string | undefined,
): string {
  const extension = extensionFor(metadata['artifact-format'], contentType);
  return (
    `${String(uploadIndex + 1).padStart(4, '0')}-` +
    `${digestPathSegment(uploadId).slice(0, 12)}-` +
    `${String(objectIndex + 1).padStart(4, '0')}-${objectId}${extension}`
  );
}

function extensionFor(
  artifactFormat: string | undefined,
  contentType: string | undefined,
): string {
  if (artifactFormat === 'markdown') {
    return '.md';
  }
  if (artifactFormat === 'text') {
    return '.txt';
  }
  if (artifactFormat === 'citations') {
    return '.json';
  }
  const normalizedContentType = contentType?.split(';', 1)[0]?.trim().toLowerCase();
  if (normalizedContentType === 'application/json') {
    return '.json';
  }
  if (normalizedContentType === 'text/markdown') {
    return '.md';
  }
  if (normalizedContentType?.startsWith('text/')) {
    return '.txt';
  }
  return '.bin';
}

async function writeVerifiedObject(
  destination: string,
  object: NormalizedObjectGetOutput,
  metadata: Readonly<Record<string, string>>,
  key: string,
): Promise<{ readonly sha256: string; readonly sizeBytes: number }> {
  const expectedSha256 = metadata['sha256'];
  if (expectedSha256 === undefined || !SHA256_HEX.test(expectedSha256)) {
    throw new Error(`normalized object has no valid SHA-256 metadata: ${key}`);
  }
  if (
    object.contentLength !== undefined &&
    (!Number.isSafeInteger(object.contentLength) || object.contentLength < 0)
  ) {
    throw new Error(`normalized object has an invalid content length: ${key}`);
  }
  let handle: FileHandle | null = null;
  let sizeBytes = 0;
  const hash = createHash('sha256');
  try {
    handle = await open(destination, 'wx', 0o600);
    for await (const chunk of bodyChunks(object.body, key)) {
      hash.update(chunk);
      sizeBytes += chunk.byteLength;
      await handle.writeFile(chunk);
    }
    await handle.sync();
  } catch (error) {
    await handle?.close();
    await rm(destination, { force: true });
    throw error;
  }
  await handle.close();
  const actualSha256 = hash.digest('hex');
  if (actualSha256 !== expectedSha256) {
    await rm(destination, { force: true });
    throw new Error(
      `SHA-256 mismatch for normalized object ${key}: expected ${expectedSha256}, received ${actualSha256}`,
    );
  }
  if (
    object.contentLength !== undefined &&
    object.contentLength !== sizeBytes
  ) {
    await rm(destination, { force: true });
    throw new Error(
      `content length mismatch for normalized object ${key}: expected ${object.contentLength}, received ${sizeBytes}`,
    );
  }
  return { sha256: actualSha256, sizeBytes };
}

async function* bodyChunks(
  body: unknown,
  key: string,
): AsyncGenerator<Uint8Array> {
  if (body instanceof Uint8Array) {
    yield body;
    return;
  }
  if (body instanceof ArrayBuffer) {
    yield new Uint8Array(body);
    return;
  }
  if (isRecord(body) && typeof body['transformToByteArray'] === 'function') {
    const bytes = await (
      body['transformToByteArray'] as () => Promise<Uint8Array>
    )();
    if (!(bytes instanceof Uint8Array)) {
      throw new Error(`S3 object body returned invalid bytes: ${key}`);
    }
    yield bytes;
    return;
  }
  if (hasAsyncIterator(body)) {
    for await (const chunk of body) {
      if (chunk instanceof Uint8Array) {
        yield chunk;
      } else if (chunk instanceof ArrayBuffer) {
        yield new Uint8Array(chunk);
      } else if (ArrayBuffer.isView(chunk)) {
        yield new Uint8Array(
          chunk.buffer,
          chunk.byteOffset,
          chunk.byteLength,
        );
      } else {
        throw new Error(`S3 object body yielded invalid bytes: ${key}`);
      }
    }
    return;
  }
  throw new Error(`S3 object body is missing or unreadable: ${key}`);
}

async function publishSourceSnapshot(
  staging: string,
  destination: string,
  runRoot: string,
): Promise<void> {
  assertContained(runRoot, staging);
  assertContained(runRoot, destination);
  const existing = await pathKind(destination);
  if (existing === 'symlink') {
    throw new Error(`refusing to replace a symbolic-link source workspace: ${destination}`);
  }
  if (existing === 'other') {
    throw new Error(`source workspace path is not a directory: ${destination}`);
  }
  if (existing === 'missing') {
    await rename(staging, destination);
    return;
  }
  const backup = join(runRoot, `.source-backup-${randomUUID()}`);
  assertContained(runRoot, backup);
  await rename(destination, backup);
  try {
    await rename(staging, destination);
  } catch (error) {
    await rename(backup, destination);
    throw error;
  }
  await rm(backup, { recursive: true, force: true });
}

async function ensureDirectory(path: string): Promise<void> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      throw new Error(`workspace directory must not be a symbolic link: ${path}`);
    }
    if (!stats.isDirectory()) {
      throw new Error(`workspace path is not a directory: ${path}`);
    }
  } catch (error) {
    if (!isMissingPathError(error)) {
      throw error;
    }
    await mkdir(path, { mode: 0o700 });
    const stats = await lstat(path);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw new Error(`failed to create a safe workspace directory: ${path}`);
    }
  }
}

async function assertSafeMetadataDestination(path: string): Promise<void> {
  const kind = await pathKind(path);
  if (kind === 'symlink') {
    throw new Error(`metadata destination must not be a symbolic link: ${path}`);
  }
  if (kind === 'directory') {
    throw new Error(`metadata destination is a directory: ${path}`);
  }
}

async function writeAtomicJson(path: string, value: unknown): Promise<void> {
  const temporaryPath = `${path}.tmp-${randomUUID()}`;
  let handle: FileHandle | null = null;
  try {
    handle = await open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporaryPath, path);
  } finally {
    await handle?.close();
    await rm(temporaryPath, { force: true });
  }
}

function normalizeMetadata(
  value: Readonly<Record<string, string | undefined>>,
  key: string,
): Readonly<Record<string, string>> {
  const entries: [string, string][] = [];
  for (const [rawKey, rawValue] of Object.entries(value)) {
    if (rawValue === undefined) {
      continue;
    }
    const normalizedKey = rawKey.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(normalizedKey)) {
      throw new Error(`normalized object has invalid metadata key ${rawKey}: ${key}`);
    }
    if (/[\u0000-\u001f\u007f-\u009f]/.test(rawValue)) {
      throw new Error(`normalized object has control characters in metadata: ${key}`);
    }
    entries.push([normalizedKey, rawValue]);
  }
  entries.sort(([left], [right]) => left.localeCompare(right));
  return Object.fromEntries(entries);
}

function asStringMetadata(
  value: unknown,
): Readonly<Record<string, string | undefined>> {
  const record = asRecord(value);
  if (record === null) {
    return {};
  }
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(record)) {
    if (typeof item === 'string') {
      output[key] = item;
    }
  }
  return output;
}

function validateIdentifier(value: string, field: string): string {
  if (!SAFE_INGESTION_IDENTIFIER.test(value)) {
    throw new Error(
      `${field} must be a safe 1-128 character ingestion identifier`,
    );
  }
  return value;
}

function validateOpaqueValue(value: string, field: string): string {
  if (
    value.length === 0 ||
    value.length > 512 ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value)
  ) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function requiredConfiguration(value: string, field: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${field} is required`);
  }
  return normalized;
}

function encodeKeyPart(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function digestPathSegment(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function assertContained(root: string, candidate: string): void {
  const relativePath = relative(root, candidate);
  if (
    relativePath.length === 0 ||
    relativePath === '..' ||
    relativePath.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) ||
    isAbsolute(relativePath)
  ) {
    if (relativePath.length === 0 && root === candidate) {
      return;
    }
    throw new Error(`workspace path escapes its root: ${candidate}`);
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isRecord(value: unknown): value is Record<PropertyKey, unknown> {
  return value !== null && typeof value === 'object';
}

function hasAsyncIterator(value: unknown): value is AsyncIterable<unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    Symbol.asyncIterator in value &&
    typeof (value as AsyncIterable<unknown>)[Symbol.asyncIterator] ===
      'function'
  );
}

async function pathKind(
  path: string,
): Promise<'missing' | 'directory' | 'symlink' | 'other'> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      return 'symlink';
    }
    return stats.isDirectory() ? 'directory' : 'other';
  } catch (error) {
    if (isMissingPathError(error)) {
      return 'missing';
    }
    throw error;
  }
}

function isMissingPathError(
  error: unknown,
): error is NodeJS.ErrnoException {
  return (
    error instanceof Error &&
    (error as NodeJS.ErrnoException).code === 'ENOENT'
  );
}

function isAwsMissingObject(error: unknown): boolean {
  if (error === null || typeof error !== 'object') {
    return false;
  }
  const record = error as Record<string, unknown>;
  if (record['name'] === 'NoSuchKey' || record['name'] === 'NotFound') {
    return true;
  }
  const metadata = asRecord(record['$metadata']);
  return metadata?.['httpStatusCode'] === 404;
}
