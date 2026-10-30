import { lstat, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import {
  ArtifactIdSchema,
  ArtifactRefSchema,
  RunIdSchema,
  VersionSummarySchema,
  runDisplayName,
  type ArtifactRef,
  type VersionSummary,
} from '@threatforest/types';
import { encodeKeyPart, type ControlPlaneScope } from '@threatforest/control-plane';
import {
  evaluateDomainOutputQuality,
  createSourceEvidenceResolver,
  type DomainQualityReport,
} from '@threatforest/engine';
import type {
  StageExecutionContext,
  StageOutputPublisher,
} from './contracts.js';
import {
  buildThreatforestReportArchive,
  THREATFOREST_REPORT_CONTENT_TYPE,
  type ThreatforestReportVersion,
} from './report-archive.js';
import type { ApprovedFeedbackMemory } from './memory.js';
import {
  createAgentCoreHostedTelemetry,
  runTelemetryAttributes,
  type HostedTelemetry,
  type HostedTelemetryAttributeValue,
} from './telemetry.js';
import { canonicalJson, isRecord, sha256 } from './util.js';

const ARCHIVE_FILES = [
  {
    path: 'output/threatforest_data.json',
    contentType: 'application/json',
    required: true,
  },
  {
    path: 'output/threat_model_report.md',
    contentType: 'text/markdown; charset=utf-8',
    required: true,
  },
  {
    path: 'output/attack_trees_dashboard.html',
    contentType: 'text/html; charset=utf-8',
    required: false,
  },
  {
    path: 'state/scanner_context.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'state/threats.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'state/attack_trees.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'state/ttp_mappings.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'state/mitigations.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'mitigation_overrides.json',
    contentType: 'application/json',
    required: false,
  },
  {
    path: 'run_metadata.json',
    contentType: 'application/json',
    required: false,
  },
] as const;

const MAX_APPLICATION_REPORT_CAS_ATTEMPTS = 4;
type ExportContext = Pick<StageExecutionContext, 'scope'> & {
  run: Pick<StageExecutionContext['run'], 'run_id' | 'created_at' | 'updated_at'>;
  stage: Pick<StageExecutionContext['stage'], 'version'>;
  settings: Pick<StageExecutionContext['settings'], 'business_context'>;
};

export interface PublishedObjectPutInput {
  bucketName: string;
  key: string;
  body: Uint8Array;
  contentType: string;
  checksumSha256: string;
  kmsKeyId: string;
  metadata: Readonly<Record<string, string>>;
}

export interface PublishedObjectHead {
  sizeBytes: number;
  metadata: Readonly<Record<string, string | undefined>>;
  serverSideEncryption?: string;
  kmsKeyId?: string;
  bucketKeyEnabled?: boolean;
}

export interface PublishedObjectClient {
  putObjectIfAbsent(input: PublishedObjectPutInput): Promise<boolean>;
  headObject(
    bucketName: string,
    key: string,
  ): Promise<PublishedObjectHead | null>;
  getObject(bucketName: string, key: string): Promise<Uint8Array | null>;
}

export interface HostedApplicationExportContext {
  readonly name: string;
  readonly description: string;
  readonly createdAt: string;
  readonly businessContext: Readonly<Record<string, unknown>> | null;
}

export interface HostedVersionStateClient {
  getVersion(
    tableName: string,
    partitionKey: string,
    sortKey: string,
  ): Promise<unknown | null>;
  putVersionIfAbsent(
    tableName: string,
    item: Readonly<Record<string, unknown>>,
  ): Promise<boolean>;
  listVersions(
    tableName: string,
    partitionKey: string,
  ): Promise<readonly unknown[]>;
  getApplicationReport(
    tableName: string,
    partitionKey: string,
  ): Promise<unknown | null>;
  getApplicationExportContext(
    tableName: string,
    controlPlanePartitionKey: string,
    hostedPartitionKey: string,
  ): Promise<HostedApplicationExportContext>;
  putApplicationReport(
    tableName: string,
    item: Readonly<Record<string, unknown>>,
    expectedVersionDigest: string | null,
  ): Promise<boolean>;
}

export interface HostedReportOutputPublisherOptions {
  tableName: string;
  bucketName: string;
  kmsKeyId: string;
  objectClient: PublishedObjectClient;
  versionClient: HostedVersionStateClient;
  keyPrefix?: string;
  threatforestVersion?: string;
  memory?: ApprovedFeedbackMemory;
  telemetry?: HostedTelemetry;
  logger?: Pick<Console, 'error'>;
}

export interface AwsHostedReportOutputPublisherOptions {
  tableName: string;
  bucketName: string;
  kmsKeyId: string;
  keyPrefix?: string;
  threatforestVersion?: string;
  memory?: ApprovedFeedbackMemory;
  telemetry?: HostedTelemetry;
  logger?: Pick<Console, 'error'>;
  region?: string;
  dynamoClientConfiguration?: Readonly<Record<string, unknown>>;
  s3ClientConfiguration?: Readonly<Record<string, unknown>>;
}

interface OutputFile {
  readonly archivePath: string;
  readonly filePath: string;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly sha256: string;
}

interface StoredBundleEntry {
  readonly path: string;
  readonly key: string;
  readonly content_type: string;
  readonly sha256: string;
  readonly size_bytes: number;
}

interface StoredVersion {
  readonly runId: string;
  readonly createdAt: string;
  readonly entries: readonly StoredBundleEntry[];
}

export interface AwsCommandClient {
  send(command: unknown): Promise<Record<string, unknown>>;
}

export interface AwsCommandConstructor {
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
  PutCommand: AwsCommandConstructor;
  QueryCommand: AwsCommandConstructor;
}

export interface HostedVersionDynamoCommands {
  GetCommand: AwsCommandConstructor;
  PutCommand: AwsCommandConstructor;
  QueryCommand: AwsCommandConstructor;
}

interface S3ClientModule {
  S3Client: new (configuration: Record<string, unknown>) => AwsCommandClient;
  PutObjectCommand: AwsCommandConstructor;
  HeadObjectCommand: AwsCommandConstructor;
  GetObjectCommand: AwsCommandConstructor;
}

export class HostedReportOutputPublisher implements StageOutputPublisher {
  readonly #tableName: string;
  readonly #bucketName: string;
  readonly #kmsKeyId: string;
  readonly #keyPrefix: string;
  readonly #threatforestVersion: string;
  readonly #objectClient: PublishedObjectClient;
  readonly #versionClient: HostedVersionStateClient;
  readonly #memory: ApprovedFeedbackMemory | null;
  readonly #telemetry: HostedTelemetry | null;
  readonly #logger: Pick<Console, 'error'>;

  constructor(options: HostedReportOutputPublisherOptions) {
    this.#tableName = required(options.tableName, 'tableName');
    this.#bucketName = required(options.bucketName, 'bucketName');
    this.#kmsKeyId = required(options.kmsKeyId, 'kmsKeyId');
    this.#keyPrefix = required(
      options.keyPrefix ?? 'hosted',
      'keyPrefix',
    ).replace(/^\/+|\/+$/g, '');
    this.#threatforestVersion = options.threatforestVersion ?? '';
    this.#objectClient = options.objectClient;
    this.#versionClient = options.versionClient;
    this.#memory = options.memory ?? null;
    this.#telemetry = options.telemetry ?? null;
    this.#logger = options.logger ?? console;
  }

  async publish(
    context: StageExecutionContext,
    runDir: string,
    repoPath?: string,
  ): Promise<readonly ArtifactRef[]> {
    if (context.stage.id !== 'report_verifier') {
      throw new Error('report outputs may only be published by report_verifier');
    }
    const files = await readOutputFiles(runDir);
    const data = files.find(
      (file) => file.archivePath === 'output/threatforest_data.json',
    );
    if (data === undefined) {
      throw new Error('threatforest_data.json was not available after validation');
    }
    const parsedData = parseReportData(data);
    const quality = evaluatePublishedOutputQuality(files, repoPath, runDir);
    if (!quality.gatePassed) {
      throw new Error(
        `report output failed the domain quality gate: ${quality.issues.join('; ')}`,
      );
    }
    const partitionKey = hostedApplicationPartition(context);
    const controlPlanePartitionKey = controlPlaneApplicationPartition(context);
    const application =
      await this.#versionClient.getApplicationExportContext(
        this.#tableName,
        controlPlanePartitionKey,
        partitionKey,
      );
    const storedEntries = await Promise.all(
      files.map(async (file): Promise<StoredBundleEntry> => {
        const key = this.#entryObjectKey(context, file.archivePath);
        await this.#putImmutable(context, file, key);
        return {
          path: file.archivePath,
          key,
          content_type: file.contentType,
          sha256: file.sha256,
          size_bytes: file.body.byteLength,
        };
      }),
    );
    const singleBundle = buildThreatforestReportArchive({
      ...archiveApplication(context, application),
      versions: [
        {
          id: context.run.run_id,
          entries: files.map((file) => ({
            path: file.archivePath,
            body: file.body,
          })),
        },
      ],
      includeScannerContext: true,
      exportedAt: context.run.updated_at,
      threatforestVersion: this.#threatforestVersion,
    });
    const singleKey = this.#singleReportKey(context);
    const singleFile = generatedReportFile(
      `${safeFilename(context.scope.application_id)}-${safeFilename(
        context.run.run_id,
      )}.tfreport`,
      singleBundle,
    );
    const singleArtifact = await this.#putImmutable(
      context,
      singleFile,
      singleKey,
    );
    const singleWithoutScannerFile = generatedReportFile(
      singleFile.archivePath,
      buildThreatforestReportArchive({
        ...archiveApplication(context, application),
        versions: [
          {
            id: context.run.run_id,
            entries: files.map((file) => ({
              path: file.archivePath,
              body: file.body,
            })),
          },
        ],
        includeScannerContext: false,
        exportedAt: context.run.updated_at,
        threatforestVersion: this.#threatforestVersion,
      }),
    );
    const singleWithoutScannerKey =
      this.#singleReportWithoutScannerKey(context);
    await this.#putImmutable(
      context,
      singleWithoutScannerFile,
      singleWithoutScannerKey,
    );

    const summary = versionSummary(context, parsedData);
    const sortKey = `VERSION#${encodeKeyPart(context.run.run_id)}`;
    const versionItem: Readonly<Record<string, unknown>> = {
      PK: partitionKey,
      SK: sortKey,
      entity: 'hosted-version',
      owner_id: context.scope.owner_id,
      application_id: context.scope.application_id,
      run_id: context.run.run_id,
      summary,
      data_key: this.#entryObjectKey(
        context,
        'output/threatforest_data.json',
      ),
      bundle_entries: storedEntries,
      report: storedReport(singleKey, singleFile, context.run.run_id),
      report_without_scanner: storedReport(
        singleWithoutScannerKey,
        singleWithoutScannerFile,
        context.run.run_id,
      ),
      data_sha256: data.sha256,
      report_sha256: singleFile.sha256,
      output_quality: quality,
      created_at: context.run.created_at,
    };
    const created = await this.#versionClient.putVersionIfAbsent(
      this.#tableName,
      versionItem,
    );
    if (!created) {
      const existing = await this.#versionClient.getVersion(
        this.#tableName,
        partitionKey,
        sortKey,
      );
      assertCompatibleVersion(existing, versionItem, context.run.run_id);
    }

    await this.#recordThreatModel(context, parsedData);
    if (created) {
      this.#recordQualityTelemetry(context, quality, summary);
    }
    return [singleArtifact];
  }

  #recordQualityTelemetry(
    context: StageExecutionContext,
    quality: DomainQualityReport,
    summary: VersionSummary,
  ): void {
    if (this.#telemetry === null) {
      return;
    }
    const attributes: Record<string, HostedTelemetryAttributeValue> = {
      ...runTelemetryAttributes(
        context.scope,
        context.run,
        context.settings,
        'completed',
      ),
      'threatforest.quality.schema_version': quality.schemaVersion,
      'threatforest.quality.gate_passed': quality.gatePassed,
      'threatforest.quality.issue_count': quality.issues.length,
      'threatforest.evaluation.ready': true,
      'threatforest.threat.count': summary.threat_count,
      'threatforest.threat.high_severity_count':
        summary.high_severity_count,
      'threatforest.threat.categories': summary.categories,
      'threatforest.ttp.accepted_precision_target':
        quality.policy.ttpAcceptedPrecisionTarget,
      'threatforest.ttp.acceptance_policy':
        quality.policy.ttpAcceptancePolicy,
      'threatforest.ttp.decision_coverage':
        quality.metrics.ttpDecisionCoverage,
      'threatforest.ttp.accepted_coverage':
        quality.metrics.ttpAcceptedCoverage,
      'threatforest.ttp.abstention_rate':
        quality.metrics.ttpAbstentionRate,
    };
    if (quality.metrics.mitigationCoverage !== null) {
      attributes['threatforest.mitigation.coverage'] = quality.metrics.mitigationCoverage;
    }
    if (quality.metrics.mitigationEvidenceCoverage !== null) {
      attributes['threatforest.mitigation.evidence_coverage'] = quality.metrics.mitigationEvidenceCoverage;
    }
    if (quality.metrics.meanAcceptedConfidence !== null) {
      attributes['threatforest.ttp.mean_accepted_confidence'] =
        quality.metrics.meanAcceptedConfidence;
    }
    this.#telemetry.record({
      spanName: 'threatforest.run.output_quality',
      status: 'ok',
      attributes,
    });
  }

  /** Build history only when an export is requested, reusing a digest cache. */
  async ensureApplicationReport(scope: ControlPlaneScope): Promise<void> {
    const partitionKey = hostedApplicationPartition({ scope });
    const versions = (await this.#versionClient.listVersions(this.#tableName, partitionKey))
      .map(parseStoredVersion).sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.runId.localeCompare(b.runId));
    const latest = versions.at(-1);
    if (!latest) return;
    const application = await this.#versionClient.getApplicationExportContext(
      this.#tableName, controlPlaneApplicationPartition({ scope }), partitionKey);
    await this.#publishApplicationReport({
      scope,
      run: { run_id: RunIdSchema.parse(latest.runId), created_at: latest.createdAt, updated_at: latest.createdAt },
      stage: { version: 1 },
      settings: {},
    }, application, partitionKey);
  }

  async #publishApplicationReport(
    context: ExportContext,
    application: HostedApplicationExportContext,
    partitionKey: string,
  ): Promise<void> {
    for (
      let attempt = 1;
      attempt <= MAX_APPLICATION_REPORT_CAS_ATTEMPTS;
      attempt += 1
    ) {
      const existing = await this.#versionClient.getApplicationReport(
        this.#tableName,
        partitionKey,
      );
      const expectedVersionDigest = applicationReportDigest(existing);
      const versions = (
        await this.#versionClient.listVersions(
          this.#tableName,
          partitionKey,
        )
      )
        .map(parseStoredVersion)
        .sort(
          (left, right) =>
            left.createdAt.localeCompare(right.createdAt) ||
            left.runId.localeCompare(right.runId),
        );
      const versionDigest = sha256(canonicalJson({
        application,
        versions: versions.map(version => ({
          run_id: version.runId,
          entries: version.entries.map(entry => [entry.path, entry.sha256]),
        })),
      }));
      if (expectedVersionDigest === versionDigest) return;
      const archiveVersions: ThreatforestReportVersion[] = [];
      for (const version of versions) {
        const entries = [];
        for (const entry of version.entries) {
          const body = await this.#objectClient.getObject(this.#bucketName, entry.key);
          if (body === null) {
            throw new Error(
              `stored report entry is missing for ${version.runId}: ${entry.key}`,
            );
          }
          if (
            body.byteLength !== entry.size_bytes ||
            sha256(body) !== entry.sha256
          ) {
            throw new Error(
              `stored report entry failed integrity validation: ${entry.key}`,
            );
          }
          entries.push({ path: entry.path, body });
        }
        archiveVersions.push({ id: version.runId, entries });
      }
      const fullFile = generatedReportFile(
        `${safeFilename(context.scope.application_id)}-full.tfreport`,
        buildThreatforestReportArchive({
          ...archiveApplication(context, application),
          versions: archiveVersions,
          includeScannerContext: true,
          exportedAt: context.run.updated_at,
          threatforestVersion: this.#threatforestVersion,
        }),
      );
      const fullKey = this.#fullReportKey(context, versionDigest);
      await this.#putImmutable(context, fullFile, fullKey);
      const fullWithoutScannerFile = generatedReportFile(
        fullFile.archivePath,
        buildThreatforestReportArchive({
          ...archiveApplication(context, application),
          versions: archiveVersions,
          includeScannerContext: false,
          exportedAt: context.run.updated_at,
          threatforestVersion: this.#threatforestVersion,
        }),
      );
      const fullWithoutScannerKey = this.#fullReportWithoutScannerKey(
        context,
        versionDigest,
      );
      await this.#putImmutable(
        context,
        fullWithoutScannerFile,
        fullWithoutScannerKey,
      );
      const updated = await this.#versionClient.putApplicationReport(
        this.#tableName,
        {
          PK: partitionKey,
          SK: 'APPLICATION_REPORT',
          entity: 'hosted-application-report',
          owner_id: context.scope.owner_id,
          application_id: context.scope.application_id,
          version_count: versions.length,
          version_digest: versionDigest,
          version_ids: versions.map((version) => version.runId),
          report: storedReport(fullKey, fullFile, context.run.run_id),
          report_without_scanner: storedReport(
            fullWithoutScannerKey,
            fullWithoutScannerFile,
            context.run.run_id,
          ),
          updated_at: context.run.updated_at,
        },
        expectedVersionDigest,
      );
      if (updated) {
        return;
      }
    }
    throw new Error(
      `application report changed during ${String(
        MAX_APPLICATION_REPORT_CAS_ATTEMPTS,
      )} publication attempts`,
    );
  }

  async #recordThreatModel(
    context: StageExecutionContext,
    threatModel: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    if (this.#memory === null) {
      return;
    }
    try {
      await this.#memory.recordThreatModel({
        actorId: context.actorId,
        applicationId: context.scope.application_id,
        runId: context.run.run_id,
        createdAt: context.run.updated_at,
        threatModel,
      });
    } catch (error) {
      this.#logger.error(
        JSON.stringify({
          level: 'error',
          event: 'agentcore_memory_write_failed',
          operation: 'record_threat_model',
          application_id: context.scope.application_id,
          run_id: context.run.run_id,
        }),
        error,
      );
    }
  }

  async #putImmutable(
    context: ExportContext,
    file: OutputFile,
    key: string,
  ): Promise<ArtifactRef> {
    const artifactId = ArtifactIdSchema.parse(
      `report_${sha256(
        `${context.run.run_id}\0${file.archivePath}\0${file.sha256}`,
      ).slice(0, 48)}`,
    );
    const created = await this.#objectClient.putObjectIfAbsent({
      bucketName: this.#bucketName,
      key,
      body: file.body,
      contentType: file.contentType,
      checksumSha256: file.sha256,
      kmsKeyId: this.#kmsKeyId,
      metadata: {
        sha256: file.sha256,
        artifact_id: artifactId,
        owner_id: context.scope.owner_id,
        application_id: context.scope.application_id,
        run_id: context.run.run_id,
        output_name: file.archivePath,
      },
    });
    if (!created) {
      const existing = await this.#objectClient.headObject(
        this.#bucketName,
        key,
      );
      if (
        existing === null ||
        existing.sizeBytes !== file.body.byteLength ||
        existing.metadata['sha256'] !== file.sha256 ||
        existing.serverSideEncryption !== 'aws:kms' ||
        existing.kmsKeyId !== this.#kmsKeyId ||
        existing.bucketKeyEnabled !== true
      ) {
        throw new Error(
          `published output key ${key} contains different content`,
        );
      }
    }
    return ArtifactRefSchema.parse({
      artifact_id: artifactId,
      kind: 'report',
      version: context.stage.version,
      content_type: file.contentType,
      size_bytes: file.body.byteLength,
      sha256: file.sha256,
      created_at: context.run.created_at,
    });
  }

  #entryObjectKey(
    context: StageExecutionContext,
    archivePath: string,
  ): string {
    return `${this.#runPrefix(context)}/${archivePath}`;
  }

  #singleReportKey(context: StageExecutionContext): string {
    return `${this.#runPrefix(context)}/reports/version.tfreport`;
  }

  #singleReportWithoutScannerKey(
    context: StageExecutionContext,
  ): string {
    return `${this.#runPrefix(context)}/reports/version-without-scanner.tfreport`;
  }

  #fullReportKey(
    context: ExportContext,
    versionDigest: string,
  ): string {
    return [
      this.#applicationPrefix(context),
      'reports',
      `full-${versionDigest}.tfreport`,
    ].join('/');
  }

  #fullReportWithoutScannerKey(
    context: ExportContext,
    versionDigest: string,
  ): string {
    return [
      this.#applicationPrefix(context),
      'reports',
      `full-${versionDigest}-without-scanner.tfreport`,
    ].join('/');
  }

  #runPrefix(context: StageExecutionContext): string {
    return [
      this.#applicationPrefix(context),
      'runs',
      context.run.run_id,
    ].join('/');
  }

  #applicationPrefix(context: Pick<StageExecutionContext, 'scope'>): string {
    return [
      this.#keyPrefix,
      'owners',
      context.scope.owner_id,
      'applications',
      context.scope.application_id,
    ].join('/');
  }
}

export function createDynamoHostedVersionStateClient(
  documentClient: AwsCommandClient,
  commands: HostedVersionDynamoCommands,
): HostedVersionStateClient {
  return {
    async getVersion(tableName, partitionKey, sortKey) {
      const response = await documentClient.send(
        new commands.GetCommand({
          TableName: tableName,
          Key: { PK: partitionKey, SK: sortKey },
          ConsistentRead: true,
        }),
      );
      return response['Item'] ?? null;
    },
    async putVersionIfAbsent(tableName, item) {
      try {
        await documentClient.send(
          new commands.PutCommand({
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
    async listVersions(tableName, partitionKey) {
      const items: unknown[] = [];
      let exclusiveStartKey: Record<string, unknown> | undefined;
      do {
        const response = await documentClient.send(
          new commands.QueryCommand({
            TableName: tableName,
            KeyConditionExpression:
              'PK = :partition AND begins_with(SK, :version)',
            ExpressionAttributeValues: {
              ':partition': partitionKey,
              ':version': 'VERSION#',
            },
            ConsistentRead: true,
            ...(exclusiveStartKey === undefined
              ? {}
              : { ExclusiveStartKey: exclusiveStartKey }),
          }),
        );
        if (Array.isArray(response['Items'])) {
          items.push(...response['Items']);
        }
        exclusiveStartKey = isRecord(response['LastEvaluatedKey'])
          ? response['LastEvaluatedKey']
          : undefined;
      } while (exclusiveStartKey !== undefined);
      return items;
    },
    async getApplicationReport(tableName, partitionKey) {
      const response = await documentClient.send(
        new commands.GetCommand({
          TableName: tableName,
          Key: { PK: partitionKey, SK: 'APPLICATION_REPORT' },
          ConsistentRead: true,
        }),
      );
      return response['Item'] ?? null;
    },
    async getApplicationExportContext(
      tableName,
      controlPlanePartitionKey,
      hostedPartitionKey,
    ) {
      const [applicationResponse, metadataResponse] = await Promise.all([
        documentClient.send(
          new commands.GetCommand({
            TableName: tableName,
            Key: {
              PK: controlPlanePartitionKey,
              SK: 'APPLICATION',
            },
            ConsistentRead: true,
          }),
        ),
        documentClient.send(
          new commands.GetCommand({
            TableName: tableName,
            Key: { PK: hostedPartitionKey, SK: 'METADATA' },
            ConsistentRead: true,
          }),
        ),
      ]);
      const application = asRecord(
        applicationResponse['Item'],
        'application export metadata is missing',
      );
      const hosted = isRecord(metadataResponse['Item'])
        ? metadataResponse['Item']
        : {};
      const businessContext = isRecord(hosted['business_context'])
        ? hosted['business_context']
        : null;
      return {
        name:
          typeof application['name'] === 'string'
            ? application['name']
            : String(application['application_id'] ?? 'ThreatForest'),
        description:
          typeof businessContext?.['description'] === 'string'
            ? businessContext['description']
            : '',
        createdAt:
          typeof application['created_at'] === 'string'
            ? application['created_at']
            : '',
        businessContext,
      };
    },
    async putApplicationReport(
      tableName,
      item,
      expectedVersionDigest,
    ) {
      const nextVersionDigest = item['version_digest'];
      if (typeof nextVersionDigest !== 'string') {
        throw new Error('application report version_digest is required');
      }
      const condition =
        expectedVersionDigest === null
          ? 'attribute_not_exists(version_digest) OR version_digest = :nextVersionDigest'
          : 'version_digest = :expectedVersionDigest OR version_digest = :nextVersionDigest';
      const values: Record<string, unknown> = {
        ':nextVersionDigest': nextVersionDigest,
      };
      if (expectedVersionDigest !== null) {
        values[':expectedVersionDigest'] = expectedVersionDigest;
      }
      try {
        await documentClient.send(
          new commands.PutCommand({
            TableName: tableName,
            Item: item,
            ConditionExpression: condition,
            ExpressionAttributeValues: values,
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
  };
}

export async function createAwsHostedReportOutputPublisher(
  options: AwsHostedReportOutputPublisherOptions,
): Promise<HostedReportOutputPublisher> {
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
  const documentClient = document.DynamoDBDocumentClient.from(
    new dynamo.DynamoDBClient({
      ...options.dynamoClientConfiguration,
      ...(options.region === undefined ? {} : { region: options.region }),
    }),
    {
      marshallOptions: {
        removeUndefinedValues: true,
        convertClassInstanceToMap: false,
      },
    },
  );
  const s3Client = new s3.S3Client({
    ...options.s3ClientConfiguration,
    ...(options.region === undefined ? {} : { region: options.region }),
  });
  const publisherOptions: HostedReportOutputPublisherOptions = {
    tableName: options.tableName,
    bucketName: options.bucketName,
    kmsKeyId: options.kmsKeyId,
    objectClient: {
      async putObjectIfAbsent(input) {
        try {
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
          return true;
        } catch (error) {
          if (isHttpFailure(error, 412, 'PreconditionFailed')) {
            return false;
          }
          throw error;
        }
      },
      async headObject(bucketName, key) {
        try {
          const response = await s3Client.send(
            new s3.HeadObjectCommand({ Bucket: bucketName, Key: key }),
          );
          const sizeBytes = response['ContentLength'];
          if (typeof sizeBytes !== 'number') {
            throw new Error(`S3 output ${key} is missing ContentLength`);
          }
          return {
            sizeBytes,
            metadata: stringMetadata(response['Metadata']),
            ...(typeof response['ServerSideEncryption'] === 'string'
              ? {
                  serverSideEncryption: response[
                    'ServerSideEncryption'
                  ] as string,
                }
              : {}),
            ...(typeof response['SSEKMSKeyId'] === 'string'
              ? { kmsKeyId: response['SSEKMSKeyId'] as string }
              : {}),
            ...(typeof response['BucketKeyEnabled'] === 'boolean'
              ? { bucketKeyEnabled: response['BucketKeyEnabled'] as boolean }
              : {}),
          };
        } catch (error) {
          if (isHttpFailure(error, 404, 'NotFound')) {
            return null;
          }
          throw error;
        }
      },
      async getObject(bucketName, key) {
        try {
          const response = await s3Client.send(
            new s3.GetObjectCommand({ Bucket: bucketName, Key: key }),
          );
          return bodyBytes(response['Body'], key);
        } catch (error) {
          if (isHttpFailure(error, 404, 'NoSuchKey')) {
            return null;
          }
          throw error;
        }
      },
    },
    versionClient: createDynamoHostedVersionStateClient(
      documentClient,
      document,
    ),
  };
  if (options.memory !== undefined) {
    publisherOptions.memory = options.memory;
  }
  publisherOptions.telemetry =
    options.telemetry ?? createAgentCoreHostedTelemetry();
  if (options.logger !== undefined) {
    publisherOptions.logger = options.logger;
  }
  if (options.keyPrefix !== undefined) {
    publisherOptions.keyPrefix = options.keyPrefix;
  }
  if (options.threatforestVersion !== undefined) {
    publisherOptions.threatforestVersion = options.threatforestVersion;
  }
  return new HostedReportOutputPublisher(publisherOptions);
}

async function readOutputFiles(runDir: string): Promise<OutputFile[]> {
  const root = resolve(runDir);
  const rootStats = await lstat(root);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new Error(`report run directory is not a regular directory: ${root}`);
  }
  const files: OutputFile[] = [];
  for (const definition of ARCHIVE_FILES) {
    const filePath = join(root, definition.path);
    let stats;
    try {
      stats = await lstat(filePath);
    } catch (error) {
      if (
        !definition.required &&
        error instanceof Error &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        continue;
      }
      throw error;
    }
    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw new Error(`report output is not a regular file: ${filePath}`);
    }
    const body = await readFile(filePath);
    files.push({
      archivePath: definition.path,
      filePath,
      body,
      contentType: definition.contentType,
      sha256: sha256(body),
    });
  }
  return files;
}

function generatedReportFile(
  filename: string,
  body: Uint8Array,
): OutputFile {
  return {
    archivePath: filename,
    filePath: filename,
    body,
    contentType: THREATFOREST_REPORT_CONTENT_TYPE,
    sha256: sha256(body),
  };
}

function parseReportData(file: OutputFile): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(file.body).toString('utf8')) as unknown;
  } catch {
    throw new Error(`${file.filePath} is not valid JSON`);
  }
  if (!isRecord(parsed)) {
    throw new Error(`${file.filePath} must contain a JSON object`);
  }
  return parsed;
}

function evaluatePublishedOutputQuality(
  files: readonly OutputFile[],
  repoPath?: string,
  runDir?: string,
): DomainQualityReport {
  const required = (
    archivePath: string,
    field: string,
  ): Array<Record<string, unknown>> => {
    const file = files.find((candidate) => candidate.archivePath === archivePath);
    if (file === undefined) {
      throw new Error(`${archivePath} is required for output quality evaluation`);
    }
    const parsed = parseReportData(file);
    const value = parsed[field];
    if (!Array.isArray(value)) {
      throw new Error(`${archivePath} must contain an array field ${field}`);
    }
    if (value.some((entry) => entry === null || typeof entry !== 'object' || Array.isArray(entry))) {
      throw new Error(`${archivePath} must contain only objects in ${field}`);
    }
    return value;
  };
  return evaluateDomainOutputQuality({
    threats: required('state/threats.json', 'threats'),
    attackTrees: required('state/attack_trees.json', 'attack_trees'),
    ttpMappings: required('state/ttp_mappings.json', 'ttp_mappings'),
    mitigations: required('state/mitigations.json', 'mitigations'),
    resolveEvidence: repoPath === undefined ? undefined : createSourceEvidenceResolver(
      repoPath, runDir === undefined ? [] : [join(runDir, 'state'), join(runDir, 'output')],
    ),
  });
}

function storedReport(
  key: string,
  file: OutputFile,
  runId: string,
): Readonly<Record<string, unknown>> {
  return {
    key,
    content_type: file.contentType,
    filename: file.archivePath,
    metadata: {
      run_id: runId,
      sha256: file.sha256,
      size_bytes: file.body.byteLength,
    },
  };
}

function archiveApplication(
  context: ExportContext,
  application: HostedApplicationExportContext,
): {
  applicationId: string;
  applicationName: string;
  applicationSlug: string;
  applicationDescription: string;
  applicationCreatedAt: string;
  businessContext: Readonly<Record<string, unknown>> | null;
} {
  return {
    applicationId: context.scope.application_id,
    applicationName: application.name,
    applicationSlug: context.scope.application_id,
    applicationDescription: context.settings.business_context?.description ?? application.description,
    applicationCreatedAt: application.createdAt,
    businessContext: context.settings.business_context ?? application.businessContext,
  };
}

function versionSummary(
  context: StageExecutionContext,
  data: Record<string, unknown>,
): VersionSummary {
  const extraction = isRecord(data['extraction_summary'])
    ? data['extraction_summary']
    : {};
  const categories = Array.isArray(data['categories'])
    ? data['categories'].filter(
        (value): value is string => typeof value === 'string',
      )
    : [];
  return VersionSummarySchema.parse({
    id: context.run.run_id,
    run_date: context.run.created_at,
    status:
      typeof data['status'] === 'string' && data['status'].length > 0
        ? data['status']
        : 'complete',
    threat_count: nonNegativeInteger(
      data['threat_count'],
      extraction['total_threats'],
    ),
    high_severity_count: nonNegativeInteger(
      data['high_severity_count'],
      extraction['high_severity_count'],
    ),
    categories: [...new Set(categories)],
    display_name: context.run.display_name || runDisplayName(null, context.run.created_at),
    run_id: context.run.run_id,
  });
}

function nonNegativeInteger(primary: unknown, fallback: unknown): number {
  for (const value of [primary, fallback]) {
    const parsed = typeof value === 'number' ? value : Number(value);
    if (Number.isSafeInteger(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return 0;
}

function applicationReportDigest(value: unknown | null): string | null {
  if (value === null) {
    return null;
  }
  const item = asRecord(value, 'stored application report is malformed');
  const digest = item['version_digest'];
  if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)) {
    throw new Error('stored application report version_digest is malformed');
  }
  return digest;
}

function parseStoredVersion(value: unknown): StoredVersion {
  const item = asRecord(value, 'stored hosted version is malformed');
  const runId = requiredString(
    item['run_id'],
    'stored hosted version run_id is malformed',
  );
  const createdAt = requiredString(
    item['created_at'],
    'stored hosted version created_at is malformed',
  );
  if (!Array.isArray(item['bundle_entries'])) {
    throw new Error(
      `stored hosted version ${runId} has no importable bundle entries`,
    );
  }
  const entries = item['bundle_entries'].map(
    (entry, index): StoredBundleEntry => {
      const record = asRecord(
        entry,
        `stored hosted version ${runId} entry ${index} is malformed`,
      );
      const size = record['size_bytes'];
      if (!Number.isSafeInteger(size) || Number(size) < 0) {
        throw new Error(
          `stored hosted version ${runId} entry ${index} size is malformed`,
        );
      }
      return {
        path: requiredString(record['path'], 'bundle entry path is malformed'),
        key: requiredString(record['key'], 'bundle entry key is malformed'),
        content_type: requiredString(
          record['content_type'],
          'bundle entry content type is malformed',
        ),
        sha256: requiredString(
          record['sha256'],
          'bundle entry sha256 is malformed',
        ),
        size_bytes: Number(size),
      };
    },
  );
  return { runId, createdAt, entries };
}

function assertCompatibleVersion(
  existing: unknown,
  expected: Readonly<Record<string, unknown>>,
  runId: string,
): void {
  if (!isRecord(existing)) {
    throw new Error(
      `hosted version ${runId} was not readable after a write race`,
    );
  }
  for (const key of [
    'PK',
    'SK',
    'entity',
    'summary',
    'data_key',
    'bundle_entries',
    'report',
    'report_without_scanner',
  ]) {
    if (canonicalJson(existing[key]) !== canonicalJson(expected[key])) {
      throw new Error(
        `hosted version ${runId} already contains different ${key}`,
      );
    }
  }
}

function hostedApplicationPartition(context: Pick<StageExecutionContext, 'scope'>): string {
  return (
    `HOSTED#OWNER#${encodeKeyPart(context.scope.owner_id)}` +
    `#APP#${encodeKeyPart(context.scope.application_id)}`
  );
}

function controlPlaneApplicationPartition(
  context: Pick<StageExecutionContext, 'scope'>,
): string {
  return (
    `OWNER#${encodeKeyPart(context.scope.owner_id)}` +
    `#APP#${encodeKeyPart(context.scope.application_id)}`
  );
}

function safeFilename(value: string): string {
  const safe = value
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return safe || 'threatforest';
}

function required(value: string, name: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`${name} is required`);
  }
  return normalized;
}

function requiredString(value: unknown, message: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(message);
  }
  return value;
}

function asRecord(
  value: unknown,
  message: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(message);
  }
  return value;
}

function stringMetadata(
  value: unknown,
): Readonly<Record<string, string | undefined>> {
  if (!isRecord(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key.toLowerCase(),
      typeof item === 'string' ? item : undefined,
    ]),
  );
}

async function bodyBytes(value: unknown, key: string): Promise<Uint8Array> {
  if (
    typeof value === 'object' &&
    value !== null &&
    'transformToByteArray' in value &&
    typeof (value as { transformToByteArray?: unknown })
      .transformToByteArray === 'function'
  ) {
    return (
      value as { transformToByteArray(): Promise<Uint8Array> }
    ).transformToByteArray();
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new Error(`S3 output ${key} has no readable body`);
}

function isHttpFailure(
  error: unknown,
  statusCode: number,
  name: string,
): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  const metadata = (error as Error & {
    $metadata?: { httpStatusCode?: number };
  }).$metadata;
  return (
    error.name === name ||
    metadata?.httpStatusCode === statusCode
  );
}
