import { createHash, randomUUID } from 'node:crypto';
import {
  ApplicationIdSchema,
  BusinessContextSchema,
  type ApplicationId,
  type UserId,
} from '@threatforest/types';
import { encodeKeyPart } from '@threatforest/control-plane';
import {
  buildThreatforestReportArchive,
  THREATFOREST_REPORT_CONTENT_TYPE,
  type ThreatforestReportVersion,
} from '@threatforest/hosted-runtime/report-archive';
import { HostedApiError, conflict } from './errors.js';
import {
  parseThreatforestReportArchive,
  type ParsedThreatforestReport,
} from './report-format.js';
import type {
  ReportImportDestination,
  ReportImportResult,
  ReportImportSession,
  ReportImportStore,
  ReportImportWorkerLease,
} from './report-import-service.js';

const DEFAULT_LEASE_MILLISECONDS = 16 * 60 * 1_000;

export interface ReportImportSourceObject {
  body: Uint8Array;
  sizeBytes: number;
  checksumSha256: string;
  serverSideEncryption: string;
  kmsKeyId: string;
  bucketKeyEnabled: boolean;
  metadata: Readonly<Record<string, string | undefined>>;
}

export interface ReportImportSourceReader {
  get(session: ReportImportSession): Promise<ReportImportSourceObject>;
}

export interface ReportImportCommitter {
  prepareDestination(
    session: ReportImportSession,
    report: ParsedThreatforestReport,
  ): Promise<ReportImportDestination>;
  commit(
    session: ReportImportSession,
    report: ParsedThreatforestReport,
  ): Promise<ReportImportResult>;
}

export class ReportImportWorker {
  readonly #store: ReportImportStore;
  readonly #source: ReportImportSourceReader;
  readonly #committer: ReportImportCommitter;
  readonly #now: () => Date;
  readonly #leaseMilliseconds: number;

  constructor(
    store: ReportImportStore,
    source: ReportImportSourceReader,
    committer: ReportImportCommitter,
    now = () => new Date(),
    leaseMilliseconds = DEFAULT_LEASE_MILLISECONDS,
  ) {
    this.#store = store;
    this.#source = source;
    this.#committer = committer;
    this.#now = now;
    this.#leaseMilliseconds = leaseMilliseconds;
  }

  async process(ownerId: UserId, importId: ReportImportSession['importId']) {
    const existing = await this.#store.get(ownerId, importId);
    if (existing === null) {
      throw new Error(`Report import ${importId} does not exist.`);
    }
    if (existing.status === 'completed' || existing.status === 'failed') {
      return existing;
    }
    if (existing.status !== 'processing') {
      throw new Error(
        `Report import ${importId} cannot be processed while ${existing.status}.`,
      );
    }
    const acquire = this.#store.acquireProcessingLease;
    const save = this.#store.saveLeased;
    if (acquire === undefined || save === undefined) {
      throw new Error('Report import store does not support atomic worker leases.');
    }
    const acquiredAt = this.#now();
    const lease: ReportImportWorkerLease = {
      leaseId: randomUUID(),
      acquiredAt: acquiredAt.toISOString(),
      expiresAt: new Date(
        acquiredAt.getTime() + this.#leaseMilliseconds,
      ).toISOString(),
    };
    const session = await acquire.call(
      this.#store,
      ownerId,
      importId,
      lease,
    );
    if (session === null) {
      const latest = await this.#store.get(ownerId, importId);
      if (latest?.status === 'completed' || latest?.status === 'failed') {
        return latest;
      }
      throw new ReportImportLeaseUnavailableError(importId);
    }
    try {
      const source = await this.#source.get(session);
      assertSource(session, source);
      const parsed = parseThreatforestReportArchive(source.body);
      if (session.destination === undefined) {
        session.destination = await this.#committer.prepareDestination(
          session,
          parsed,
        );
        session.updatedAt = this.#now().toISOString();
        await saveLeased(this.#store, session, lease.leaseId);
      }
      session.result = await this.#committer.commit(session, parsed);
      session.status = 'completed';
      session.failureCode = null;
      session.updatedAt = this.#now().toISOString();
      session.workerLease = null;
      await saveLeased(this.#store, session, lease.leaseId);
      return session;
    } catch (error) {
      if (isPermanentReportFailure(error)) {
        session.status = 'failed';
        session.failureCode =
          error instanceof HostedApiError ? error.code : 'INVALID_REPORT';
        session.result = {
          bundle: session.filename,
          status: 'failed',
          folder_name: null,
          versions_added: [],
          versions_skipped: [],
          error: error instanceof Error ? error.message : 'Invalid report.',
        };
        session.updatedAt = this.#now().toISOString();
        session.workerLease = null;
        await saveLeased(this.#store, session, lease.leaseId);
        return session;
      }
      session.updatedAt = this.#now().toISOString();
      session.workerLease = null;
      await save.call(this.#store, session, lease.leaseId).catch(() => false);
      throw error;
    }
  }
}

export class ReportImportLeaseUnavailableError extends Error {
  constructor(importId: ReportImportSession['importId']) {
    super(`Report import ${importId} is already being processed.`);
    this.name = 'ReportImportLeaseUnavailableError';
  }
}

async function saveLeased(
  store: ReportImportStore,
  session: ReportImportSession,
  leaseId: string,
): Promise<void> {
  if (!(await store.saveLeased!(session, leaseId))) {
    throw new Error(`Report import ${session.importId} worker lease was lost.`);
  }
}

export interface ReportImportObjectWriter {
  putImmutable(input: {
    key: string;
    body: Uint8Array;
    contentType: string;
    checksumSha256: string;
    metadata: Record<string, string>;
  }): Promise<void>;
  get(key: string): Promise<Uint8Array>;
}

export interface ReportImportStateClient {
  listApplications(ownerId: UserId): Promise<Array<Record<string, unknown>>>;
  getMetadata(
    ownerId: UserId,
    applicationId: ApplicationId,
  ): Promise<Record<string, unknown> | null>;
  putMetadata(
    ownerId: UserId,
    applicationId: ApplicationId,
    metadata: Record<string, unknown>,
  ): Promise<void>;
  createApplication(item: Record<string, unknown>): Promise<void>;
  getVersion(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string,
  ): Promise<Record<string, unknown> | null>;
  putVersion(item: Record<string, unknown>): Promise<boolean>;
  listVersions(
    ownerId: UserId,
    applicationId: ApplicationId,
  ): Promise<Array<Record<string, unknown>>>;
  putApplicationReport(item: Record<string, unknown>): Promise<void>;
}

export class DurableReportImportCommitter implements ReportImportCommitter {
  readonly #objects: ReportImportObjectWriter;
  readonly #state: ReportImportStateClient;
  readonly #now: () => Date;

  constructor(
    objects: ReportImportObjectWriter,
    state: ReportImportStateClient,
    now = () => new Date(),
  ) {
    this.#objects = objects;
    this.#state = state;
    this.#now = now;
  }

  async commit(
    session: ReportImportSession,
    report: ParsedThreatforestReport,
  ): Promise<ReportImportResult> {
    const destination = requiredDestination(session);
    const added: string[] = [];
    const skipped: string[] = [];
    for (const version of report.versions) {
      const existing = await this.#state.getVersion(
        session.ownerId,
        destination.applicationId,
        version.id,
      );
      const dataSha256 = version.entries.find(
        (entry) => entry.path === 'output/threatforest_data.json',
      )!.sha256;
      if (existing !== null) {
        if (existing.data_sha256 !== dataSha256) {
          throw conflict(
            `Version '${version.id}' already exists with different content.`,
            'report_version_conflict',
          );
        }
        skipped.push(version.id);
        continue;
      }
      const bundleEntries = [];
      for (const entry of version.entries) {
        const key = this.#entryKey(
          session.ownerId,
          destination.applicationId,
          version.id,
          entry.path,
        );
        await this.#objects.putImmutable({
          key,
          body: entry.body,
          contentType: entry.contentType,
          checksumSha256: entry.sha256,
          metadata: {
            owner_id: session.ownerId,
            application_id: destination.applicationId,
            run_id: version.id,
            output_name: entry.path,
            sha256: entry.sha256,
            import_id: session.importId,
          },
        });
        bundleEntries.push({
          path: entry.path,
          key,
          content_type: entry.contentType,
          sha256: entry.sha256,
          size_bytes: entry.body.byteLength,
        });
      }
      const reportMetadata = {
        applicationId: destination.applicationId,
        applicationName: report.application.name,
        applicationSlug: report.manifest.source_app_slug,
        applicationDescription: report.application.description,
        applicationCreatedAt: report.application.createdAt,
        businessContext: report.application.businessContext,
        versions: [
          {
            id: version.id,
            entries: version.entries.map((entry) => ({
              path: entry.path,
              body: entry.body,
            })),
          },
        ],
        exportedAt: report.manifest.exported_at,
        threatforestVersion: report.manifest.exported_by_threatforest,
      };
      const single = buildThreatforestReportArchive({
        ...reportMetadata,
        includeScannerContext: true,
      });
      const singleWithoutScanner = buildThreatforestReportArchive({
        ...reportMetadata,
        includeScannerContext: false,
      });
      const singleKey = this.#reportKey(
        session.ownerId,
        destination.applicationId,
        version.id,
        'version.tfreport',
      );
      const singleWithoutScannerKey = this.#reportKey(
        session.ownerId,
        destination.applicationId,
        version.id,
        'version-without-scanner.tfreport',
      );
      await Promise.all([
        this.#objects.putImmutable({
          key: singleKey,
          body: single,
          contentType: THREATFOREST_REPORT_CONTENT_TYPE,
          checksumSha256: sha256(single),
          metadata: reportObjectMetadata(
            session,
            destination.applicationId,
            version.id,
            sha256(single),
          ),
        }),
        this.#objects.putImmutable({
          key: singleWithoutScannerKey,
          body: singleWithoutScanner,
          contentType: THREATFOREST_REPORT_CONTENT_TYPE,
          checksumSha256: sha256(singleWithoutScanner),
          metadata: reportObjectMetadata(
            session,
            destination.applicationId,
            version.id,
            sha256(singleWithoutScanner),
          ),
        }),
      ]);
      const item = {
        PK: hostedPartition(session.ownerId, destination.applicationId),
        SK: `VERSION#${encodeKeyPart(version.id)}`,
        entity: 'hosted-version',
        owner_id: session.ownerId,
        application_id: destination.applicationId,
        run_id: version.id,
        summary: version.summary,
        data_key: bundleEntries.find(
          (entry) => entry.path === 'output/threatforest_data.json',
        )!.key,
        bundle_entries: bundleEntries,
        report: storedReport(
          singleKey,
          `${safeFilename(report.manifest.source_app_slug)}-${safeFilename(version.id)}.tfreport`,
          single,
          version.id,
        ),
        report_without_scanner: storedReport(
          singleWithoutScannerKey,
          `${safeFilename(report.manifest.source_app_slug)}-${safeFilename(version.id)}.tfreport`,
          singleWithoutScanner,
          version.id,
        ),
        data_sha256: dataSha256,
        report_sha256: sha256(single),
        created_at: version.createdAt,
        imported_at: this.#now().toISOString(),
      };
      if (!(await this.#state.putVersion(item))) {
        const raced = await this.#state.getVersion(
          session.ownerId,
          destination.applicationId,
          version.id,
        );
        if (raced?.data_sha256 !== dataSha256) {
          throw conflict(
            `Version '${version.id}' was concurrently imported with different content.`,
            'report_version_conflict',
          );
        }
        skipped.push(version.id);
      } else {
        added.push(version.id);
      }
    }

    await this.#publishFullReport(session, destination.applicationId, report);
    const now = this.#now().toISOString();
    const metadata = {
      business_context:
        report.application.businessContext ??
        BusinessContextSchema.parse({
          description: report.application.description,
          regulatory_frameworks: [],
          data_sensitivity: 'unknown',
          cia_priority: ['confidentiality', 'integrity', 'availability'],
        }),
      project_path: '',
      deleted: false,
      imported_from_app_id: report.manifest.source_app_id,
      imported_from_app_name: report.manifest.source_app_name,
      imported_at: destination.importedAt,
      last_imported_at: now,
    };
    await this.#state.putMetadata(
      session.ownerId,
      destination.applicationId,
      metadata,
    );
    if (destination.mode === 'new') {
      await this.#state.createApplication({
        PK: controlPartition(session.ownerId, destination.applicationId),
        SK: 'APPLICATION',
        GSI1PK: `OWNER#${encodeKeyPart(session.ownerId)}`,
        GSI1SK: `APP#${encodeKeyPart(destination.applicationId)}`,
        entity: 'application',
        schema_version: 1,
        owner_id: session.ownerId,
        application_id: destination.applicationId,
        name: destination.name,
        description: report.application.description,
        revision: 1,
        created_at: report.application.createdAt,
        updated_at: now,
      });
    }
    return {
      bundle: session.filename,
      status:
        added.length === 0
          ? 'skipped'
          : destination.mode === 'merge'
            ? 'merged'
            : 'imported',
      folder_name: destination.applicationId,
      versions_added: added,
      versions_skipped: skipped,
      error: null,
    };
  }

  async prepareDestination(
    session: ReportImportSession,
    report: ParsedThreatforestReport,
  ): Promise<ReportImportDestination> {
    if (session.destination !== undefined) {
      return requiredDestination(session);
    }
    const applications = await this.#state.listApplications(session.ownerId);
    if (report.manifest.scope === 'single-version') {
      for (const application of applications) {
        const applicationId = ApplicationIdSchema.parse(
          application.application_id,
        );
        const metadata = await this.#state.getMetadata(
          session.ownerId,
          applicationId,
        );
        if (
          metadata?.imported_from_app_id === report.manifest.source_app_id
        ) {
          return {
            mode: 'merge' as const,
            applicationId,
            name: String(application.name ?? report.application.name),
            importedAt:
              typeof metadata.imported_at === 'string'
                ? metadata.imported_at
                : this.#now().toISOString(),
          };
        }
      }
    }
    const existingNames = new Set(
      applications.map((application) =>
        String(application.name ?? '').toLowerCase(),
      ),
    );
    const baseName = report.application.name;
    let name = baseName;
    for (let suffix = 1; existingNames.has(name.toLowerCase()); suffix += 1) {
      name = `${baseName} (imported${suffix === 1 ? '' : ` ${suffix}`})`;
    }
    return {
      mode: 'new' as const,
      applicationId: ApplicationIdSchema.parse(
        `app_import_${sha256(
          Buffer.from(`${session.ownerId}\0${session.importId}`),
        ).slice(0, 32)}`,
      ),
      name,
      importedAt: this.#now().toISOString(),
    };
  }

  async #publishFullReport(
    session: ReportImportSession,
    applicationId: ApplicationId,
    report: ParsedThreatforestReport,
  ): Promise<void> {
    const versions = (await this.#state.listVersions(
      session.ownerId,
      applicationId,
    )).sort((left, right) =>
      String(left.created_at).localeCompare(String(right.created_at)),
    );
    const archiveVersions: ThreatforestReportVersion[] = [];
    for (const version of versions) {
      if (!Array.isArray(version.bundle_entries)) {
        throw new Error('Imported version has no bundle entries.');
      }
      const entries = [];
      for (const raw of version.bundle_entries) {
        const entry = raw as Record<string, unknown>;
        const key = String(entry.key);
        const body = await this.#objects.get(key);
        if (
          body.byteLength !== Number(entry.size_bytes) ||
          sha256(body) !== entry.sha256
        ) {
          throw new Error(`Imported version entry failed integrity validation: ${key}`);
        }
        entries.push({ path: String(entry.path), body });
      }
      archiveVersions.push({ id: String(version.run_id), entries });
    }
    const common = {
      applicationId,
      applicationName: report.application.name,
      applicationSlug: report.manifest.source_app_slug,
      applicationDescription: report.application.description,
      applicationCreatedAt: report.application.createdAt,
      businessContext: report.application.businessContext,
      versions: archiveVersions,
      exportedAt: this.#now().toISOString(),
      threatforestVersion: report.manifest.exported_by_threatforest,
    };
    const full = buildThreatforestReportArchive({
      ...common,
      includeScannerContext: true,
    });
    const fullWithoutScanner = buildThreatforestReportArchive({
      ...common,
      includeScannerContext: false,
    });
    const digest = sha256(
      Buffer.from(
        JSON.stringify(
          versions.map((version) => [
            version.run_id,
            version.data_sha256,
          ]),
        ),
      ),
    );
    const prefix = applicationPrefix(session.ownerId, applicationId);
    const fullKey = `${prefix}/reports/full-${digest}.tfreport`;
    const fullWithoutScannerKey =
      `${prefix}/reports/full-${digest}-without-scanner.tfreport`;
    await Promise.all([
      this.#objects.putImmutable({
        key: fullKey,
        body: full,
        contentType: THREATFOREST_REPORT_CONTENT_TYPE,
        checksumSha256: sha256(full),
        metadata: reportObjectMetadata(
          session,
          applicationId,
          'full',
          sha256(full),
        ),
      }),
      this.#objects.putImmutable({
        key: fullWithoutScannerKey,
        body: fullWithoutScanner,
        contentType: THREATFOREST_REPORT_CONTENT_TYPE,
        checksumSha256: sha256(fullWithoutScanner),
        metadata: reportObjectMetadata(
          session,
          applicationId,
          'full',
          sha256(fullWithoutScanner),
        ),
      }),
    ]);
    await this.#state.putApplicationReport({
      PK: hostedPartition(session.ownerId, applicationId),
      SK: 'APPLICATION_REPORT',
      entity: 'hosted-application-report',
      owner_id: session.ownerId,
      application_id: applicationId,
      version_count: versions.length,
      version_digest: digest,
      version_ids: versions.map((version) => version.run_id),
      report: storedReport(
        fullKey,
        `${safeFilename(report.manifest.source_app_slug)}-full.tfreport`,
        full,
        'full',
      ),
      report_without_scanner: storedReport(
        fullWithoutScannerKey,
        `${safeFilename(report.manifest.source_app_slug)}-full.tfreport`,
        fullWithoutScanner,
        'full',
      ),
      updated_at: this.#now().toISOString(),
    });
  }

  #entryKey(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string,
    path: string,
  ): string {
    return `${applicationPrefix(ownerId, applicationId)}/runs/${versionId}/${path}`;
  }

  #reportKey(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string,
    name: string,
  ): string {
    return `${applicationPrefix(ownerId, applicationId)}/runs/${versionId}/reports/${name}`;
  }
}

function assertSource(
  session: ReportImportSession,
  source: ReportImportSourceObject,
): void {
  if (
    source.sizeBytes !== session.sizeBytes ||
    source.checksumSha256 !== session.checksumSha256 ||
    sha256(source.body) !== session.checksumSha256 ||
    source.serverSideEncryption !== 'aws:kms' ||
    source.kmsKeyId !== session.kmsKeyId ||
    source.bucketKeyEnabled !== true ||
    source.metadata.owner_id !== session.ownerId ||
    source.metadata.import_id !== session.importId
  ) {
    throw new HostedApiError(
      422,
      'report_source_integrity_failed',
      'Uploaded report failed encrypted object integrity validation.',
    );
  }
}

function isPermanentReportFailure(error: unknown): boolean {
  return error instanceof HostedApiError && error.status >= 400 && error.status < 500;
}

function requiredDestination(
  session: ReportImportSession,
): ReportImportDestination {
  const destination = session.destination;
  if (
    destination === undefined ||
    (destination.mode !== 'new' && destination.mode !== 'merge') ||
    typeof destination.name !== 'string' ||
    destination.name.length === 0 ||
    typeof destination.importedAt !== 'string'
  ) {
    throw new Error(
      `Report import ${session.importId} has no valid destination reservation.`,
    );
  }
  return {
    ...destination,
    applicationId: ApplicationIdSchema.parse(destination.applicationId),
  };
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function hostedPartition(ownerId: UserId, applicationId: ApplicationId): string {
  return (
    `HOSTED#OWNER#${encodeKeyPart(ownerId)}` +
    `#APP#${encodeKeyPart(applicationId)}`
  );
}

function controlPartition(ownerId: UserId, applicationId: ApplicationId): string {
  return (
    `OWNER#${encodeKeyPart(ownerId)}` +
    `#APP#${encodeKeyPart(applicationId)}`
  );
}

function applicationPrefix(
  ownerId: UserId,
  applicationId: ApplicationId,
): string {
  return `hosted/owners/${ownerId}/applications/${applicationId}`;
}

function storedReport(
  key: string,
  filename: string,
  body: Uint8Array,
  runId: string,
) {
  return {
    key,
    content_type: THREATFOREST_REPORT_CONTENT_TYPE,
    filename,
    metadata: {
      run_id: runId,
      sha256: sha256(body),
      size_bytes: body.byteLength,
    },
  };
}

function reportObjectMetadata(
  session: ReportImportSession,
  applicationId: ApplicationId,
  runId: string,
  digest: string,
): Record<string, string> {
  return {
    owner_id: session.ownerId,
    application_id: applicationId,
    run_id: runId,
    import_id: session.importId,
    sha256: digest,
  };
}

function safeFilename(value: string): string {
  return (
    value
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 100) || 'threatforest'
  );
}
