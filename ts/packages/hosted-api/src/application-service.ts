import type {
  ApplicationId,
  ApplicationSummary,
  UserId,
  VersionSummary,
} from '@threatforest/types';
import {
  ApplicationCreateRequestSchema,
  ApplicationUpdateRequestSchema,
  MitigationOverrideRequestSchema,
  MitigationOverrideSchema,
  runDisplayName,
  type Application,
} from '@threatforest/types';
import type {
  ApplicationRecord,
  ControlPlaneScope,
  ControlPlaneStore,
} from '@threatforest/control-plane';
import {
  conflict,
  notFound,
  unprocessable,
} from './errors.js';
import type {
  ApplicationCompatibilityMetadata,
  ApplicationMetadataStore,
  Clock,
  IdFactory,
  MutationContext,
  MutationResponseRecord,
  ReportPayload,
  VersionStore,
} from './contracts.js';
import { IdempotencyExecutor } from './idempotency.js';
import {
  ACCOUNT_SCOPE_APPLICATION_ID,
  asApplicationId,
  slugify,
} from './runtime.js';

export interface ApplicationServiceOptions {
  controlPlane: ControlPlaneStore;
  metadata: ApplicationMetadataStore;
  versions: VersionStore;
  idempotency: IdempotencyExecutor;
  ids: IdFactory;
  clock: Clock;
}

function emptyVersions(): VersionSummary[] {
  return [];
}

export class ApplicationService {
  readonly #controlPlane: ControlPlaneStore;
  readonly #metadata: ApplicationMetadataStore;
  readonly #versions: VersionStore;
  readonly #idempotency: IdempotencyExecutor;
  readonly #ids: IdFactory;
  readonly #clock: Clock;

  constructor(options: ApplicationServiceOptions) {
    this.#controlPlane = options.controlPlane;
    this.#metadata = options.metadata;
    this.#versions = options.versions;
    this.#idempotency = options.idempotency;
    this.#ids = options.ids;
    this.#clock = options.clock;
  }

  async list(ownerId: UserId): Promise<{ applications: ApplicationSummary[] }> {
    const records = await this.#controlPlane.listApplications(ownerId);
    const applications = await Promise.all(
      records.map(async (record): Promise<ApplicationSummary | null> => {
        const metadata = await this.#metadata.get(record);
        if (metadata?.deleted === true) {
          return null;
        }
        const versions = await this.#versions.list(record).catch(emptyVersions);
        return this.#summary(record, this.#metadataOrDefault(record, metadata), versions);
      }),
    );
    return {
      applications: applications
        .filter((value): value is ApplicationSummary => value !== null)
        .sort((left, right) => right.last_run_date.localeCompare(left.last_run_date)),
    };
  }

  async create(
    context: MutationContext,
    input: unknown,
  ): Promise<MutationResponseRecord & { value: Application }> {
    const parsed = ApplicationCreateRequestSchema.parse(input);
    const name = parsed.name.trim();
    if (name.length === 0 || name.length > 256) {
      throw unprocessable('Application name must contain 1-256 characters.');
    }
    if (parsed.project_path.length > 2048) {
      throw unprocessable('Project path must not exceed 2048 characters.');
    }
    const accountScope = this.#accountScope(context.ownerId);
    return this.#idempotency.execute(
      accountScope,
      context.idempotencyKey,
      'create_application',
      parsed,
      async () => {
        await this.#assertUniqueName(context.ownerId, name);
        const now = this.#clock.now().toISOString();
        const applicationId = this.#ids.applicationId();
        const record: ApplicationRecord = {
          schema_version: 1,
          owner_id: context.ownerId,
          application_id: applicationId,
          name,
          description: parsed.business_context.description,
          revision: 1,
          created_at: now,
          updated_at: now,
        };
        const metadata: ApplicationCompatibilityMetadata = {
          businessContext: parsed.business_context,
          projectPath: parsed.project_path,
          deleted: false,
          importedFromAppId: null,
          importedFromAppName: null,
          importedAt: null,
          lastImportedAt: null,
        };
        await this.#controlPlane.createApplication(record);
        await this.#metadata.put(record, metadata);
        return { status: 201, value: this.#application(record, metadata) };
      },
    );
  }

  async get(ownerId: UserId, applicationId: ApplicationId): Promise<Application> {
    const { record, metadata } = await this.require(ownerId, applicationId);
    return this.#application(record, metadata);
  }

  async require(
    ownerId: UserId,
    applicationId: ApplicationId,
  ): Promise<{ record: ApplicationRecord; metadata: ApplicationCompatibilityMetadata }> {
    const scope = { owner_id: ownerId, application_id: applicationId };
    const record = await this.#controlPlane.getApplication(scope);
    if (record === null) {
      throw notFound(`Unknown application: ${applicationId}`);
    }
    const stored = await this.#metadata.get(scope);
    if (stored?.deleted === true) {
      throw notFound(`Unknown application: ${applicationId}`);
    }
    return { record, metadata: this.#metadataOrDefault(record, stored) };
  }

  async requireWritable(
    ownerId: UserId,
    applicationId: ApplicationId,
  ): Promise<{
    record: ApplicationRecord;
    metadata: ApplicationCompatibilityMetadata;
  }> {
    const application = await this.require(ownerId, applicationId);
    if (application.metadata.importedFromAppId !== null) {
      throw conflict('Imported applications are read-only.');
    }
    return application;
  }

  async update(
    context: MutationContext,
    applicationId: ApplicationId,
    input: unknown,
  ): Promise<MutationResponseRecord & { value: Application }> {
    const parsed = ApplicationUpdateRequestSchema.parse(input);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'update_application',
      parsed,
      async () => {
        const { record, metadata } = await this.requireWritable(
          context.ownerId,
          applicationId,
        );
        const name = parsed.name?.trim() ?? record.name;
        if (name.length === 0 || name.length > 256) {
          throw unprocessable('Application name must contain 1-256 characters.');
        }
        if (parsed.name !== null && name.toLowerCase() !== record.name.toLowerCase()) {
          await this.#assertUniqueName(context.ownerId, name, applicationId);
        }
        const nextMetadata: ApplicationCompatibilityMetadata = {
          businessContext: parsed.business_context ?? metadata.businessContext,
          projectPath: parsed.project_path ?? metadata.projectPath,
          deleted: false,
          importedFromAppId: metadata.importedFromAppId,
          importedFromAppName: metadata.importedFromAppName,
          importedAt: metadata.importedAt,
          lastImportedAt: metadata.lastImportedAt,
        };
        if (nextMetadata.projectPath.length > 2048) {
          throw unprocessable('Project path must not exceed 2048 characters.');
        }
        const next: ApplicationRecord = {
          ...record,
          name,
          description: nextMetadata.businessContext.description,
          revision: record.revision + 1,
          updated_at: this.#clock.now().toISOString(),
        };
        const saved = await this.#controlPlane.updateApplication(next, record.revision);
        await this.#metadata.put(scope, nextMetadata);
        return { status: 200, value: this.#application(saved, nextMetadata) };
      },
    );
  }

  async delete(
    context: MutationContext,
    applicationId: ApplicationId,
  ): Promise<MutationResponseRecord> {
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'delete_application',
      { applicationId },
      async () => {
        const { metadata } = await this.require(context.ownerId, applicationId);
        await this.#metadata.put(scope, { ...metadata, deleted: true });
        return {
          status: 200,
          value: {
            success: true,
            message: `Application '${applicationId}' deleted successfully`,
          },
        };
      },
    );
  }

  #accountScope(ownerId: UserId): ControlPlaneScope {
    return { owner_id: ownerId, application_id: ACCOUNT_SCOPE_APPLICATION_ID };
  }

  async #assertUniqueName(
    ownerId: UserId,
    name: string,
    exceptApplicationId?: ApplicationId,
  ): Promise<void> {
    const records = await this.#controlPlane.listApplications(ownerId);
    for (const record of records) {
      if (record.application_id === exceptApplicationId) {
        continue;
      }
      const metadata = await this.#metadata.get(record);
      if (metadata?.deleted !== true && record.name.toLowerCase() === name.toLowerCase()) {
        throw conflict(`An application named '${name}' already exists.`);
      }
    }
  }

  #metadataOrDefault(
    record: ApplicationRecord,
    metadata: ApplicationCompatibilityMetadata | null,
  ): ApplicationCompatibilityMetadata {
    return (
      metadata ?? {
        businessContext: {
          description: record.description ?? '',
          regulatory_frameworks: [],
          data_sensitivity: 'unknown',
          cia_priority: ['confidentiality', 'integrity', 'availability'],
        },
        projectPath: '',
        deleted: false,
        importedFromAppId: null,
        importedFromAppName: null,
        importedAt: null,
        lastImportedAt: null,
      }
    );
  }

  #application(
    record: ApplicationRecord,
    metadata: ApplicationCompatibilityMetadata,
  ): Application {
    return {
      id: record.application_id,
      name: record.name,
      slug: slugify(record.name),
      project_path: metadata.projectPath,
      business_context: metadata.businessContext,
      created_at: record.created_at,
      updated_at: record.updated_at,
      run_dir_name: record.application_id,
      imported: metadata.importedFromAppId !== null,
      imported_from: metadata.importedFromAppName,
    };
  }

  #summary(
    record: ApplicationRecord,
    metadata: ApplicationCompatibilityMetadata,
    versions: VersionSummary[],
  ): ApplicationSummary {
    return {
      id: record.application_id,
      name: record.name,
      description: metadata.businessContext.description,
      version_count: versions.length,
      last_run_date: versions[0]?.run_date ?? '',
      business_context: metadata.businessContext,
      imported: metadata.importedFromAppId !== null,
      imported_from: metadata.importedFromAppName,
    };
  }
}

export interface VersionServiceOptions {
  applications: ApplicationService;
  versions: VersionStore;
  idempotency: IdempotencyExecutor;
  clock: Clock;
}

export class VersionService {
  readonly #applications: ApplicationService;
  readonly #versions: VersionStore;
  readonly #idempotency: IdempotencyExecutor;
  readonly #clock: Clock;

  constructor(options: VersionServiceOptions) {
    this.#applications = options.applications;
    this.#versions = options.versions;
    this.#idempotency = options.idempotency;
    this.#clock = options.clock;
  }

  async list(ownerId: UserId, applicationId: ApplicationId): Promise<{ versions: VersionSummary[] }> {
    const { record } = await this.#applications.require(ownerId, applicationId);
    const versions = await this.#versions.list({
      owner_id: ownerId,
      application_id: applicationId,
    });
    return {
      versions: versions.map(version => ({
        ...version,
        display_name: version.display_name || runDisplayName(record.name, version.run_date),
      })),
    };
  }

  async data(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string,
  ): Promise<Record<string, unknown>> {
    await this.#applications.require(ownerId, applicationId);
    const scope = { owner_id: ownerId, application_id: applicationId };
    const data = await this.#versions.getData(scope, versionId);
    if (data === null) {
      throw notFound(
        `Version '${versionId}' not found for application '${applicationId}'.`,
      );
    }
    return data;
  }

  async remove(
    context: MutationContext,
    applicationId: ApplicationId,
    versionId: string,
  ): Promise<MutationResponseRecord> {
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'delete_version',
      { versionId },
      async () => {
        await this.#applications.require(context.ownerId, applicationId);
        if (!(await this.#versions.delete(scope, versionId))) {
          throw notFound(
            `Version '${versionId}' not found for application '${applicationId}'.`,
          );
        }
        return {
          status: 200,
          value: { success: true, message: `Version '${versionId}' deleted` },
        };
      },
    );
  }

  async report(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string | null,
    includeScannerContext: boolean,
  ): Promise<ReportPayload> {
    await this.#applications.require(ownerId, applicationId);
    const report = await this.#versions.getReport(
      { owner_id: ownerId, application_id: applicationId },
      versionId,
      includeScannerContext,
    );
    if (report === null) {
      throw notFound(`No completed report is available for application '${applicationId}'.`);
    }
    return report;
  }

  async overrides(
    ownerId: UserId,
    applicationId: ApplicationId,
    versionId: string,
  ): Promise<{ overrides: Record<string, Record<string, unknown>> }> {
    await this.#applications.require(ownerId, applicationId);
    return {
      overrides: await this.#versions.getMitigationOverrides(
        { owner_id: ownerId, application_id: applicationId },
        versionId,
      ),
    };
  }

  async setOverride(
    context: MutationContext,
    applicationId: ApplicationId,
    versionId: string,
    key: string,
    input: unknown,
  ): Promise<MutationResponseRecord> {
    if (key.length === 0 || key.length > 2048) {
      throw unprocessable('Mitigation key must contain 1-2048 characters.');
    }
    const parsed = MitigationOverrideRequestSchema.parse(input);
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'set_mitigation_override',
      { versionId, key, parsed },
      async () => {
        await this.#applications.require(context.ownerId, applicationId);
        const value = MitigationOverrideSchema.parse({
          status: parsed.status,
          comment: parsed.comment.trim(),
          updated_at: this.#clock.now().toISOString(),
        }) as unknown as Record<string, unknown>;
        const stored = await this.#versions.setMitigationOverride(
          scope,
          versionId,
          key,
          value,
        );
        if (stored === null) {
          throw notFound(`Version '${versionId}' not found for application.`);
        }
        return { status: 200, value: { override: stored } };
      },
    );
  }

  async clearOverride(
    context: MutationContext,
    applicationId: ApplicationId,
    versionId: string,
    key: string,
  ): Promise<MutationResponseRecord> {
    const scope = { owner_id: context.ownerId, application_id: applicationId };
    return this.#idempotency.execute(
      scope,
      context.idempotencyKey,
      'clear_mitigation_override',
      { versionId, key },
      async () => {
        await this.#applications.require(context.ownerId, applicationId);
        await this.#versions.setMitigationOverride(scope, versionId, key, null);
        return { status: 200, value: { success: true } };
      },
    );
  }
}

export function applicationId(value: unknown): ApplicationId {
  return asApplicationId(value);
}
