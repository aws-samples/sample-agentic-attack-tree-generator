import type {
  Application,
  ApplicationId,
  ArtifactId,
  RunId,
  UploadId,
  UserId,
} from '@threatforest/types';
import { DEFAULT_TTP_FRAMEWORK_IDS } from '@threatforest/types';
import { InMemoryControlPlane } from '@threatforest/control-plane';
import {
  ApplicationService,
  VersionService,
} from '../src/application-service.js';
import { IdempotencyExecutor } from '../src/idempotency.js';
import {
  InMemoryApplicationMetadataStore,
  InMemoryArtifactResolver,
  InMemoryMultipartStorageAdapter,
  InMemoryMutationResponseStore,
  InMemoryNormalizationOrchestrator,
  InMemoryRunIndex,
  InMemoryUploadSessionStore,
  InMemoryVersionStore,
  RecordingRunOrchestrator,
  StaticDiscoveryService,
} from '../src/in-memory.js';
import {
  createHttpHandler,
  type ApiGatewayEvent,
  type ApiGatewayResponse,
  type HostedApiServices,
} from '../src/http.js';
import type {
  Clock,
  IdFactory,
  ProviderCredentialStore,
} from '../src/contracts.js';
import { HitlService, RunService } from '../src/run-service.js';
import { SettingsService } from '../src/settings-service.js';
import { UploadService } from '../src/upload-service.js';
import { ReplayTicketService } from '../src/websocket.js';
import { ReportImportService } from '../src/report-import-service.js';
import {
  InMemoryReportImportStore,
  RecordingReportImportDispatcher,
} from '../src/report-import-in-memory.js';

export const OWNER_A = 'user_a' as UserId;
export const OWNER_B = 'user_b' as UserId;
export const ORIGIN_SECRET = 'origin-secret-at-least-32-characters';
export const TICKET_SECRET = 'ticket-secret-at-least-32-characters-long';
export const HASH_A = 'a'.repeat(64);
export const HASH_B = 'b'.repeat(64);

export class MutableClock implements Clock {
  value = new Date('2026-08-19T12:00:00.000Z');

  now(): Date {
    return new Date(this.value);
  }

  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

export class SequentialIds implements IdFactory {
  applicationCounter = 0;
  runCounter = 0;
  uploadCounter = 0;
  artifactCounter = 0;
  ticketCounter = 0;

  applicationId(): ApplicationId {
    this.applicationCounter += 1;
    return `app_${this.applicationCounter}` as ApplicationId;
  }

  runId(): RunId {
    this.runCounter += 1;
    return `run_${this.runCounter}` as RunId;
  }

  uploadId(): UploadId {
    this.uploadCounter += 1;
    return `upload_${this.uploadCounter}` as UploadId;
  }

  artifactId(): ArtifactId {
    this.artifactCounter += 1;
    return `artifact_${this.artifactCounter}` as ArtifactId;
  }

  traceId(): string {
    return `0123456789abcdef${this.runCounter.toString().padStart(16, '0')}`;
  }

  ticketId(): string {
    this.ticketCounter += 1;
    return `ticket_${this.ticketCounter}`;
  }
}

export class InMemoryProviderCredentialStore
  implements ProviderCredentialStore
{
  readonly writes: Array<{ ownerId: UserId; provider: string }> = [];
  readonly #configured = new Set<string>();

  configured(ownerId: UserId, provider: string): Promise<boolean> {
    return Promise.resolve(
      this.#configured.has(`${ownerId}:${provider.toLowerCase()}`),
    );
  }

  put(ownerId: UserId, provider: string, _apiKey: string): Promise<void> {
    this.#configured.add(`${ownerId}:${provider.toLowerCase()}`);
    this.writes.push({ ownerId, provider });
    return Promise.resolve();
  }
}

export interface Fixture {
  controlPlane: InMemoryControlPlane;
  metadata: InMemoryApplicationMetadataStore;
  versionsStore: InMemoryVersionStore;
  runIndex: InMemoryRunIndex;
  orchestrator: RecordingRunOrchestrator;
  artifacts: InMemoryArtifactResolver;
  responses: InMemoryMutationResponseStore;
  uploadSessions: InMemoryUploadSessionStore;
  storage: InMemoryMultipartStorageAdapter;
  normalization: InMemoryNormalizationOrchestrator;
  reportImports: InMemoryReportImportStore;
  reportImportDispatcher: RecordingReportImportDispatcher;
  providerCredentials: InMemoryProviderCredentialStore;
  clock: MutableClock;
  ids: SequentialIds;
  services: HostedApiServices;
  handler(event: ApiGatewayEvent): Promise<ApiGatewayResponse>;
}

export function makeFixture(): Fixture {
  const controlPlane = new InMemoryControlPlane();
  const metadata = new InMemoryApplicationMetadataStore();
  const versionsStore = new InMemoryVersionStore();
  const runIndex = new InMemoryRunIndex();
  const orchestrator = new RecordingRunOrchestrator();
  const artifacts = new InMemoryArtifactResolver();
  const responses = new InMemoryMutationResponseStore();
  const uploadSessions = new InMemoryUploadSessionStore();
  const storage = new InMemoryMultipartStorageAdapter();
  const normalization = new InMemoryNormalizationOrchestrator();
  const reportImports = new InMemoryReportImportStore();
  const reportImportDispatcher = new RecordingReportImportDispatcher();
  const providerCredentials = new InMemoryProviderCredentialStore();
  const clock = new MutableClock();
  const ids = new SequentialIds();
  const idempotency = new IdempotencyExecutor({
    store: controlPlane,
    responses,
    clock,
  });
  const applications = new ApplicationService({
    controlPlane,
    metadata,
    versions: versionsStore,
    idempotency,
    ids,
    clock,
  });
  const settings = new SettingsService({
    controlPlane,
    applications,
    discovery: new StaticDiscoveryService(),
    credentials: providerCredentials,
    idempotency,
    clock,
  });
  const runs = new RunService({
    controlPlane,
    applications,
    settings,
    runIndex,
    orchestrator,
    artifacts,
    idempotency,
    ids,
    clock,
  });
  const hitl = new HitlService({
    controlPlane,
    runs,
    orchestrator,
    idempotency,
    clock,
  });
  const versions = new VersionService({
    applications,
    versions: versionsStore,
    idempotency,
    clock,
  });
  const uploads = new UploadService({
    applications,
    sessions: uploadSessions,
    storage,
    normalization,
    idempotency,
    ids,
    clock,
    bucket: 'threatforest-artifacts',
    kmsKeyId: 'arn:aws:kms:eu-west-2:123456789012:key/test-key',
    defaultPartSizeBytes: 8 * 1024 * 1024,
  });
  const tickets = new ReplayTicketService({
    secret: TICKET_SECRET,
    runs,
    ids,
    clock,
    lifetimeSeconds: 60,
  });
  const imports = new ReportImportService({
    store: reportImports,
    storage,
    dispatcher: reportImportDispatcher,
    idempotency,
    ids,
    clock,
    bucket: 'threatforest-artifacts',
    kmsKeyId: 'arn:aws:kms:eu-west-2:123456789012:key/test-key',
    defaultPartSizeBytes: 8 * 1024 * 1024,
  });
  const services: HostedApiServices = {
    applications,
    versions,
    settings,
    runs,
    observability: {
      list: async (ownerId, runId) => {
        await runs.getRecord(ownerId, runId);
        return {
          run_id: runId,
          entries: [],
          next_token: null,
          source: 'agentcore_cloudwatch' as const,
        };
      },
    },
    hitl,
    uploads,
    imports,
    tickets,
  };
  const handler = createHttpHandler({
    originSecret: ORIGIN_SECRET,
    services,
  });
  return {
    controlPlane,
    metadata,
    versionsStore,
    runIndex,
    orchestrator,
    artifacts,
    responses,
    uploadSessions,
    storage,
    normalization,
    reportImports,
    reportImportDispatcher,
    providerCredentials,
    clock,
    ids,
    services,
    handler,
  };
}

let requestCounter = 0;

export function apiEvent(
  method: string,
  path: string,
  options: {
    owner?: UserId | null;
    origin?: string | null;
    idempotencyKey?: string;
    body?: unknown;
    query?: Record<string, string>;
    headers?: Record<string, string>;
  } = {},
): ApiGatewayEvent {
  requestCounter += 1;
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.origin !== null) {
    headers['x-threatforest-origin-verify'] = options.origin ?? ORIGIN_SECRET;
  }
  if (options.idempotencyKey !== undefined) {
    headers['idempotency-key'] = options.idempotencyKey;
  }
  const owner = options.owner === undefined ? OWNER_A : options.owner;
  return {
    version: '2.0',
    rawPath: path,
    headers,
    queryStringParameters: options.query ?? null,
    body: options.body === undefined ? null : JSON.stringify(options.body),
    requestContext: {
      requestId: `request-${requestCounter}`,
      http: { method, path },
      ...(owner === null
        ? {}
        : { authorizer: { jwt: { claims: { sub: owner } } } }),
    },
  };
}

export function json(response: ApiGatewayResponse): Record<string, unknown> {
  return JSON.parse(response.body) as Record<string, unknown>;
}

export const BUSINESS_CONTEXT = {
  description: 'Processes regulated payment data.',
  regulatory_frameworks: ['PCI DSS'],
  data_sensitivity: 'regulated_financial' as const,
  cia_priority: ['confidentiality', 'integrity', 'availability'] as const,
};

export async function createApplication(
  fixture: Fixture,
  owner: UserId = OWNER_A,
  key = `create-app-${fixture.ids.applicationCounter + 1}`,
): Promise<Application> {
  const response = await fixture.handler(
    apiEvent('POST', '/api/applications', {
      owner,
      idempotencyKey: key,
      body: {
        name: `Payments ${fixture.ids.applicationCounter + 1}`,
        project_path: '/logical/payments',
        business_context: BUSINESS_CONTEXT,
      },
    }),
  );
  if (response.statusCode !== 201) {
    throw new Error(`application creation failed: ${response.body}`);
  }
  return json(response) as unknown as Application;
}

export async function createRun(
  fixture: Fixture,
  application: Application,
  owner: UserId = OWNER_A,
): Promise<RunId> {
  const artifact = 'artifact_source' as ArtifactId;
  fixture.artifacts.setReady(
    { owner_id: owner, application_id: application.id as ApplicationId },
    [artifact],
  );
  const response = await fixture.handler(
    apiEvent('POST', '/api/runs', {
      owner,
      idempotencyKey: `create-run-${fixture.ids.runCounter + 1}`,
      body: {
        app_id: application.id,
        project_path: application.project_path,
        threat_source: 'auto',
        threat_file_path: null,
        frameworks: [...DEFAULT_TTP_FRAMEWORK_IDS],
        resume_run_dir: null,
        skip_nodes: [],
        source_artifact_ids: [artifact],
      },
    }),
  );
  if (response.statusCode !== 202) {
    throw new Error(`run creation failed: ${response.body}`);
  }
  return json(response).run_id as RunId;
}
