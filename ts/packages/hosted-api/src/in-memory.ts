import type {
  ApplicationId,
  ArtifactId,
  BedrockModelsResponse,
  ConfigTestRequest,
  ConfigTestResponse,
  HostedProgressEvent,
  RunId,
  UploadId,
  UserId,
  VersionSummary,
} from '@threatforest/types';
import {
  TTP_FRAMEWORK_CATALOG,
  TTP_FRAMEWORK_IDS,
} from '@threatforest/types';
import type { ControlPlaneScope } from '@threatforest/control-plane';
import type {
  ApplicationCompatibilityMetadata,
  ApplicationMetadataStore,
  ArtifactResolver,
  CompletedPart,
  ConnectionAdapter,
  DiscoveryService,
  MultipartCompletionRecord,
  MultipartInitiateRequest,
  MultipartInspection,
  MultipartPartRequest,
  MultipartPartSignature,
  MultipartStorageAdapter,
  SignedMultipartPart,
  MutationResponseRecord,
  MutationResponseStore,
  NormalizationOrchestrator,
  NormalizationStatus,
  ReportPayload,
  RunDispatch,
  RunIndex,
  RunIndexEntry,
  RunOrchestrator,
  UploadSessionRecord,
  UploadSessionStore,
  VersionStore,
  WebSocketConnection,
} from './contracts.js';
import { copy } from './runtime.js';

function scopeKey(scope: ControlPlaneScope): string {
  return `${scope.owner_id}\0${scope.application_id}`;
}

function itemKey(scope: ControlPlaneScope, id: string): string {
  return `${scopeKey(scope)}\0${id}`;
}

export class InMemoryApplicationMetadataStore implements ApplicationMetadataStore {
  readonly #items = new Map<string, ApplicationCompatibilityMetadata>();

  async get(scope: ControlPlaneScope): Promise<ApplicationCompatibilityMetadata | null> {
    const value = this.#items.get(scopeKey(scope));
    return value === undefined ? null : copy(value);
  }

  async put(
    scope: ControlPlaneScope,
    metadata: ApplicationCompatibilityMetadata,
  ): Promise<ApplicationCompatibilityMetadata> {
    this.#items.set(scopeKey(scope), copy(metadata));
    return copy(metadata);
  }
}

interface VersionRecord {
  summary: VersionSummary;
  data: Record<string, unknown>;
  overrides: Record<string, Record<string, unknown>>;
  report: ReportPayload | null;
}

export class InMemoryVersionStore implements VersionStore {
  readonly #versions = new Map<string, Map<string, VersionRecord>>();
  readonly #applicationReports = new Map<string, ReportPayload>();

  seed(
    scope: ControlPlaneScope,
    summary: VersionSummary,
    data: Record<string, unknown>,
    report: ReportPayload | null = null,
  ): void {
    const versions = this.#versions.get(scopeKey(scope)) ?? new Map<string, VersionRecord>();
    versions.set(summary.id, {
      summary: copy(summary),
      data: copy(data),
      overrides: {},
      report: report === null ? null : copy(report),
    });
    this.#versions.set(scopeKey(scope), versions);
  }

  seedApplicationReport(scope: ControlPlaneScope, report: ReportPayload): void {
    this.#applicationReports.set(scopeKey(scope), copy(report));
  }

  async list(scope: ControlPlaneScope): Promise<VersionSummary[]> {
    return [...(this.#versions.get(scopeKey(scope))?.values() ?? [])]
      .map((record) => copy(record.summary))
      .sort((left, right) => right.run_date.localeCompare(left.run_date));
  }

  async getData(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, unknown> | null> {
    const record = this.#resolve(scope, versionId);
    return record === null ? null : copy(record.data);
  }

  async delete(scope: ControlPlaneScope, versionId: string): Promise<boolean> {
    return this.#versions.get(scopeKey(scope))?.delete(versionId) ?? false;
  }

  async getReport(
    scope: ControlPlaneScope,
    versionId: string | null,
    _includeScannerContext: boolean,
  ): Promise<ReportPayload | null> {
    if (versionId === null) {
      const report = this.#applicationReports.get(scopeKey(scope));
      return report === undefined ? null : copy(report);
    }
    const record = this.#resolve(scope, versionId);
    return record?.report === null || record === null ? null : copy(record.report);
  }

  async getMitigationOverrides(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, Record<string, unknown>>> {
    return copy(this.#resolve(scope, versionId)?.overrides ?? {});
  }

  async setMitigationOverride(
    scope: ControlPlaneScope,
    versionId: string,
    key: string,
    value: Record<string, unknown> | null,
  ): Promise<Record<string, unknown> | null> {
    const record = this.#resolve(scope, versionId);
    if (record === null) {
      return null;
    }
    if (value === null) {
      delete record.overrides[key];
      return {};
    }
    record.overrides[key] = copy(value);
    return copy(value);
  }

  #resolve(scope: ControlPlaneScope, versionId: string): VersionRecord | null {
    const versions = this.#versions.get(scopeKey(scope));
    if (versions === undefined) {
      return null;
    }
    if (versionId === 'latest') {
      return [...versions.values()].sort((left, right) =>
        right.summary.run_date.localeCompare(left.summary.run_date),
      )[0] ?? null;
    }
    return versions.get(versionId) ?? null;
  }
}

export class InMemoryRunIndex implements RunIndex {
  readonly #entries = new Map<string, RunIndexEntry>();

  async put(entry: RunIndexEntry): Promise<void> {
    this.#entries.set(`${entry.ownerId}\0${entry.runId}`, copy(entry));
  }

  async locate(ownerId: UserId, runId: RunId): Promise<RunIndexEntry | null> {
    const value = this.#entries.get(`${ownerId}\0${runId}`);
    return value === undefined ? null : copy(value);
  }

  async list(ownerId: UserId): Promise<RunIndexEntry[]> {
    return [...this.#entries.values()]
      .filter((entry) => entry.ownerId === ownerId)
      .map(copy);
  }
}

export class RecordingRunOrchestrator implements RunOrchestrator {
  readonly dispatches: RunDispatch[] = [];
  readonly continuations: Array<{
    scope: ControlPlaneScope;
    runId: RunId;
    traceId: string;
  }> = [];
  readonly controls: Array<{
    scope: ControlPlaneScope;
    runId: RunId;
    action: 'pause' | 'stop';
  }> = [];

  async dispatch(input: RunDispatch): Promise<void> {
    this.dispatches.push(copy(input));
  }

  async continue(
    scope: ControlPlaneScope,
    runId: RunId,
    traceId: string,
  ): Promise<void> {
    this.continuations.push({ scope: copy(scope), runId, traceId });
  }

  async requestControl(
    scope: ControlPlaneScope,
    runId: RunId,
    action: 'pause' | 'stop',
  ): Promise<void> {
    this.controls.push({ scope: copy(scope), runId, action });
  }
}

export class InMemoryNormalizationOrchestrator
  implements NormalizationOrchestrator
{
  readonly #statuses = new Map<string, NormalizationStatus>();
  readonly dispatches: Array<{
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
  }> = [];

  describeSource(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    checksumSha256: string;
  }): { sourceObjectId: string; objectKey: string } {
    const sourceObjectId = `source-${input.checksumSha256}`;
    return {
      sourceObjectId,
      objectKey: [
        'v1',
        'owners',
        input.ownerId,
        'applications',
        input.applicationId,
        'uploads',
        input.uploadId,
        'original',
        sourceObjectId,
      ].join('/'),
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
    const key = itemKey(
      { owner_id: input.ownerId, application_id: input.applicationId },
      input.uploadId,
    );
    if (!this.#statuses.has(key)) {
      this.#statuses.set(key, {
        status: 'pending',
        normalizedObjectIds: [],
        authoritativeThreatObjectIds: [],
        failureCode: null,
      });
    }
  }

  async markUploaded(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    sourceObjectId: string;
    sourceSha256: string;
    parts: CompletedPart[];
  }): Promise<void> {
    this.#statuses.set(
      itemKey(
        { owner_id: input.ownerId, application_id: input.applicationId },
        input.uploadId,
      ),
      {
        status: 'uploaded',
        normalizedObjectIds: [],
        authoritativeThreatObjectIds: [],
        failureCode: null,
      },
    );
  }

  async dispatch(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
  }): Promise<void> {
    this.dispatches.push(copy(input));
  }

  async status(
    scope: ControlPlaneScope,
    uploadId: UploadId,
  ): Promise<NormalizationStatus | null> {
    return copy(this.#statuses.get(itemKey(scope, uploadId)) ?? null);
  }

  setStatus(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    status: NormalizationStatus,
  ): void {
    this.#statuses.set(itemKey(scope, uploadId), copy(status));
  }
}

export class InMemoryArtifactResolver implements ArtifactResolver {
  readonly #ready = new Map<string, Set<ArtifactId>>();

  setReady(scope: ControlPlaneScope, artifactIds: ArtifactId[]): void {
    this.#ready.set(scopeKey(scope), new Set(artifactIds));
  }

  async listReadySourceArtifacts(scope: ControlPlaneScope): Promise<ArtifactId[]> {
    return [...(this.#ready.get(scopeKey(scope)) ?? [])];
  }

  async assertReadable(scope: ControlPlaneScope, artifactIds: ArtifactId[]): Promise<void> {
    const ready = this.#ready.get(scopeKey(scope)) ?? new Set<ArtifactId>();
    const inaccessible = artifactIds.find((artifactId) => !ready.has(artifactId));
    if (inaccessible !== undefined) {
      throw new Error(`Artifact ${inaccessible} is not readable in this application scope.`);
    }
  }
}

export class InMemoryMutationResponseStore implements MutationResponseStore {
  readonly #items = new Map<string, MutationResponseRecord>();

  async get(
    scope: ControlPlaneScope,
    idempotencyKey: string,
  ): Promise<MutationResponseRecord | null> {
    const value = this.#items.get(itemKey(scope, idempotencyKey));
    return value === undefined ? null : copy(value);
  }

  async put(
    scope: ControlPlaneScope,
    idempotencyKey: string,
    response: MutationResponseRecord,
  ): Promise<void> {
    this.#items.set(itemKey(scope, idempotencyKey), copy(response));
  }
}

export class InMemoryUploadSessionStore implements UploadSessionStore {
  readonly #items = new Map<string, UploadSessionRecord>();

  async get(
    scope: ControlPlaneScope,
    uploadId: UploadId,
  ): Promise<UploadSessionRecord | null> {
    const value = this.#items.get(itemKey(scope, uploadId));
    return value === undefined ? null : copy(value);
  }

  async put(scope: ControlPlaneScope, session: UploadSessionRecord): Promise<void> {
    this.#items.set(itemKey(scope, session.manifest.upload_id), copy(session));
  }

  async recordSignedPart(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<UploadSessionRecord | null> {
    const key = itemKey(scope, uploadId);
    const existing = this.#items.get(key);
    if (
      existing === undefined ||
      existing.completion !== undefined ||
      !['pending', 'uploading'].includes(existing.manifest.status)
    ) {
      return null;
    }
    const updated = copy(existing);
    updated.signedParts[String(part.partNumber)] = {
      sizeBytes: part.sizeBytes,
      checksumSha256: part.checksumSha256,
      signedAt,
    };
    updated.manifest = {
      ...updated.manifest,
      status: 'uploading',
      updated_at: signedAt,
      parts: [
        ...updated.manifest.parts.filter(
          (candidate) => candidate.part_number !== part.partNumber,
        ),
        {
          part_number: part.partNumber,
          size_bytes: part.sizeBytes,
          etag: null,
          checksum_sha256: part.checksumSha256,
        },
      ].sort((left, right) => left.part_number - right.part_number),
    };
    this.#items.set(key, updated);
    return copy(updated);
  }

  async claimCompletion(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<UploadSessionRecord | null> {
    const key = itemKey(scope, uploadId);
    const existing = this.#items.get(key);
    if (existing === undefined) {
      return null;
    }
    if (
      existing.completion !== undefined &&
      existing.completion.claimId !== completion.claimId &&
      existing.completion.claimExpiresAt > claimedAt
    ) {
      return null;
    }
    const claimed = copy(existing);
    claimed.completion = copy(completion);
    claimed.manifest.updated_at = claimedAt;
    this.#items.set(key, claimed);
    return copy(claimed);
  }
}

interface MultipartRecord {
  request: MultipartInitiateRequest;
  parts: CompletedPart[];
  completed: boolean;
  aborted: boolean;
}

export class InMemoryMultipartStorageAdapter implements MultipartStorageAdapter {
  readonly #uploads = new Map<string, MultipartRecord>();
  readonly initiated: MultipartInitiateRequest[] = [];
  completeCalls = 0;
  completionAttempts = 0;
  failNextCompletion = false;

  async initiate(
    request: MultipartInitiateRequest,
  ): Promise<{ storageUploadId: string }> {
    const storageUploadId = `storage-${this.#uploads.size + 1}`;
    this.#uploads.set(storageUploadId, {
      request: copy(request),
      parts: [],
      completed: false,
      aborted: false,
    });
    this.initiated.push(copy(request));
    return { storageUploadId };
  }

  async presignPart(request: MultipartPartRequest): Promise<MultipartPartSignature> {
    if (!this.#uploads.has(request.storageUploadId)) {
      throw new Error('unknown storage upload');
    }
    return {
      url: `https://uploads.example/${request.storageUploadId}/${request.partNumber}`,
      expiresAt: new Date(Date.now() + request.expiresInSeconds * 1000).toISOString(),
      headers: {
        'x-amz-checksum-sha256': Buffer.from(
          request.partChecksumSha256,
          'hex',
        ).toString('base64'),
      },
    };
  }

  recordPart(storageUploadId: string, part: CompletedPart): void {
    const upload = this.#uploads.get(storageUploadId);
    if (upload === undefined) {
      throw new Error('unknown storage upload');
    }
    upload.parts = [
      ...upload.parts.filter((candidate) => candidate.partNumber !== part.partNumber),
      copy(part),
    ].sort((left, right) => left.partNumber - right.partNumber);
  }

  async inspect(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<MultipartInspection> {
    const upload = this.#uploads.get(request.storageUploadId);
    if (upload === undefined) {
      throw new Error('unknown storage upload');
    }
    return {
      ...copy(upload.request),
      storageUploadId: request.storageUploadId,
      parts: copy(upload.parts),
    };
  }

  async complete(
    request: MultipartInitiateRequest & {
      storageUploadId: string;
      parts: CompletedPart[];
    },
  ): Promise<{ versionId: string | null }> {
    const upload = this.#uploads.get(request.storageUploadId);
    if (upload === undefined) {
      throw new Error('unknown storage upload');
    }
    this.completionAttempts += 1;
    if (this.failNextCompletion) {
      this.failNextCompletion = false;
      throw new Error('simulated storage completion failure');
    }
    upload.completed = true;
    this.completeCalls += 1;
    return { versionId: 'version-1' };
  }

  async inspectCompleted(
    request: MultipartInitiateRequest & { parts: CompletedPart[] },
  ): Promise<{ versionId: string | null } | null> {
    const completed = [...this.#uploads.values()].find(
      (upload) =>
        upload.request.bucket === request.bucket &&
        upload.request.key === request.key &&
        upload.completed,
    );
    return completed === undefined ? null : { versionId: 'version-1' };
  }

  async abort(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<void> {
    const upload = this.#uploads.get(request.storageUploadId);
    if (upload !== undefined) {
      upload.aborted = true;
    }
  }
}

export class InMemoryConnectionAdapter implements ConnectionAdapter {
  readonly #connections = new Map<string, WebSocketConnection>();
  readonly messages = new Map<string, Array<Record<string, unknown>>>();

  async get(connectionId: string): Promise<WebSocketConnection | null> {
    const value = this.#connections.get(connectionId);
    return value === undefined ? null : copy(value);
  }

  async put(connection: WebSocketConnection): Promise<void> {
    this.#connections.set(connection.connectionId, copy(connection));
  }

  async activate(
    connectionId: string,
    expectedCursor: number,
  ): Promise<WebSocketConnection> {
    const connection = this.#connections.get(connectionId);
    if (connection === undefined || connection.cursor !== expectedCursor) {
      throw new Error('WebSocket connection activation conflict');
    }
    connection.phase = 'live';
    return copy(connection);
  }

  async listForRun(
    scope: { owner_id: UserId; application_id: ApplicationId },
    runId: RunId,
  ): Promise<WebSocketConnection[]> {
    return [...this.#connections.values()]
      .filter(
        (connection) =>
          connection.ownerId === scope.owner_id &&
          connection.applicationId === scope.application_id &&
          connection.runId === runId,
      )
      .map(copy);
  }

  async advance(
    connection: WebSocketConnection,
    event: HostedProgressEvent,
  ): Promise<WebSocketConnection | null> {
    const current = this.#connections.get(connection.connectionId);
    if (
      current === undefined ||
      current.phase !== 'live' ||
      current.cursor !== connection.cursor
    ) {
      return current === undefined ? null : copy(current);
    }
    current.cursor = event.sequence;
    current.seenEventIds.push(event.event_id);
    if (current.seenEventIds.length > 256) {
      current.seenEventIds.splice(0, current.seenEventIds.length - 256);
    }
    return copy(current);
  }

  async delete(connectionId: string): Promise<void> {
    this.#connections.delete(connectionId);
  }

  async post(connectionId: string, value: Record<string, unknown>): Promise<void> {
    const messages = this.messages.get(connectionId) ?? [];
    messages.push(copy(value));
    this.messages.set(connectionId, messages);
  }
}

export class StaticDiscoveryService implements DiscoveryService {
  readonly #providers: string[];
  readonly #frameworks: Record<string, { name: string; description: string }>;
  readonly #models: BedrockModelsResponse;

  constructor(options: {
    providers?: string[];
    frameworks?: Record<string, { name: string; description: string }>;
    models?: BedrockModelsResponse;
  } = {}) {
    this.#providers = options.providers ?? [
      'AWS Bedrock',
      'Anthropic',
      'OpenAI',
      'Google Gemini',
    ];
    this.#frameworks =
      options.frameworks ??
      Object.fromEntries(
        TTP_FRAMEWORK_IDS.map((id) => [id, { ...TTP_FRAMEWORK_CATALOG[id] }]),
      );
    this.#models = options.models ?? {
      models: [],
      source: 'fallback',
      warning: 'No live discovery adapter is configured.',
      region: 'eu-west-2',
    };
  }

  async providers(): Promise<string[]> {
    return copy(this.#providers);
  }

  async frameworks(): Promise<
    Record<string, { name: string; description: string }>
  > {
    return copy(this.#frameworks);
  }

  async models(): Promise<BedrockModelsResponse> {
    return copy(this.#models);
  }

  async testConfiguration(input: ConfigTestRequest): Promise<ConfigTestResponse> {
    return {
      success: input.provider.length > 0 && input.model_id.length > 0,
      message: 'Configuration shape is valid; invocation is checked when a run starts.',
    };
  }
}

export function runIndexEntry(
  ownerId: UserId,
  applicationId: ApplicationId,
  runId: RunId,
): RunIndexEntry {
  return { ownerId, applicationId, runId };
}
