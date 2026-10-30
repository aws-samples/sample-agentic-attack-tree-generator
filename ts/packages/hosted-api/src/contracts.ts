import type {
  Application,
  ApplicationId,
  ApplicationSummary,
  ArtifactId,
  BedrockModelsResponse,
  BusinessContext,
  ConfigTestRequest,
  ConfigTestResponse,
  HostedProgressEvent,
  RunId,
  RunState,
  UploadId,
  UploadManifest,
  UserId,
  VersionSummary,
} from '@threatforest/types';
import type { ControlPlaneScope, RunRecord } from '@threatforest/control-plane';

export interface AuthenticatedActor {
  ownerId: UserId;
}

export interface MutationContext extends AuthenticatedActor {
  idempotencyKey: string;
}

export interface ApplicationCompatibilityMetadata {
  businessContext: BusinessContext;
  projectPath: string;
  deleted: boolean;
  importedFromAppId: string | null;
  importedFromAppName: string | null;
  importedAt: string | null;
  lastImportedAt: string | null;
}

export interface ApplicationMetadataStore {
  get(scope: ControlPlaneScope): Promise<ApplicationCompatibilityMetadata | null>;
  put(
    scope: ControlPlaneScope,
    metadata: ApplicationCompatibilityMetadata,
  ): Promise<ApplicationCompatibilityMetadata>;
}

export interface ApplicationView {
  application: Application;
  summary: ApplicationSummary;
}

export interface ReportPayload {
  contentType: string;
  filename: string;
  body?: Uint8Array;
  redirectUrl?: string;
  metadata: Record<string, unknown>;
}

export interface VersionStore {
  list(scope: ControlPlaneScope): Promise<VersionSummary[]>;
  getData(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, unknown> | null>;
  delete(scope: ControlPlaneScope, versionId: string): Promise<boolean>;
  getReport(
    scope: ControlPlaneScope,
    versionId: string | null,
    includeScannerContext: boolean,
  ): Promise<ReportPayload | null>;
  getMitigationOverrides(
    scope: ControlPlaneScope,
    versionId: string,
  ): Promise<Record<string, Record<string, unknown>>>;
  setMitigationOverride(
    scope: ControlPlaneScope,
    versionId: string,
    key: string,
    value: Record<string, unknown> | null,
  ): Promise<Record<string, unknown> | null>;
}

export interface RunIndexEntry {
  ownerId: UserId;
  applicationId: ApplicationId;
  runId: RunId;
}

export interface RunIndex {
  put(entry: RunIndexEntry): Promise<void>;
  locate(ownerId: UserId, runId: RunId): Promise<RunIndexEntry | null>;
  list(ownerId: UserId): Promise<RunIndexEntry[]>;
}

export interface RunDispatch {
  run: RunRecord;
  resumedFromRunId: RunId | null;
}

export interface RunOrchestrator {
  dispatch(input: RunDispatch): Promise<void>;
  continue(scope: ControlPlaneScope, runId: RunId, traceId: string): Promise<void>;
  requestControl(
    scope: ControlPlaneScope,
    runId: RunId,
    action: 'pause' | 'stop',
  ): Promise<void>;
}

export interface ArtifactResolver {
  listReadySourceArtifacts(scope: ControlPlaneScope): Promise<ArtifactId[]>;
  describeSources?(scope: ControlPlaneScope): Promise<Array<{ artifact_id: ArtifactId; filename: string; created_at: string }>>;
  assertReadable(scope: ControlPlaneScope, artifactIds: ArtifactId[]): Promise<void>;
}

export interface DiscoveryService {
  providers(): Promise<string[]>;
  frameworks(): Promise<Record<string, { name: string; description: string }>>;
  models(region?: string, refresh?: boolean): Promise<BedrockModelsResponse>;
  testConfiguration(input: ConfigTestRequest): Promise<ConfigTestResponse>;
}

export interface ProviderCredentialStore {
  configured(ownerId: UserId, provider: string): Promise<boolean>;
  put(ownerId: UserId, provider: string, apiKey: string): Promise<void>;
}

export interface MutationResponseRecord {
  status: number;
  value: unknown;
  headers?: Record<string, string>;
}

export interface MutationResponseStore {
  get(
    scope: ControlPlaneScope,
    idempotencyKey: string,
  ): Promise<MutationResponseRecord | null>;
  put(
    scope: ControlPlaneScope,
    idempotencyKey: string,
    response: MutationResponseRecord,
  ): Promise<void>;
}

export interface UploadSessionRecord {
  manifest: UploadManifest;
  bucket: string;
  key: string;
  sourceObjectId: string;
  kmsKeyId: string;
  checksumSha256: string;
  storageUploadId: string;
  partSizeBytes: number;
  partCount: number;
  signedParts: Record<
    string,
    { sizeBytes: number; checksumSha256: string; signedAt: string }
  >;
  completion?: MultipartCompletionRecord;
}

export interface UploadSessionStore {
  get(scope: ControlPlaneScope, uploadId: UploadId): Promise<UploadSessionRecord | null>;
  put(scope: ControlPlaneScope, session: UploadSessionRecord): Promise<void>;
  recordSignedPart(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<UploadSessionRecord | null>;
  claimCompletion(
    scope: ControlPlaneScope,
    uploadId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<UploadSessionRecord | null>;
}

export interface NormalizationStatus {
  status:
    | 'pending'
    | 'uploading'
    | 'uploaded'
    | 'normalizing'
    | 'ready'
    | 'failed'
    | 'cancelled';
  normalizedObjectIds: string[];
  authoritativeThreatObjectIds: string[];
  failureCode: string | null;
}

export interface NormalizationOrchestrator {
  describeSource(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    checksumSha256: string;
  }): { sourceObjectId: string; objectKey: string };
  createPending(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    filename: string;
    contentType: string;
    sizeBytes: number;
  }): Promise<void>;
  markUploaded(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
    sourceObjectId: string;
    sourceSha256: string;
    parts: CompletedPart[];
  }): Promise<void>;
  dispatch(input: {
    ownerId: UserId;
    applicationId: ApplicationId;
    uploadId: UploadId;
  }): Promise<void>;
  status(
    scope: ControlPlaneScope,
    uploadId: UploadId,
  ): Promise<NormalizationStatus | null>;
}

export interface MultipartInitiateRequest {
  bucket: string;
  key: string;
  contentType: string;
  sizeBytes: number;
  checksumSha256: string;
  kmsKeyId: string;
  metadata: Record<string, string>;
}

export interface MultipartPartRequest extends MultipartInitiateRequest {
  storageUploadId: string;
  partNumber: number;
  partSizeBytes: number;
  partChecksumSha256: string;
  expiresInSeconds: number;
}

export interface MultipartPartSignature {
  url: string;
  expiresAt: string;
  headers: Record<string, string>;
}

export interface CompletedPart {
  partNumber: number;
  sizeBytes: number;
  etag: string;
  checksumSha256: string;
}

export interface SignedMultipartPart {
  partNumber: number;
  sizeBytes: number;
  checksumSha256: string;
}

export interface MultipartCompletionRecord {
  state: 'completing' | 'completed';
  parts: CompletedPart[];
  startedAt: string;
  completedAt: string | null;
  storageVersionId: string | null;
  claimId: string;
  claimExpiresAt: string;
}

export interface MultipartInspection extends MultipartInitiateRequest {
  storageUploadId: string;
  parts: CompletedPart[];
}

export interface CompletedMultipartObject {
  versionId: string | null;
}

export interface MultipartStorageAdapter {
  initiate(request: MultipartInitiateRequest): Promise<{ storageUploadId: string }>;
  presignPart(request: MultipartPartRequest): Promise<MultipartPartSignature>;
  inspect(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<MultipartInspection>;
  complete(
    request: MultipartInitiateRequest & {
      storageUploadId: string;
      parts: CompletedPart[];
    },
  ): Promise<{ versionId: string | null }>;
  inspectCompleted(
    request: MultipartInitiateRequest & { parts: CompletedPart[] },
  ): Promise<CompletedMultipartObject | null>;
  abort(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<void>;
}

export interface WebSocketConnection {
  connectionId: string;
  ownerId: UserId;
  applicationId: ApplicationId;
  runId: RunId;
  phase: 'replay_pending' | 'live';
  cursor: number;
  seenEventIds: string[];
  ticketId: string;
  connectedAt: string;
  expiresAt: string;
}

export interface ConnectionAdapter {
  get(connectionId: string): Promise<WebSocketConnection | null>;
  put(connection: WebSocketConnection): Promise<void>;
  activate(
    connectionId: string,
    expectedCursor: number,
  ): Promise<WebSocketConnection>;
  listForRun(
    scope: ControlPlaneScope,
    runId: RunId,
  ): Promise<WebSocketConnection[]>;
  advance(
    connection: WebSocketConnection,
    event: HostedProgressEvent,
  ): Promise<WebSocketConnection | null>;
  delete(connectionId: string): Promise<void>;
  post(connectionId: string, value: Record<string, unknown>): Promise<void>;
}

export interface EventAdapter {
  list(
    scope: ControlPlaneScope,
    runId: RunId,
    afterSequence: number,
  ): Promise<HostedProgressEvent[]>;
}

export interface HostedRunView {
  state: RunState;
  applicationId: ApplicationId;
}

export interface IdFactory {
  applicationId(): ApplicationId;
  runId(): RunId;
  uploadId(): UploadId;
  artifactId(): ArtifactId;
  traceId(): string;
  ticketId(): string;
}

export interface Clock {
  now(): Date;
}
