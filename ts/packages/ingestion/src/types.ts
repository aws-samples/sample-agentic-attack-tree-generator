export type UploadStatus =
  | 'pending'
  | 'uploading'
  | 'uploaded'
  | 'normalizing'
  | 'ready'
  | 'failed'
  | 'cancelled';

export interface UploadScope {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly uploadId: string;
}

export interface RunScope {
  readonly ownerId: string;
  readonly applicationId: string;
  readonly runId: string;
}

export type UploadObjectArea = 'manifest' | 'original' | 'normalized' | 'diagnostic';
export type RunObjectArea = 'input' | 'state' | 'checkpoint' | 'output';

export interface UploadObjectLocator extends UploadScope {
  readonly scope: 'upload';
  readonly area: UploadObjectArea;
  readonly objectId: string;
}

export interface RunObjectLocator extends RunScope {
  readonly scope: 'run';
  readonly area: RunObjectArea;
  readonly objectId: string;
}

export type WorkspaceObjectLocator = UploadObjectLocator | RunObjectLocator;

export type WorkspaceListScope =
  | (UploadScope & { readonly scope: 'upload'; readonly area: UploadObjectArea })
  | (RunScope & { readonly scope: 'run'; readonly area: RunObjectArea });

export interface WorkspaceObject {
  readonly locator: WorkspaceObjectLocator;
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly etag?: string;
}

export interface WorkspaceObjectSummary {
  readonly locator: WorkspaceObjectLocator;
  readonly contentType: string;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly etag?: string;
}

export interface WorkspaceWriteResult extends WorkspaceObjectSummary {
  readonly created: boolean;
}

export interface UploadPart {
  readonly partNumber: number;
  readonly sizeBytes: number;
  readonly etag: string;
  readonly checksumSha256: string;
}

export interface UploadManifest {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly ownerId: string;
  readonly applicationId: string;
  readonly uploadId: string;
  readonly filename: string;
  readonly declaredContentType: string;
  readonly declaredSizeBytes: number;
  readonly status: UploadStatus;
  readonly parts: readonly UploadPart[];
  readonly sourceObjectId: string | null;
  readonly sourceSha256: string | null;
  readonly normalizedObjectIds: readonly string[];
  readonly authoritativeThreatObjectIds: readonly string[];
  readonly attempt: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly failureCode: string | null;
  readonly failureReason: string | null;
}

export interface MultipartCompletedPart {
  readonly partNumber: number;
  readonly sizeBytes: number;
  readonly etag: string;
  readonly checksumSha256: string;
}

export type DetectedFileKind =
  | 'empty'
  | 'code'
  | 'text'
  | 'markdown'
  | 'json'
  | 'yaml'
  | 'diagram'
  | 'svg'
  | 'image'
  | 'pdf'
  | 'office'
  | 'archive'
  | 'binary'
  | 'unsupported';

export interface FileDetection {
  readonly kind: DetectedFileKind;
  readonly mediaType: string;
  readonly extension: string | null;
  readonly confidence: number;
  readonly supported: boolean;
  readonly extensionMismatch: boolean;
  readonly reasons: readonly string[];
}

export interface SourceDocument {
  readonly sourceObjectId: string;
  readonly sourceSha256: string;
  readonly filename: string;
  readonly archivePath: string | null;
  readonly declaredContentType: string | null;
  readonly bytes: Uint8Array;
  readonly explicitRole?: 'evidence' | 'threat-input';
  readonly workspaceLocator?: WorkspaceObjectLocator;
}

export interface CitationBoundingBox {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

export interface SourceCitation {
  readonly citationId: string;
  readonly sourceObjectId: string;
  readonly sourceSha256: string;
  readonly sourceName: string;
  readonly archivePath: string | null;
  readonly page: number | null;
  readonly lineStart: number | null;
  readonly lineEnd: number | null;
  readonly boundingBox: CitationBoundingBox | null;
}

export interface NormalizedDocument {
  readonly markdown: string;
  readonly text: string;
  readonly citations: readonly SourceCitation[];
}

export type ExtractionStatus = 'extracted' | 'low_confidence' | 'unsupported' | 'failed';

export interface ThreatInputClassification {
  readonly authoritative: boolean;
  readonly confidence: number;
  readonly reasons: readonly string[];
}

export interface ExtractionResult {
  readonly status: ExtractionStatus;
  readonly extractor: string | null;
  readonly detection: FileDetection;
  readonly document: NormalizedDocument | null;
  readonly threatInput: ThreatInputClassification;
  readonly warnings: readonly string[];
  readonly errorCode: string | null;
  readonly errorMessage: string | null;
}

export interface NormalizedArtifact {
  readonly objectId: string;
  readonly sourceObjectId: string;
  readonly format: 'markdown' | 'text' | 'citations';
  readonly contentType: string;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly authoritativeThreatInput: boolean;
}

export interface NormalizationResult {
  readonly manifest: UploadManifest;
  readonly detectionResults: readonly ExtractionResult[];
  readonly normalizedArtifacts: readonly NormalizedArtifact[];
  readonly authoritativeThreatObjectIds: readonly string[];
}

export interface IngestionJob {
  readonly schemaVersion: 1;
  readonly jobId: string;
  readonly idempotencyKey: string;
  readonly ownerId: string;
  readonly applicationId: string;
  readonly uploadId: string;
  readonly attempt: number;
  readonly enqueuedAt: string;
}

export interface IngestionWorkerResult {
  readonly status: 'completed' | 'duplicate' | 'failed';
  readonly uploadId: string;
  readonly normalizedObjectIds: readonly string[];
  readonly failureCode: string | null;
}
