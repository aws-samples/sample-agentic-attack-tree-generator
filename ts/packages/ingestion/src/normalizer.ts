import { basename } from 'node:path';
import { SafeZipExtractor } from './archive.js';
import { detectFile } from './detection.js';
import { documentArtifacts, ExtractorRegistry } from './extractors.js';
import { sha256Hex, stableJson } from './hash.js';
import { createObjectId } from './keys.js';
import {
  retryFailedNormalization,
  transitionUploadManifest,
} from './manifest.js';
import { verifyMultipartCompletion } from './multipart.js';
import type {
  ExtractionResult,
  MultipartCompletedPart,
  NormalizationResult,
  NormalizedArtifact,
  SourceDocument,
  UploadManifest,
  UploadObjectLocator,
  UploadScope,
} from './types.js';
import { S3Workspace } from './workspace.js';

export interface UploadNormalizerOptions {
  readonly extractors?: ExtractorRegistry;
  readonly archiveExtractor?: SafeZipExtractor;
  readonly clock?: () => string;
}

export class UnusableEvidenceError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'UnusableEvidenceError';
  }
}

export class UploadNormalizer {
  private readonly extractors: ExtractorRegistry;
  private readonly archiveExtractor: SafeZipExtractor;
  private readonly clock: () => string;

  public constructor(
    private readonly workspace: S3Workspace,
    options: UploadNormalizerOptions = {},
  ) {
    this.extractors = options.extractors ?? new ExtractorRegistry();
    this.archiveExtractor = options.archiveExtractor ?? new SafeZipExtractor();
    this.clock = options.clock ?? (() => new Date().toISOString());
  }

  public async storeOriginal(
    manifest: UploadManifest,
    bytes: Uint8Array,
    options: {
      readonly multipartParts?: readonly MultipartCompletedPart[];
      readonly registeredParts?: UploadManifest['parts'];
    } = {},
  ): Promise<UploadManifest> {
    if (manifest.status === 'uploaded') {
      const actualHash = sha256Hex(bytes);
      if (
        manifest.sourceSha256 === actualHash &&
        manifest.declaredSizeBytes === bytes.byteLength
      ) {
        return manifest;
      }
      throw new Error('Uploaded manifest cannot be replaced with different content');
    }
    let uploading = manifest;
    if (uploading.status === 'pending') {
      uploading = transitionUploadManifest(uploading, 'uploading', { now: this.clock() });
    }
    if (uploading.status !== 'uploading') {
      throw new Error(`Cannot store original content while upload is ${uploading.status}`);
    }
    if (bytes.byteLength !== uploading.declaredSizeBytes) {
      throw new Error(
        `Uploaded object size ${bytes.byteLength} does not match declared size ${uploading.declaredSizeBytes}`,
      );
    }

    let parts = uploading.parts;
    if (options.multipartParts !== undefined) {
      parts = verifyMultipartCompletion(options.multipartParts, {
        declaredSizeBytes: uploading.declaredSizeBytes,
        expectedParts: options.registeredParts ?? uploading.parts,
      }).parts;
    }
    const sourceSha256 = sha256Hex(bytes);
    const sourceObjectId = createObjectId(
      'source',
      stableJson({ uploadId: uploading.uploadId, sha256: sourceSha256 }),
    );
    await this.workspace.write(
      uploadLocator(uploading, 'original', sourceObjectId),
      bytes,
      {
        contentType: uploading.declaredContentType,
        immutable: true,
        expectedSha256: sourceSha256,
        metadata: {
          filename: uploading.filename,
          'artifact-role': 'uploaded-original',
        },
      },
    );
    return transitionUploadManifest(uploading, 'uploaded', {
      now: this.clock(),
      parts,
      sourceObjectId,
      sourceSha256,
    });
  }

  public beginNormalization(manifest: UploadManifest): UploadManifest {
    if (manifest.status === 'normalizing') {
      return manifest;
    }
    if (manifest.status === 'failed') {
      return retryFailedNormalization(manifest, this.clock());
    }
    if (manifest.status !== 'uploaded') {
      throw new Error(`Cannot begin normalization while upload is ${manifest.status}`);
    }
    return transitionUploadManifest(manifest, 'normalizing', {
      now: this.clock(),
      attempt: manifest.attempt + 1,
    });
  }

  public async process(inProgress: UploadManifest): Promise<NormalizationResult> {
    if (
      inProgress.status !== 'normalizing' ||
      inProgress.sourceObjectId === null ||
      inProgress.sourceSha256 === null
    ) {
      throw new Error('Normalization requires a normalizing manifest with a source object');
    }
    const original = await this.workspace.read(
      uploadLocator(inProgress, 'original', inProgress.sourceObjectId),
    );
    if (original === null) {
      throw new Error('Uploaded source object is missing');
    }
    if (
      original.sha256 !== inProgress.sourceSha256 ||
      original.sizeBytes !== inProgress.declaredSizeBytes
    ) {
      throw new Error('Uploaded source object does not match its manifest');
    }

    const topSourceLocator = uploadLocator(
      inProgress,
      'original',
      inProgress.sourceObjectId,
    );
    const topSource: SourceDocument = {
      sourceObjectId: inProgress.sourceObjectId,
      sourceSha256: original.sha256,
      filename: inProgress.filename,
      archivePath: null,
      declaredContentType: inProgress.declaredContentType,
      bytes: original.body,
      workspaceLocator: topSourceLocator,
    };
    const topDetection = detectFile({
      filename: topSource.filename,
      bytes: topSource.bytes,
      declaredContentType: topSource.declaredContentType,
    });

    const results: ExtractionResult[] = [];
    const sources: SourceDocument[] = [];
    if (topDetection.kind === 'archive') {
      const archive = this.archiveExtractor.extract(topSource.bytes);
      results.push({
        status: 'extracted',
        extractor: 'safe-zip-v1',
        detection: topDetection,
        document: null,
        threatInput: {
          authoritative: false,
          confidence: 1,
          reasons: ['Archive containers are evidence sources, not threat inputs'],
        },
        warnings: [
          ...archive.warnings,
          ...(archive.entries.length === 0 ? ['Archive contains no extractable files'] : []),
        ],
        errorCode: archive.entries.length === 0 ? 'EMPTY_ARCHIVE' : null,
        errorMessage: null,
      });
      for (const entry of archive.entries) {
        const sourceObjectId = createObjectId(
          'entry',
          stableJson({ path: entry.path, sha256: entry.sha256 }),
        );
        const entryLocator = uploadLocator(inProgress, 'original', sourceObjectId);
        await this.workspace.write(
          entryLocator,
          entry.bytes,
          {
            contentType: 'application/octet-stream',
            immutable: true,
            expectedSha256: entry.sha256,
            metadata: {
              filename: basename(entry.path),
              'archive-path': entry.path,
              'parent-object-id': topSource.sourceObjectId,
              'artifact-role': 'archive-entry-original',
            },
          },
        );
        sources.push({
          sourceObjectId,
          sourceSha256: entry.sha256,
          filename: basename(entry.path),
          archivePath: entry.path,
          declaredContentType: null,
          bytes: entry.bytes,
          workspaceLocator: entryLocator,
        });
      }
    } else {
      sources.push(topSource);
    }

    const artifacts: NormalizedArtifact[] = [];
    const authoritativeThreatObjectIds: string[] = [];
    for (const source of sources) {
      const result = await this.extractors.extract(source);
      results.push(result);
      if (result.document === null || !result.document.text.trim() || result.status !== 'extracted') {
        continue;
      }
      const written = await this.writeNormalizedDocument(inProgress, source, result);
      artifacts.push(...written);
      if (result.threatInput.authoritative) {
        const markdown = written.find((artifact) => artifact.format === 'markdown');
        if (markdown !== undefined) {
          authoritativeThreatObjectIds.push(markdown.objectId);
        }
      }
    }

    await this.writeDiagnostics(inProgress, results);
    // Empty/binary archive members may be incidental (e.g. .gitkeep, compiled
    // assets). A supported document that failed extraction must not disappear.
    const unusable = results.find((result) =>
      result.detection.kind !== 'archive' &&
      result.detection.kind !== 'empty' &&
      result.detection.kind !== 'binary' &&
      (result.status !== 'extracted' || !result.document?.text.trim()),
    );
    if (unusable !== undefined) {
      throw new UnusableEvidenceError(
        unusable.errorCode ?? 'UNUSABLE_EVIDENCE',
        'A source document could not be extracted reliably. Supply a readable text version and upload again.',
      );
    }
    if (artifacts.length === 0) {
      throw new UnusableEvidenceError(
        'NO_USABLE_EVIDENCE',
        'No usable source text was extracted. Supply a readable document or source archive.',
      );
    }
    const normalizedObjectIds = [
      ...new Set(artifacts.map((artifact) => artifact.objectId)),
    ].sort();
    const ready = transitionUploadManifest(inProgress, 'ready', {
      now: this.clock(),
      normalizedObjectIds,
      authoritativeThreatObjectIds: [...new Set(authoritativeThreatObjectIds)].sort(),
    });
    return {
      manifest: ready,
      detectionResults: results,
      normalizedArtifacts: artifacts,
      authoritativeThreatObjectIds: ready.authoritativeThreatObjectIds,
    };
  }

  public async normalize(manifest: UploadManifest): Promise<NormalizationResult> {
    return this.process(this.beginNormalization(manifest));
  }

  private async writeNormalizedDocument(
    manifest: UploadManifest,
    source: SourceDocument,
    result: ExtractionResult,
  ): Promise<readonly NormalizedArtifact[]> {
    if (result.document === null) {
      return [];
    }
    const encoded = documentArtifacts(result.document);
    const values = [
      {
        format: 'markdown' as const,
        contentType: 'text/markdown; charset=utf-8',
        bytes: encoded.markdown,
      },
      {
        format: 'text' as const,
        contentType: 'text/plain; charset=utf-8',
        bytes: encoded.text,
      },
      {
        format: 'citations' as const,
        contentType: 'application/json',
        bytes: encoded.citations,
      },
    ];
    const output: NormalizedArtifact[] = [];
    for (const value of values) {
      const contentHash = sha256Hex(value.bytes);
      const objectId = createObjectId(
        value.format,
        stableJson({
          sourceObjectId: source.sourceObjectId,
          sourceSha256: source.sourceSha256,
          format: value.format,
          contentHash,
        }),
      );
      const write = await this.workspace.write(
        uploadLocator(manifest, 'normalized', objectId),
        value.bytes,
        {
          contentType: value.contentType,
          immutable: true,
          expectedSha256: contentHash,
          metadata: {
            'source-object-id': source.sourceObjectId,
            'source-sha256': source.sourceSha256,
            'artifact-format': value.format,
            'input-class': result.threatInput.authoritative
              ? 'authoritative-threat'
              : 'evidence',
          },
        },
      );
      output.push({
        objectId,
        sourceObjectId: source.sourceObjectId,
        format: value.format,
        contentType: value.contentType,
        sizeBytes: write.sizeBytes,
        sha256: write.sha256,
        authoritativeThreatInput: result.threatInput.authoritative,
      });
    }
    return output;
  }

  private async writeDiagnostics(
    manifest: UploadManifest,
    results: readonly ExtractionResult[],
  ): Promise<void> {
    const diagnosticResults = results.map((result) => ({
      status: result.status,
      extractor: result.extractor,
      detection: result.detection,
      threatInput: result.threatInput,
      warnings: result.warnings,
      errorCode: result.errorCode,
      errorMessage: result.errorMessage,
      document:
        result.document === null
          ? null
          : {
              markdownSha256: sha256Hex(result.document.markdown),
              textSha256: sha256Hex(result.document.text),
              citationCount: result.document.citations.length,
            },
    }));
    const body = Buffer.from(
      `${stableJson({
        schemaVersion: 1,
        uploadId: manifest.uploadId,
        results: diagnosticResults,
      })}\n`,
      'utf8',
    );
    const objectId = `normalization-${sha256Hex(body)}`;
    await this.workspace.write(uploadLocator(manifest, 'diagnostic', objectId), body, {
      contentType: 'application/json',
      immutable: true,
      metadata: {
        'artifact-role': 'normalization-diagnostics',
        'source-object-id': manifest.sourceObjectId ?? 'missing',
      },
    });
  }
}

function uploadLocator(
  scope: UploadScope,
  area: UploadObjectLocator['area'],
  objectId: string,
): UploadObjectLocator {
  return {
    scope: 'upload',
    ownerId: scope.ownerId,
    applicationId: scope.applicationId,
    uploadId: scope.uploadId,
    area,
    objectId,
  };
}
