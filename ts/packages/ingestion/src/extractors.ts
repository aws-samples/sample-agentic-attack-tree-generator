import { parseDocument } from 'yaml';
import { detectFile, decodeText, languageForExtension } from './detection.js';
import { sha256Hex, stableJson } from './hash.js';
import { classifyThreatInput } from './threat-input.js';
import type {
  CitationBoundingBox,
  ExtractionResult,
  FileDetection,
  NormalizedDocument,
  SourceCitation,
  SourceDocument,
} from './types.js';

export interface OcrLine {
  readonly text: string;
  readonly confidence: number;
  readonly lineNumber: number;
  readonly boundingBox?: CitationBoundingBox;
}

export interface OcrPage {
  readonly pageNumber: number;
  readonly lines: readonly OcrLine[];
}

export interface OcrDocument {
  readonly pages: readonly OcrPage[];
}

export interface OcrAdapter {
  analyze(input: {
    readonly bytes: Uint8Array;
    readonly mediaType: string;
    readonly filename: string;
    readonly workspaceLocator?: SourceDocument['workspaceLocator'];
  }): Promise<OcrDocument>;
}

export interface OfficeDocumentAdapter {
  extract(input: {
    readonly bytes: Uint8Array;
    readonly mediaType: string;
    readonly filename: string;
  }): Promise<OcrDocument>;
}

export interface TextractBlock {
  readonly BlockType?: string;
  readonly Text?: string;
  readonly Confidence?: number;
  readonly Page?: number;
  readonly Geometry?: {
    readonly BoundingBox?: {
      readonly Left?: number;
      readonly Top?: number;
      readonly Width?: number;
      readonly Height?: number;
    };
  };
}

export interface TextractStyleClient {
  detectDocumentText(input: {
    readonly Document: { readonly Bytes: Uint8Array };
  }): Promise<{ readonly Blocks?: readonly TextractBlock[] }>;
}

export class TextractStyleOcrAdapter implements OcrAdapter {
  public constructor(private readonly client: TextractStyleClient) {}

  public async analyze(input: {
    readonly bytes: Uint8Array;
    readonly mediaType: string;
    readonly filename: string;
    readonly workspaceLocator?: SourceDocument['workspaceLocator'];
  }): Promise<OcrDocument> {
    const response = await this.client.detectDocumentText({
      Document: { Bytes: Uint8Array.from(input.bytes) },
    });
    return textractBlocksToOcrDocument(response.Blocks ?? []);
  }
}

export function textractBlocksToOcrDocument(
  blocks: readonly TextractBlock[],
): OcrDocument {
    const byPage = new Map<number, OcrLine[]>();
    for (const block of blocks) {
      if (block.BlockType !== 'LINE' || block.Text === undefined || block.Text.trim().length === 0) {
        continue;
      }
      const page = block.Page ?? 1;
      const lines = byPage.get(page) ?? [];
      const boundingBox = block.Geometry?.BoundingBox;
      lines.push({
        text: block.Text,
        confidence: normalizeOcrConfidence(block.Confidence ?? 0),
        lineNumber: lines.length + 1,
        ...(boundingBox === undefined
          ? {}
          : {
              boundingBox: {
                left: boundingBox.Left ?? 0,
                top: boundingBox.Top ?? 0,
                width: boundingBox.Width ?? 0,
                height: boundingBox.Height ?? 0,
              },
            }),
      });
      byPage.set(page, lines);
    }
    return {
      pages: [...byPage.entries()]
        .sort(([left], [right]) => left - right)
        .map(([pageNumber, lines]) => ({ pageNumber, lines })),
    };
}

export interface DocumentExtractor {
  readonly name: string;
  supports(detection: FileDetection): boolean;
  extract(source: SourceDocument, detection: FileDetection): Promise<ExtractionResult>;
}

export interface ExtractorRegistryOptions {
  readonly ocrAdapter?: OcrAdapter;
  readonly officeAdapter?: OfficeDocumentAdapter;
  readonly minimumOcrConfidence?: number;
  readonly additionalExtractors?: readonly DocumentExtractor[];
}

export class ExtractorRegistry {
  private readonly extractors: readonly DocumentExtractor[];

  public constructor(options: ExtractorRegistryOptions = {}) {
    this.extractors = [
      ...(options.additionalExtractors ?? []),
      new TextDocumentExtractor(),
      new OcrDocumentExtractor(options.ocrAdapter, options.minimumOcrConfidence ?? 0.7),
      new OfficeExtractor(options.officeAdapter, options.minimumOcrConfidence ?? 0.7),
    ];
  }

  public async extract(source: SourceDocument): Promise<ExtractionResult> {
    const detection = detectFile({
      filename: source.filename,
      bytes: source.bytes,
      declaredContentType: source.declaredContentType,
    });
    const threatInput = classifyThreatInput(source, detection);
    const extractor = this.extractors.find((candidate) => candidate.supports(detection));
    if (extractor === undefined) {
      return {
        status: detection.kind === 'empty' ? 'low_confidence' : 'unsupported',
        extractor: null,
        detection,
        document: null,
        threatInput,
        warnings: [
          detection.kind === 'empty'
            ? 'Empty input was preserved but has no evidence to extract'
            : `No extractor is registered for ${detection.kind}`,
        ],
        errorCode: detection.kind === 'empty' ? 'EMPTY_INPUT' : 'UNSUPPORTED_TYPE',
        errorMessage: null,
      };
    }
    try {
      const result = await extractor.extract(source, detection);
      return { ...result, threatInput };
    } catch (error) {
      return {
        status: 'failed',
        extractor: extractor.name,
        detection,
        document: null,
        threatInput,
        warnings: [],
        errorCode: 'EXTRACTION_FAILED',
        errorMessage: (error instanceof Error ? error.message : 'Unknown extraction failure').slice(
          0,
          2_048,
        ),
      };
    }
  }
}

export class TextDocumentExtractor implements DocumentExtractor {
  public readonly name = 'builtin-text-v1';

  public supports(detection: FileDetection): boolean {
    return ['code', 'text', 'markdown', 'json', 'yaml', 'diagram', 'svg'].includes(
      detection.kind,
    );
  }

  public async extract(
    source: SourceDocument,
    detection: FileDetection,
  ): Promise<ExtractionResult> {
    const decoded = decodeText(source.bytes);
    if (decoded === null) {
      throw new Error('Detected textual input is not valid UTF-8');
    }
    const text = normalizeText(decoded);
    const validationWarning = validateStructuredText(text, detection);
    const citations = createLineCitations(source, text);
    const markdown =
      detection.kind === 'markdown'
        ? text
        : renderFencedMarkdown(source.filename, text, markdownLanguage(detection));
    return {
      status: validationWarning === null ? 'extracted' : 'low_confidence',
      extractor: this.name,
      detection,
      document: { markdown, text, citations },
      threatInput: {
        authoritative: false,
        confidence: 0,
        reasons: ['Set by extractor registry'],
      },
      warnings: validationWarning === null ? [] : [validationWarning],
      errorCode: validationWarning === null ? null : 'STRUCTURE_VALIDATION_FAILED',
      errorMessage: null,
    };
  }
}

export class OcrDocumentExtractor implements DocumentExtractor {
  public readonly name = 'ocr-document-v1';

  public constructor(
    private readonly adapter: OcrAdapter | undefined,
    private readonly minimumConfidence: number,
  ) {}

  public supports(detection: FileDetection): boolean {
    return detection.kind === 'image' || detection.kind === 'pdf';
  }

  public async extract(
    source: SourceDocument,
    detection: FileDetection,
  ): Promise<ExtractionResult> {
    if (this.adapter === undefined) {
      return unavailableResult(
        this.name,
        detection,
        'OCR_ADAPTER_UNAVAILABLE',
        'Image/PDF was preserved, but no OCR adapter is configured',
      );
    }
    const ocr = await this.adapter.analyze({
      bytes: source.bytes,
      mediaType: detection.mediaType,
      filename: source.filename,
      ...(source.workspaceLocator === undefined
        ? {}
        : { workspaceLocator: source.workspaceLocator }),
    });
    return ocrResult(this.name, source, detection, ocr, this.minimumConfidence);
  }
}

export class OfficeExtractor implements DocumentExtractor {
  public readonly name = 'office-document-v1';

  public constructor(
    private readonly adapter: OfficeDocumentAdapter | undefined,
    private readonly minimumConfidence: number,
  ) {}

  public supports(detection: FileDetection): boolean {
    return detection.kind === 'office';
  }

  public async extract(
    source: SourceDocument,
    detection: FileDetection,
  ): Promise<ExtractionResult> {
    if (this.adapter === undefined) {
      return unavailableResult(
        this.name,
        detection,
        'OFFICE_ADAPTER_UNAVAILABLE',
        'Office document was preserved, but no Office extraction adapter is configured',
      );
    }
    const document = await this.adapter.extract({
      bytes: source.bytes,
      mediaType: detection.mediaType,
      filename: source.filename,
    });
    return ocrResult(this.name, source, detection, document, this.minimumConfidence);
  }
}

function ocrResult(
  extractor: string,
  source: SourceDocument,
  detection: FileDetection,
  ocr: OcrDocument,
  minimumConfidence: number,
): ExtractionResult {
  const pages = [...ocr.pages].sort((left, right) => left.pageNumber - right.pageNumber);
  const textSections: string[] = [];
  const markdownSections: string[] = [];
  const citations: SourceCitation[] = [];
  const confidences: number[] = [];
  for (const page of pages) {
    if (!Number.isInteger(page.pageNumber) || page.pageNumber < 1) {
      throw new Error('OCR page numbers must be positive integers');
    }
    const lines = [...page.lines].sort((left, right) => left.lineNumber - right.lineNumber);
    const pageText = lines.map((line) => line.text).join('\n');
    textSections.push(pageText);
    markdownSections.push(`## Page ${page.pageNumber}\n\n${pageText}`);
    for (const line of lines) {
      const confidence = normalizeOcrConfidence(line.confidence);
      confidences.push(confidence);
      citations.push(
        makeCitation(source, {
          page: page.pageNumber,
          lineStart: line.lineNumber,
          lineEnd: line.lineNumber,
          boundingBox: line.boundingBox ?? null,
        }),
      );
    }
  }
  if (citations.length === 0) {
    return unavailableResult(
      extractor,
      detection,
      'NO_TEXT_DETECTED',
      'Extractor returned no readable text; the original was preserved',
    );
  }
  const average = confidences.reduce((sum, value) => sum + value, 0) / confidences.length;
  const lowConfidence = average < minimumConfidence;
  return {
    status: lowConfidence ? 'low_confidence' : 'extracted',
    extractor,
    detection,
    document: {
      markdown: `# ${escapeMarkdown(source.filename)}\n\n${markdownSections.join('\n\n')}\n`,
      text: `${textSections.join('\n\f\n')}\n`,
      citations,
    },
    threatInput: {
      authoritative: false,
      confidence: 0,
      reasons: ['Set by extractor registry'],
    },
    warnings: lowConfidence
      ? [`Average extraction confidence ${average.toFixed(3)} is below ${minimumConfidence}`]
      : [],
    errorCode: lowConfidence ? 'LOW_OCR_CONFIDENCE' : null,
    errorMessage: null,
  };
}

function unavailableResult(
  extractor: string,
  detection: FileDetection,
  errorCode: string,
  warning: string,
): ExtractionResult {
  return {
    status: 'low_confidence',
    extractor,
    detection,
    document: null,
    threatInput: {
      authoritative: false,
      confidence: 0,
      reasons: ['Set by extractor registry'],
    },
    warnings: [warning],
    errorCode,
    errorMessage: null,
  };
}

function createLineCitations(
  source: SourceDocument,
  text: string,
  chunkSize = 100,
): readonly SourceCitation[] {
  const citationText = text.endsWith('\n') ? text.slice(0, -1) : text;
  const lineCount = citationText.length === 0 ? 0 : citationText.split('\n').length;
  const citations: SourceCitation[] = [];
  for (let start = 1; start <= lineCount; start += chunkSize) {
    citations.push(
      makeCitation(source, {
        page: null,
        lineStart: start,
        lineEnd: Math.min(lineCount, start + chunkSize - 1),
        boundingBox: null,
      }),
    );
  }
  return citations;
}

function makeCitation(
  source: SourceDocument,
  location: {
    readonly page: number | null;
    readonly lineStart: number | null;
    readonly lineEnd: number | null;
    readonly boundingBox: CitationBoundingBox | null;
  },
): SourceCitation {
  const seed = {
    sourceObjectId: source.sourceObjectId,
    sourceSha256: source.sourceSha256,
    sourceName: source.filename,
    archivePath: source.archivePath,
    ...location,
  };
  return {
    citationId: `citation-${sha256Hex(stableJson(seed))}`,
    ...seed,
  };
}

function normalizeText(value: string): string {
  const withoutBom = value.charCodeAt(0) === 0xfeff ? value.slice(1) : value;
  const unix = withoutBom.replace(/\r\n?/g, '\n');
  return unix.endsWith('\n') ? unix : `${unix}\n`;
}

function validateStructuredText(text: string, detection: FileDetection): string | null {
  if (detection.kind === 'json') {
    try {
      JSON.parse(text);
      return null;
    } catch (error) {
      return `JSON validation failed: ${error instanceof Error ? error.message : 'invalid JSON'}`;
    }
  }
  if (detection.kind === 'yaml') {
    const document = parseDocument(text, { strict: true, uniqueKeys: true });
    if (document.errors.length > 0) {
      return `YAML validation failed: ${document.errors[0]!.message}`;
    }
    try {
      document.toJS({ maxAliasCount: 100 });
    } catch (error) {
      return `YAML expansion failed: ${error instanceof Error ? error.message : 'unsafe aliases'}`;
    }
  }
  return null;
}

function renderFencedMarkdown(filename: string, text: string, language: string): string {
  const longestRun = Math.max(3, ...([...text.matchAll(/`+/g)].map((match) => match[0].length + 1)));
  const fence = '`'.repeat(longestRun);
  return `# ${escapeMarkdown(filename)}\n\n${fence}${language}\n${text}${fence}\n`;
}

function markdownLanguage(detection: FileDetection): string {
  if (detection.kind === 'diagram') {
    if (detection.mediaType === 'text/vnd.mermaid') {
      return 'mermaid';
    }
    if (detection.mediaType === 'text/vnd.plantuml') {
      return 'plantuml';
    }
    return 'xml';
  }
  if (detection.kind === 'svg') {
    return 'xml';
  }
  return languageForExtension(detection.extension);
}

function escapeMarkdown(value: string): string {
  return value.replace(/([\\`*_[\]<>#])/g, '\\$1');
}

function normalizeOcrConfidence(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(1, value > 1 ? value / 100 : value));
}

export function documentArtifacts(document: NormalizedDocument): Readonly<{
  markdown: Uint8Array;
  text: Uint8Array;
  citations: Uint8Array;
}> {
  return {
    markdown: Buffer.from(document.markdown, 'utf8'),
    text: Buffer.from(document.text, 'utf8'),
    citations: Buffer.from(`${stableJson(document.citations)}\n`, 'utf8'),
  };
}
