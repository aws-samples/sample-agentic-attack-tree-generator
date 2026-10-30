import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import {
  ExtractorRegistry,
  classifyThreatInput,
  detectFile,
  sha256Hex,
  type OcrAdapter,
  type OfficeDocumentAdapter,
  type SourceDocument,
} from '../src/index.js';

test('magic detection overrides misleading extensions and reports mismatches', () => {
  const pdf = Buffer.from('%PDF-1.7\nfake\n');
  const detected = detectFile({
    filename: 'architecture.txt',
    bytes: pdf,
    declaredContentType: 'text/plain',
  });
  assert.equal(detected.kind, 'pdf');
  assert.equal(detected.mediaType, 'application/pdf');
  assert.equal(detected.extensionMismatch, true);
  assert.equal(detected.confidence, 1);
});

test('empty and unknown binary inputs are explicit rather than omitted', async () => {
  const registry = new ExtractorRegistry();
  const empty = await registry.extract(source('empty.txt', Buffer.alloc(0)));
  assert.equal(empty.status, 'low_confidence');
  assert.equal(empty.errorCode, 'EMPTY_INPUT');

  const binary = await registry.extract(
    source('payload.bin', Buffer.from([0, 1, 2, 3, 4, 5])),
  );
  assert.equal(binary.status, 'unsupported');
  assert.equal(binary.errorCode, 'UNSUPPORTED_TYPE');
});

test('text extraction normalizes line endings and creates deterministic citations', async () => {
  const registry = new ExtractorRegistry();
  const input = source('service.ts', Buffer.from('const a = 1;\r\nconst b = 2;'));
  const first = await registry.extract(input);
  const second = await registry.extract(input);
  assert.equal(first.status, 'extracted');
  assert.equal(first.document!.text, 'const a = 1;\nconst b = 2;\n');
  assert.deepEqual(first.document!.citations, second.document!.citations);
  assert.match(first.document!.citations[0]!.citationId, /^citation-[a-f0-9]{64}$/);
  assert.equal(first.document!.citations[0]!.lineStart, 1);
  assert.equal(first.document!.citations[0]!.lineEnd, 2);
});

test('invalid JSON is preserved with an explicit low-confidence result', async () => {
  const result = await new ExtractorRegistry().extract(
    source('config.json', Buffer.from('{"broken":\n')),
  );
  assert.equal(result.status, 'low_confidence');
  assert.equal(result.errorCode, 'STRUCTURE_VALIDATION_FAILED');
  assert.match(result.warnings[0]!, /JSON validation failed/);
  assert.equal(result.document!.text, '{"broken":\n');
});

test('diagram and SVG inputs use textual extraction', async () => {
  const registry = new ExtractorRegistry();
  const mermaid = await registry.extract(
    source('architecture.mmd', Buffer.from('graph TD\nA-->B\n')),
  );
  assert.equal(mermaid.detection.kind, 'diagram');
  assert.match(mermaid.document!.markdown, /```mermaid/);

  const svg = await registry.extract(
    source('architecture.data', Buffer.from('<svg><text>API</text></svg>')),
  );
  assert.equal(svg.detection.kind, 'svg');
  assert.match(svg.document!.markdown, /```xml/);
});

test('OCR adapter preserves page, line, and bounding-box citations', async () => {
  const ocr: OcrAdapter = {
    async analyze() {
      return {
        pages: [
          {
            pageNumber: 2,
            lines: [
              {
                text: 'Database',
                confidence: 98,
                lineNumber: 1,
                boundingBox: { left: 0.1, top: 0.2, width: 0.3, height: 0.1 },
              },
            ],
          },
          {
            pageNumber: 1,
            lines: [{ text: 'API Gateway', confidence: 0.99, lineNumber: 1 }],
          },
        ],
      };
    },
  };
  const png = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    Buffer.alloc(20),
  ]);
  const result = await new ExtractorRegistry({ ocrAdapter: ocr }).extract(
    source('diagram.png', png),
  );
  assert.equal(result.status, 'extracted');
  assert.deepEqual(
    result.document!.citations.map((citation) => citation.page),
    [1, 2],
  );
  assert.equal(result.document!.citations[1]!.boundingBox!.left, 0.1);
  assert.match(result.document!.markdown, /## Page 1[\s\S]*## Page 2/);
});

test('image/PDF and Office inputs without adapters return low-confidence outcomes', async () => {
  const registry = new ExtractorRegistry();
  const pdf = await registry.extract(source('design.pdf', Buffer.from('%PDF-1.7\n')));
  assert.equal(pdf.status, 'low_confidence');
  assert.equal(pdf.errorCode, 'OCR_ADAPTER_UNAVAILABLE');

  const officeBytes = zipSync(
    {
      '[Content_Types].xml': Buffer.from('<Types/>'),
      'word/document.xml': Buffer.from('<document/>'),
    },
    { level: 0 },
  );
  const office = await registry.extract(source('design.docx', officeBytes));
  assert.equal(office.detection.kind, 'office');
  assert.equal(office.status, 'low_confidence');
  assert.equal(office.errorCode, 'OFFICE_ADAPTER_UNAVAILABLE');
});

test('pluggable Office extraction emits normalized content', async () => {
  const officeAdapter: OfficeDocumentAdapter = {
    async extract() {
      return {
        pages: [
          {
            pageNumber: 1,
            lines: [{ text: 'Architecture overview', confidence: 0.95, lineNumber: 1 }],
          },
        ],
      };
    },
  };
  const bytes = zipSync(
    {
      '[Content_Types].xml': Buffer.from('<Types/>'),
      'ppt/slides/slide1.xml': Buffer.from('<slide/>'),
    },
    { level: 0 },
  );
  const result = await new ExtractorRegistry({ officeAdapter }).extract(
    source('architecture.pptx', bytes),
  );
  assert.equal(result.status, 'extracted');
  assert.match(result.document!.text, /Architecture overview/);
});

test('structured and Markdown threat files are authoritative, ordinary docs are not', () => {
  const structured = source(
    'ThreatComposer_Workspace.tc.json',
    Buffer.from(
      JSON.stringify({
        schema: 1,
        applicationInfo: { name: 'Example' },
        threats: [{ statement: 'An attacker can bypass authentication controls.' }],
      }),
    ),
  );
  const structuredDetection = detectFile({
    filename: structured.filename,
    bytes: structured.bytes,
  });
  assert.equal(classifyThreatInput(structured, structuredDetection).authoritative, true);

  const markdown = source(
    'generated_threat_statements.md',
    Buffer.from(
      '# Threat Statements\n\n## Threat 1 - Injection\n**Threat Statement**: An attacker injects input.\n\n## Threat 2 - Access\n**Threat Statement**: An attacker bypasses access.\n',
    ),
  );
  const markdownDetection = detectFile({
    filename: markdown.filename,
    bytes: markdown.bytes,
  });
  assert.equal(classifyThreatInput(markdown, markdownDetection).authoritative, true);

  const readme = source(
    'README.md',
    Buffer.from('# Service\n\nThis service includes threat detection telemetry.\n'),
  );
  const readmeDetection = detectFile({ filename: readme.filename, bytes: readme.bytes });
  assert.equal(classifyThreatInput(readme, readmeDetection).authoritative, false);
});

function source(filename: string, bytes: Uint8Array): SourceDocument {
  return {
    sourceObjectId: `source-${sha256Hex(filename)}`,
    sourceSha256: sha256Hex(bytes),
    filename,
    archivePath: null,
    declaredContentType: null,
    bytes,
  };
}
