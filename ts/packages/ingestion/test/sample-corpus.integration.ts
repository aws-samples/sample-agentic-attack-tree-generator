import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join, relative, resolve, sep } from 'node:path';
import test from 'node:test';
import { OpenXmlOfficeAdapter } from '../src/office.js';
import {
  ExtractorRegistry,
  sha256Hex,
  type OcrAdapter,
  type OcrDocument,
  type SourceDocument,
} from '../src/index.js';

const CORPUS_ENVIRONMENT_VARIABLE = 'THREATFOREST_SAMPLE_CORPUS';
const EXCLUDED_DIRECTORIES = new Set([
  '.aws-sam',
  '.git',
  '.next',
  '.turbo',
  'build',
  'cdk.out',
  'coverage',
  'dist',
  'node_modules',
  'out',
  'target',
]);

const FIXTURES = {
  markdown: 'hcls-example/overview.md',
  threatComposer: 'genai-chatbot/ThreatComposer_Workspace_GenAI-Chatbot.tc.json',
  yaml: 'juice-shop/juiceshop-ecs.yaml',
  mermaid: 'genai-chatbot/genaichatbot-dfd.mmd',
  source:
    'auto-manufacturing/chatbot-realtime-smart-monitoring/src/request-boundary.ts',
  png: 'vehicle-platform/DFD.png',
  jpeg: 'sample-customer/Bismarck_20250902_163436.jpg',
  pdf: 'LAMS-m2m/lams-m2m.pdf',
  powerpoint: 'LAMS-m2m/lams-m2m.pptx',
} as const;

const EXPECTED_BINARY_INPUTS = new Map<
  string,
  {
    readonly mediaType: string;
    readonly minimumBytes: number;
    readonly signature: readonly number[] | string;
    readonly extractedText: string;
  }
>([
  [
    basename(FIXTURES.png),
    {
      mediaType: 'image/png',
      minimumBytes: 100_000,
      signature: [137, 80, 78, 71, 13, 10, 26, 10],
      extractedText: 'Vehicle registration platform data-flow diagram',
    },
  ],
  [
    basename(FIXTURES.jpeg),
    {
      mediaType: 'image/jpeg',
      minimumBytes: 2_000_000,
      signature: [0xff, 0xd8, 0xff],
      extractedText: 'Customer-supplied architecture image',
    },
  ],
  [
    basename(FIXTURES.pdf),
    {
      mediaType: 'application/pdf',
      minimumBytes: 70_000,
      signature: '%PDF-',
      extractedText: 'LAMS machine-to-machine architecture',
    },
  ],
]);

test('sample corpus is complete and inventory excludes dependency and build trees', () => {
  const root = requireCorpusRoot();
  const files = inventoryCorpus(root);

  for (const fixture of Object.values(FIXTURES)) {
    assert.ok(
      files.includes(fixture),
      `Required sample-corpus fixture is missing from the filtered inventory: ${fixture}`,
    );
  }
  assert.ok(
    files.length >= Object.keys(FIXTURES).length,
    `Filtered sample corpus unexpectedly contains only ${files.length} files`,
  );
  for (const path of files) {
    assert.equal(
      path.split('/').some((segment) => EXCLUDED_DIRECTORIES.has(segment)),
      false,
      `Excluded directory leaked into sample-corpus inventory: ${path}`,
    );
  }
});

test('real Markdown, Threat Composer JSON, YAML, Mermaid, and source code extract deterministically', async () => {
  const registry = new ExtractorRegistry();

  const markdown = await extractTwice(registry, fixtureSource(FIXTURES.markdown));
  assert.equal(markdown.status, 'extracted');
  assert.equal(markdown.detection.kind, 'markdown');
  assert.match(markdown.document!.text, /standardized datasets/);
  assert.equal(markdown.threatInput.authoritative, false);

  const threatComposer = await extractTwice(
    registry,
    fixtureSource(FIXTURES.threatComposer),
  );
  assert.equal(threatComposer.status, 'extracted');
  assert.equal(threatComposer.detection.kind, 'json');
  assert.match(threatComposer.document!.text, /Generative AI Chatbot Application/);
  assert.equal(threatComposer.threatInput.authoritative, true);
  assert.equal(threatComposer.threatInput.confidence, 1);
  assert.match(
    threatComposer.threatInput.reasons.join(' '),
    /Threat Composer workspace contains a structured threats collection/,
  );

  const yaml = await extractTwice(registry, fixtureSource(FIXTURES.yaml));
  assert.equal(yaml.status, 'extracted');
  assert.equal(yaml.detection.kind, 'yaml');
  assert.match(yaml.document!.text, /AWS::ECS::Cluster/);
  assert.match(yaml.document!.markdown, /```yaml/);

  const mermaid = await extractTwice(registry, fixtureSource(FIXTURES.mermaid));
  assert.equal(mermaid.status, 'extracted');
  assert.equal(mermaid.detection.kind, 'diagram');
  assert.equal(mermaid.detection.mediaType, 'text/vnd.mermaid');
  assert.match(mermaid.document!.text, /Trust Boundary 6/);
  assert.match(mermaid.document!.markdown, /```mermaid/);

  const source = await extractTwice(registry, fixtureSource(FIXTURES.source));
  assert.equal(source.status, 'extracted');
  assert.equal(source.detection.kind, 'code');
  assert.equal(source.detection.mediaType, 'text/typescript');
  assert.match(source.document!.text, /parseAndValidateRequest/);
  assert.match(source.document!.markdown, /```typescript/);
});

test('real PNG, JPEG, and PDF inputs cross the offline OCR boundary deterministically', async () => {
  const adapter = new CorpusOcrAdapter();
  const registry = new ExtractorRegistry({ ocrAdapter: adapter });

  for (const path of [FIXTURES.png, FIXTURES.jpeg, FIXTURES.pdf]) {
    const expected = EXPECTED_BINARY_INPUTS.get(basename(path));
    assert.ok(expected, `No deterministic OCR expectation is registered for ${path}`);

    const result = await extractTwice(registry, fixtureSource(path));
    assert.equal(result.status, 'extracted');
    assert.equal(result.detection.mediaType, expected.mediaType);
    assert.equal(result.detection.kind, path.endsWith('.pdf') ? 'pdf' : 'image');
    assert.equal(result.errorCode, null);
    assert.equal(result.document!.text, `${expected.extractedText}\n`);
    assert.equal(result.document!.citations.length, 1);
    assert.equal(result.document!.citations[0]!.page, 1);
  }

  assert.deepEqual(
    adapter.calls,
    [
      basename(FIXTURES.png),
      basename(FIXTURES.png),
      basename(FIXTURES.jpeg),
      basename(FIXTURES.jpeg),
      basename(FIXTURES.pdf),
      basename(FIXTURES.pdf),
    ],
  );
});

test('real PowerPoint is detected and its OpenXML text extracts deterministically', async () => {
  const adapter = new OpenXmlOfficeAdapter();
  const registry = new ExtractorRegistry({ officeAdapter: adapter });
  const result = await extractTwice(registry, fixtureSource(FIXTURES.powerpoint));

  assert.equal(result.status, 'extracted');
  assert.equal(result.detection.kind, 'office');
  assert.equal(
    result.detection.mediaType,
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  );
  assert.equal(result.errorCode, null);
  assert.match(result.document!.text, /LAMS API \(Single LAMS Instance\)/);
  assert.match(result.document!.text, /API Gateway \(public\) HTTP API/);
  assert.match(result.document!.text, /AWS WAF \+ IP Allowlist/);
  assert.ok(result.document!.citations.length >= 10);
});

class CorpusOcrAdapter implements OcrAdapter {
  public readonly calls: string[] = [];

  public async analyze(input: {
    readonly bytes: Uint8Array;
    readonly mediaType: string;
    readonly filename: string;
  }): Promise<OcrDocument> {
    this.calls.push(input.filename);
    const expected = EXPECTED_BINARY_INPUTS.get(input.filename);
    if (expected === undefined) {
      throw new Error(`Unexpected offline OCR input: ${input.filename}`);
    }
    if (input.mediaType !== expected.mediaType) {
      throw new Error(
        `Unexpected media type for ${input.filename}: ${input.mediaType}`,
      );
    }
    if (input.bytes.byteLength < expected.minimumBytes) {
      throw new Error(
        `${input.filename} is incomplete: expected at least ${expected.minimumBytes} bytes, received ${input.bytes.byteLength}`,
      );
    }
    assertSignature(input.filename, input.bytes, expected.signature);
    return {
      pages: [
        {
          pageNumber: 1,
          lines: [
            {
              text: expected.extractedText,
              confidence: 0.99,
              lineNumber: 1,
            },
          ],
        },
      ],
    };
  }
}

function requireCorpusRoot(): string {
  const configured = process.env[CORPUS_ENVIRONMENT_VARIABLE];
  if (!configured) throw new Error(`Set ${CORPUS_ENVIRONMENT_VARIABLE} to the separately provisioned sample corpus. Unit tests use checked-in synthetic fixtures.`);
  const root = resolve(configured);
  let status;
  try {
    status = statSync(root);
  } catch (error) {
    throw new Error(
      `Sample corpus root is unavailable: ${root}. Set ${CORPUS_ENVIRONMENT_VARIABLE} to a complete sample-applications checkout.`,
      { cause: error },
    );
  }
  if (!status.isDirectory()) {
    throw new Error(`Sample corpus root is not a directory: ${root}`);
  }
  return root;
}

function fixtureSource(path: string): SourceDocument {
  const root = requireCorpusRoot();
  const absolutePath = resolve(root, ...path.split('/'));
  const relativePath = relative(root, absolutePath);
  if (
    relativePath === '..' ||
    relativePath.startsWith(`..${sep}`) ||
    resolve(root, relativePath) !== absolutePath
  ) {
    throw new Error(`Sample fixture escapes the corpus root: ${path}`);
  }

  let bytes: Buffer;
  try {
    const status = statSync(absolutePath);
    if (!status.isFile()) {
      throw new Error('path is not a regular file');
    }
    bytes = readFileSync(absolutePath);
  } catch (error) {
    throw new Error(
      `Required sample-corpus fixture is unavailable: ${path} (root: ${root})`,
      { cause: error },
    );
  }
  if (bytes.byteLength === 0) {
    throw new Error(`Required sample-corpus fixture is empty: ${path}`);
  }

  return {
    sourceObjectId: `sample-${sha256Hex(path)}`,
    sourceSha256: sha256Hex(bytes),
    filename: basename(path),
    archivePath: path,
    declaredContentType: null,
    bytes,
  };
}

function inventoryCorpus(root: string): string[] {
  const files: string[] = [];

  function visit(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRECTORIES.has(entry.name)) {
          visit(absolutePath);
        }
        continue;
      }
      if (entry.isFile()) {
        files.push(relative(root, absolutePath).split(sep).join('/'));
      }
    }
  }

  visit(root);
  return files.sort();
}

async function extractTwice(
  registry: ExtractorRegistry,
  source: SourceDocument,
) {
  const first = await registry.extract(source);
  const second = await registry.extract(source);
  assert.deepEqual(second, first, `Extraction is not deterministic for ${source.archivePath}`);
  return first;
}

function assertSignature(
  filename: string,
  bytes: Uint8Array,
  signature: readonly number[] | string,
): void {
  const actual =
    typeof signature === 'string'
      ? Buffer.from(bytes).subarray(0, signature.length).toString('ascii')
      : [...bytes.slice(0, signature.length)];
  assert.deepEqual(actual, signature, `${filename} has an unexpected binary signature`);
}
