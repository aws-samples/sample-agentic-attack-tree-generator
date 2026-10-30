import { extname } from 'node:path';
import { isOfficeZip, isZipBytes } from './archive.js';
import type { DetectedFileKind, FileDetection } from './types.js';

const CODE_EXTENSIONS = new Set([
  '.c',
  '.cc',
  '.cpp',
  '.cs',
  '.css',
  '.go',
  '.h',
  '.hpp',
  '.html',
  '.java',
  '.js',
  '.jsx',
  '.kt',
  '.kts',
  '.php',
  '.py',
  '.rb',
  '.rs',
  '.sh',
  '.sql',
  '.swift',
  '.tf',
  '.ts',
  '.tsx',
  '.vue',
  '.xml',
]);

const TEXT_EXTENSIONS = new Set([
  '.cfg',
  '.conf',
  '.env',
  '.gitignore',
  '.graphql',
  '.ini',
  '.log',
  '.properties',
  '.proto',
  '.txt',
]);

const DIAGRAM_EXTENSIONS = new Set([
  '.drawio',
  '.mermaid',
  '.mmd',
  '.plantuml',
  '.puml',
]);

const IMAGE_MEDIA_TYPES = new Map<string, string>([
  ['png', 'image/png'],
  ['jpeg', 'image/jpeg'],
  ['gif', 'image/gif'],
  ['webp', 'image/webp'],
  ['bmp', 'image/bmp'],
  ['tiff', 'image/tiff'],
]);

const EXTENSION_KINDS: Readonly<Record<string, DetectedFileKind>> = {
  '.md': 'markdown',
  '.markdown': 'markdown',
  '.json': 'json',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.svg': 'svg',
  '.png': 'image',
  '.jpg': 'image',
  '.jpeg': 'image',
  '.gif': 'image',
  '.webp': 'image',
  '.bmp': 'image',
  '.tif': 'image',
  '.tiff': 'image',
  '.pdf': 'pdf',
  '.doc': 'office',
  '.docx': 'office',
  '.ppt': 'office',
  '.pptx': 'office',
  '.xls': 'office',
  '.xlsx': 'office',
  '.zip': 'archive',
  '.tfreport': 'archive',
};

export interface DetectionInput {
  readonly filename: string;
  readonly bytes: Uint8Array;
  readonly declaredContentType?: string | null;
}

export function detectFile(input: DetectionInput): FileDetection {
  const bytes = Uint8Array.from(input.bytes);
  const extension = extensionOf(input.filename);
  if (bytes.byteLength === 0) {
    return result('empty', 'application/x-empty', extension, 1, false, [
      'Input contains zero bytes',
    ]);
  }

  const magic = detectMagic(bytes);
  if (magic !== null) {
    const expected = expectedKindForExtension(extension);
    const extensionMismatch =
      expected !== null && !kindsCompatible(expected, magic.kind);
    const declaredMismatch = declaredTypeMismatch(input.declaredContentType, magic.mediaType);
    const reasons = [
      `Binary signature identifies ${magic.mediaType}`,
      ...(extensionMismatch
        ? [`Extension ${extension ?? '(none)'} does not match detected content`]
        : []),
      ...(declaredMismatch ? ['Declared content type does not match detected content'] : []),
    ];
    return {
      ...result(magic.kind, magic.mediaType, extension, magic.confidence, true, reasons),
      extensionMismatch: extensionMismatch || declaredMismatch,
    };
  }

  const text = decodeText(bytes);
  if (text === null) {
    return result('binary', 'application/octet-stream', extension, 0.95, false, [
      'Input is binary and has no supported file signature',
    ]);
  }

  const textKind = detectTextKind(text, extension);
  const extensionMismatch =
    expectedKindForExtension(extension) !== null &&
    !kindsCompatible(expectedKindForExtension(extension)!, textKind.kind);
  return {
    ...result(
      textKind.kind,
      textKind.mediaType,
      extension,
      textKind.confidence,
      textKind.supported,
      [
        ...textKind.reasons,
        ...(extensionMismatch
          ? [`Extension ${extension ?? '(none)'} does not match textual content`]
          : []),
      ],
    ),
    extensionMismatch,
  };
}

export function decodeText(bytes: Uint8Array): string | null {
  if (bytes.includes(0)) {
    return null;
  }
  let value: string;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  if (value.length === 0) {
    return '';
  }
  let suspicious = 0;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if ((code < 32 && character !== '\n' && character !== '\r' && character !== '\t') || code === 127) {
      suspicious += 1;
    }
  }
  return suspicious / value.length > 0.01 ? null : value;
}

export function languageForExtension(extension: string | null): string {
  const languages: Readonly<Record<string, string>> = {
    '.c': 'c',
    '.cc': 'cpp',
    '.cpp': 'cpp',
    '.cs': 'csharp',
    '.css': 'css',
    '.go': 'go',
    '.h': 'c',
    '.hpp': 'cpp',
    '.html': 'html',
    '.java': 'java',
    '.js': 'javascript',
    '.jsx': 'jsx',
    '.json': 'json',
    '.kt': 'kotlin',
    '.kts': 'kotlin',
    '.php': 'php',
    '.py': 'python',
    '.rb': 'ruby',
    '.rs': 'rust',
    '.sh': 'shell',
    '.sql': 'sql',
    '.swift': 'swift',
    '.tf': 'hcl',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.vue': 'vue',
    '.xml': 'xml',
    '.yaml': 'yaml',
    '.yml': 'yaml',
  };
  return extension === null ? 'text' : (languages[extension] ?? 'text');
}

function detectMagic(
  bytes: Uint8Array,
): { readonly kind: DetectedFileKind; readonly mediaType: string; readonly confidence: number } | null {
  const buffer = Buffer.from(bytes);
  if (startsWith(buffer, '%PDF-')) {
    return { kind: 'pdf', mediaType: 'application/pdf', confidence: 1 };
  }
  if (buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    return { kind: 'image', mediaType: 'image/png', confidence: 1 };
  }
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { kind: 'image', mediaType: 'image/jpeg', confidence: 1 };
  }
  if (startsWith(buffer, 'GIF87a') || startsWith(buffer, 'GIF89a')) {
    return { kind: 'image', mediaType: 'image/gif', confidence: 1 };
  }
  if (
    startsWith(buffer, 'RIFF') &&
    buffer.byteLength >= 12 &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return { kind: 'image', mediaType: 'image/webp', confidence: 1 };
  }
  if (startsWith(buffer, 'BM')) {
    return { kind: 'image', mediaType: 'image/bmp', confidence: 0.99 };
  }
  if (
    buffer.subarray(0, 4).equals(Buffer.from([0x49, 0x49, 0x2a, 0x00])) ||
    buffer.subarray(0, 4).equals(Buffer.from([0x4d, 0x4d, 0x00, 0x2a]))
  ) {
    return { kind: 'image', mediaType: 'image/tiff', confidence: 1 };
  }
  if (
    buffer.byteLength >= 8 &&
    buffer.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))
  ) {
    return { kind: 'office', mediaType: 'application/x-ole-storage', confidence: 0.99 };
  }
  if (isZipBytes(buffer)) {
    if (isOfficeZip(buffer)) {
      return {
        kind: 'office',
        mediaType: officeMediaType(buffer),
        confidence: 1,
      };
    }
    return { kind: 'archive', mediaType: 'application/zip', confidence: 1 };
  }
  return null;
}

function detectTextKind(
  text: string,
  extension: string | null,
): {
  readonly kind: DetectedFileKind;
  readonly mediaType: string;
  readonly confidence: number;
  readonly supported: boolean;
  readonly reasons: readonly string[];
} {
  const prefix = text.slice(0, 8_192).trimStart().toLowerCase();
  if (
    extension === '.svg' ||
    /^<\?xml[\s\S]*?<svg[\s>]/.test(prefix) ||
    /^<svg[\s>]/.test(prefix)
  ) {
    return {
      kind: 'svg',
      mediaType: 'image/svg+xml',
      confidence: extension === '.svg' ? 0.98 : 0.95,
      supported: true,
      reasons: ['Text contains an SVG document root'],
    };
  }
  if (
    extension !== null &&
    DIAGRAM_EXTENSIONS.has(extension)
  ) {
    return {
      kind: 'diagram',
      mediaType: diagramMediaType(extension),
      confidence: 0.95,
      supported: true,
      reasons: [`Extension ${extension} identifies a textual diagram`],
    };
  }
  if (extension === '.json' || /^[{[]/.test(prefix)) {
    return {
      kind: 'json',
      mediaType: 'application/json',
      confidence: extension === '.json' ? 0.9 : 0.75,
      supported: true,
      reasons: ['Input has JSON syntax or extension'],
    };
  }
  if (extension === '.yaml' || extension === '.yml') {
    return {
      kind: 'yaml',
      mediaType: 'application/yaml',
      confidence: 0.9,
      supported: true,
      reasons: ['Extension identifies YAML'],
    };
  }
  if (extension === '.md' || extension === '.markdown') {
    return {
      kind: 'markdown',
      mediaType: 'text/markdown',
      confidence: 0.95,
      supported: true,
      reasons: ['Extension identifies Markdown'],
    };
  }
  if (extension !== null && CODE_EXTENSIONS.has(extension)) {
    return {
      kind: 'code',
      mediaType: codeMediaType(extension),
      confidence: 0.9,
      supported: true,
      reasons: [`Extension ${extension} identifies source code`],
    };
  }
  if (extension !== null && TEXT_EXTENSIONS.has(extension)) {
    return {
      kind: 'text',
      mediaType: 'text/plain',
      confidence: 0.9,
      supported: true,
      reasons: [`Extension ${extension} identifies text`],
    };
  }
  return {
    kind: 'text',
    mediaType: 'text/plain',
    confidence: 0.7,
    supported: true,
    reasons: ['Input is valid UTF-8 text'],
  };
}

function result(
  kind: DetectedFileKind,
  mediaType: string,
  extension: string | null,
  confidence: number,
  supported: boolean,
  reasons: readonly string[],
): FileDetection {
  return {
    kind,
    mediaType,
    extension,
    confidence,
    supported,
    extensionMismatch: false,
    reasons,
  };
}

function extensionOf(filename: string): string | null {
  const lower = filename.normalize('NFC').toLowerCase();
  const extension = extname(lower);
  return extension.length === 0 ? null : extension;
}

function expectedKindForExtension(extension: string | null): DetectedFileKind | null {
  if (extension === null) {
    return null;
  }
  if (CODE_EXTENSIONS.has(extension)) {
    return 'code';
  }
  if (TEXT_EXTENSIONS.has(extension)) {
    return 'text';
  }
  if (DIAGRAM_EXTENSIONS.has(extension)) {
    return 'diagram';
  }
  return EXTENSION_KINDS[extension] ?? null;
}

function kindsCompatible(expected: DetectedFileKind, actual: DetectedFileKind): boolean {
  if (expected === actual) {
    return true;
  }
  return (
    (expected === 'text' && ['markdown', 'json', 'yaml', 'code', 'diagram', 'svg'].includes(actual)) ||
    (actual === 'text' && ['markdown', 'code'].includes(expected))
  );
}

function declaredTypeMismatch(declared: string | null | undefined, actual: string): boolean {
  if (
    declared === undefined ||
    declared === null ||
    declared === '' ||
    declared === 'application/octet-stream'
  ) {
    return false;
  }
  const normalized = declared.split(';', 1)[0]!.trim().toLowerCase();
  if (normalized === actual) {
    return false;
  }
  return !(normalized.startsWith('image/') && actual.startsWith('image/'));
}

function startsWith(buffer: Buffer, value: string): boolean {
  return buffer.subarray(0, value.length).toString('ascii') === value;
}

function officeMediaType(bytes: Uint8Array): string {
  try {
    const names = new Set(
      // isOfficeZip already validated the directory. Keep this intentionally
      // lightweight; exact type is advisory and extraction remains pluggable.
      Buffer.from(bytes).toString('latin1').toLowerCase().match(/(?:word|ppt|xl)\//g) ?? [],
    );
    if (names.has('word/')) {
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    }
    if (names.has('ppt/')) {
      return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    }
    if (names.has('xl/')) {
      return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    }
  } catch {
    // Fall through to the generic OpenXML media type.
  }
  return 'application/vnd.openxmlformats-officedocument';
}

function diagramMediaType(extension: string): string {
  if (extension === '.mmd' || extension === '.mermaid') {
    return 'text/vnd.mermaid';
  }
  if (extension === '.puml' || extension === '.plantuml') {
    return 'text/vnd.plantuml';
  }
  return 'application/vnd.jgraph.mxfile';
}

function codeMediaType(extension: string): string {
  const mediaTypes: Readonly<Record<string, string>> = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'text/javascript',
    '.jsx': 'text/jsx',
    '.ts': 'text/typescript',
    '.tsx': 'text/tsx',
    '.xml': 'application/xml',
    '.sql': 'application/sql',
  };
  return mediaTypes[extension] ?? 'text/plain';
}

export function mediaTypeForImageKind(kind: string): string | undefined {
  return IMAGE_MEDIA_TYPES.get(kind);
}
