import { inflateRawSync } from 'node:zlib';
import { sha256Hex } from './hash.js';

export type DuplicatePolicy = 'reject' | 'keep-first' | 'rename';

export interface ArchiveLimits {
  readonly maximumFiles: number;
  readonly maximumFileBytes: number;
  readonly maximumExpandedBytes: number;
  readonly maximumPathDepth: number;
  readonly maximumPathLength: number;
  readonly maximumArchiveNesting: number;
  readonly maximumCompressionRatio: number;
  readonly duplicatePolicy: DuplicatePolicy;
}

export const DEFAULT_ARCHIVE_LIMITS: ArchiveLimits = {
  maximumFiles: 5_000,
  maximumFileBytes: 64 * 1024 * 1024,
  maximumExpandedBytes: 512 * 1024 * 1024,
  maximumPathDepth: 24,
  maximumPathLength: 1_024,
  maximumArchiveNesting: 3,
  maximumCompressionRatio: 200,
  duplicatePolicy: 'reject',
};

export interface ExtractedArchiveEntry {
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
  readonly archiveNesting: number;
}

export interface ArchiveExtractionResult {
  readonly entries: readonly ExtractedArchiveEntry[];
  readonly warnings: readonly string[];
  readonly expandedBytes: number;
  readonly inspectedFiles: number;
}

export interface ZipEntryInspection {
  readonly path: string;
  readonly directory: boolean;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly compressionMethod: number;
}

export class ArchiveValidationError extends Error {
  public constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'ArchiveValidationError';
  }
}

interface CentralEntry extends ZipEntryInspection {
  readonly crc32: number;
  readonly localHeaderOffset: number;
  readonly generalPurposeFlags: number;
  readonly externalAttributes: number;
  readonly madeByHost: number;
}

interface ExtractionBudget {
  fileCount: number;
  expandedBytes: number;
  readonly seenPaths: Set<string>;
  readonly entries: ExtractedArchiveEntry[];
  readonly warnings: string[];
}

export class SafeZipExtractor {
  private readonly limits: ArchiveLimits;

  public constructor(limits: Partial<ArchiveLimits> = {}) {
    this.limits = { ...DEFAULT_ARCHIVE_LIMITS, ...limits };
    validateLimits(this.limits);
  }

  public extract(bytes: Uint8Array): ArchiveExtractionResult {
    const budget: ExtractionBudget = {
      fileCount: 0,
      expandedBytes: 0,
      seenPaths: new Set(),
      entries: [],
      warnings: [],
    };
    this.extractArchive(Buffer.from(bytes), '', 0, budget);
    return {
      entries: budget.entries,
      warnings: budget.warnings,
      expandedBytes: budget.expandedBytes,
      inspectedFiles: budget.fileCount,
    };
  }

  private extractArchive(
    archive: Buffer,
    parentPath: string,
    archiveNesting: number,
    budget: ExtractionBudget,
  ): void {
    if (archiveNesting > this.limits.maximumArchiveNesting) {
      throw new ArchiveValidationError(
        'ARCHIVE_NESTING_EXCEEDED',
        `Archive nesting exceeds ${this.limits.maximumArchiveNesting}`,
      );
    }
    const entries = parseCentralDirectory(archive, this.limits);
    for (const entry of entries) {
      if (entry.directory) {
        continue;
      }
      this.consumeDeclaredBudget(entry, budget);
      const extracted = extractCentralEntry(archive, entry, this.limits.maximumFileBytes);
      if (extracted.byteLength !== entry.uncompressedSize) {
        throw new ArchiveValidationError(
          'SIZE_MISMATCH',
          `Expanded size does not match the ZIP directory for ${entry.path}`,
        );
      }
      if (crc32(extracted) !== entry.crc32) {
        throw new ArchiveValidationError('CHECKSUM_MISMATCH', `CRC-32 mismatch for ${entry.path}`);
      }

      const combinedPath = parentPath.length === 0 ? entry.path : `${parentPath}/${entry.path}`;
      validateArchivePath(combinedPath, false, this.limits);
      if (isZipBytes(extracted) && !isOfficeZip(extracted)) {
        if (archiveNesting >= this.limits.maximumArchiveNesting) {
          throw new ArchiveValidationError(
            'ARCHIVE_NESTING_EXCEEDED',
            `Nested archive ${combinedPath} exceeds the nesting limit`,
          );
        }
        this.extractArchive(extracted, combinedPath, archiveNesting + 1, budget);
        continue;
      }
      const acceptedPath = this.acceptDuplicate(combinedPath, budget);
      if (acceptedPath === null) {
        continue;
      }
      budget.entries.push({
        path: acceptedPath,
        bytes: Uint8Array.from(extracted),
        sha256: sha256Hex(extracted),
        archiveNesting,
      });
    }
  }

  private consumeDeclaredBudget(entry: CentralEntry, budget: ExtractionBudget): void {
    budget.fileCount += 1;
    if (budget.fileCount > this.limits.maximumFiles) {
      throw new ArchiveValidationError(
        'FILE_COUNT_EXCEEDED',
        `Archive contains more than ${this.limits.maximumFiles} files`,
      );
    }
    if (entry.uncompressedSize > this.limits.maximumFileBytes) {
      throw new ArchiveValidationError(
        'FILE_SIZE_EXCEEDED',
        `${entry.path} exceeds the per-file expanded size limit`,
      );
    }
    budget.expandedBytes += entry.uncompressedSize;
    if (
      !Number.isSafeInteger(budget.expandedBytes) ||
      budget.expandedBytes > this.limits.maximumExpandedBytes
    ) {
      throw new ArchiveValidationError(
        'EXPANDED_SIZE_EXCEEDED',
        `Archive expands beyond ${this.limits.maximumExpandedBytes} bytes`,
      );
    }
    const ratio =
      entry.uncompressedSize === 0
        ? 1
        : entry.uncompressedSize / Math.max(1, entry.compressedSize);
    if (ratio > this.limits.maximumCompressionRatio) {
      throw new ArchiveValidationError(
        'COMPRESSION_RATIO_EXCEEDED',
        `${entry.path} has a suspicious compression ratio of ${ratio.toFixed(1)}`,
      );
    }
  }

  private acceptDuplicate(path: string, budget: ExtractionBudget): string | null {
    const collisionKey = normalizedCollisionKey(path);
    if (!budget.seenPaths.has(collisionKey)) {
      budget.seenPaths.add(collisionKey);
      return path;
    }
    if (this.limits.duplicatePolicy === 'reject') {
      throw new ArchiveValidationError('DUPLICATE_PATH', `Duplicate archive path: ${path}`);
    }
    if (this.limits.duplicatePolicy === 'keep-first') {
      budget.warnings.push(`Ignored duplicate archive path: ${path}`);
      return null;
    }
    let suffix = 2;
    let candidate = addDuplicateSuffix(path, suffix);
    while (budget.seenPaths.has(normalizedCollisionKey(candidate))) {
      suffix += 1;
      candidate = addDuplicateSuffix(path, suffix);
    }
    validateArchivePath(candidate, false, this.limits);
    budget.seenPaths.add(normalizedCollisionKey(candidate));
    budget.warnings.push(`Renamed duplicate archive path ${path} to ${candidate}`);
    return candidate;
  }
}

export function inspectZipEntries(
  bytes: Uint8Array,
  limits: Partial<ArchiveLimits> = {},
): readonly ZipEntryInspection[] {
  const resolved = { ...DEFAULT_ARCHIVE_LIMITS, ...limits };
  validateLimits(resolved);
  return parseCentralDirectory(Buffer.from(bytes), resolved).map((entry) => ({
    path: entry.path,
    directory: entry.directory,
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize,
    compressionMethod: entry.compressionMethod,
  }));
}

export function isZipBytes(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 4) {
    return false;
  }
  const signature = Buffer.from(bytes).readUInt32LE(0);
  return signature === 0x04034b50 || signature === 0x06054b50 || signature === 0x08074b50;
}

export function isOfficeZip(bytes: Uint8Array): boolean {
  if (!isZipBytes(bytes)) {
    return false;
  }
  try {
    const names = inspectZipEntries(bytes, {
      maximumFiles: 20_000,
      maximumExpandedBytes: Number.MAX_SAFE_INTEGER,
      maximumFileBytes: Number.MAX_SAFE_INTEGER,
      maximumCompressionRatio: Number.MAX_SAFE_INTEGER,
    }).map((entry) => entry.path.toLowerCase());
    return (
      names.includes('[content_types].xml') &&
      names.some(
        (name) => name.startsWith('word/') || name.startsWith('xl/') || name.startsWith('ppt/'),
      )
    );
  } catch {
    return false;
  }
}

function parseCentralDirectory(archive: Buffer, limits: ArchiveLimits): CentralEntry[] {
  const eocd = findEndOfCentralDirectory(archive);
  if (eocd < 0) {
    throw new ArchiveValidationError('INVALID_ZIP', 'ZIP end-of-central-directory record is missing');
  }
  ensureReadable(archive, eocd, 22, 'end-of-central-directory');
  const diskNumber = archive.readUInt16LE(eocd + 4);
  const centralDisk = archive.readUInt16LE(eocd + 6);
  const entriesOnDisk = archive.readUInt16LE(eocd + 8);
  const totalEntries = archive.readUInt16LE(eocd + 10);
  const centralSize = archive.readUInt32LE(eocd + 12);
  const centralOffset = archive.readUInt32LE(eocd + 16);
  const commentLength = archive.readUInt16LE(eocd + 20);
  if (eocd + 22 + commentLength !== archive.byteLength) {
    throw new ArchiveValidationError('INVALID_ZIP', 'ZIP trailer length is inconsistent');
  }
  if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== totalEntries) {
    throw new ArchiveValidationError('MULTI_DISK_UNSUPPORTED', 'Multi-disk ZIP archives are unsupported');
  }
  if (
    totalEntries === 0xffff ||
    centralSize === 0xffffffff ||
    centralOffset === 0xffffffff
  ) {
    throw new ArchiveValidationError('ZIP64_UNSUPPORTED', 'ZIP64 archives are unsupported');
  }
  if (totalEntries > limits.maximumFiles) {
    throw new ArchiveValidationError(
      'FILE_COUNT_EXCEEDED',
      `Archive declares more than ${limits.maximumFiles} entries`,
    );
  }
  if (centralOffset + centralSize > eocd || centralOffset + centralSize > archive.byteLength) {
    throw new ArchiveValidationError('INVALID_ZIP', 'ZIP central directory is outside the archive');
  }

  const output: CentralEntry[] = [];
  let pointer = centralOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    ensureReadable(archive, pointer, 46, 'central-directory entry');
    if (archive.readUInt32LE(pointer) !== 0x02014b50) {
      throw new ArchiveValidationError('INVALID_ZIP', 'Invalid central-directory entry signature');
    }
    const madeBy = archive.readUInt16LE(pointer + 4);
    const flags = archive.readUInt16LE(pointer + 8);
    const compressionMethod = archive.readUInt16LE(pointer + 10);
    const checksum = archive.readUInt32LE(pointer + 16);
    const compressedSize = archive.readUInt32LE(pointer + 20);
    const uncompressedSize = archive.readUInt32LE(pointer + 24);
    const filenameLength = archive.readUInt16LE(pointer + 28);
    const extraLength = archive.readUInt16LE(pointer + 30);
    const entryCommentLength = archive.readUInt16LE(pointer + 32);
    const externalAttributes = archive.readUInt32LE(pointer + 38);
    const localHeaderOffset = archive.readUInt32LE(pointer + 42);
    const totalLength = 46 + filenameLength + extraLength + entryCommentLength;
    ensureReadable(archive, pointer, totalLength, 'central-directory entry');
    if ((flags & 0x1) !== 0) {
      throw new ArchiveValidationError('ENCRYPTED_ENTRY', 'Encrypted ZIP entries are unsupported');
    }
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) {
      throw new ArchiveValidationError('ZIP64_UNSUPPORTED', 'ZIP64 entries are unsupported');
    }
    const filenameBytes = archive.subarray(pointer + 46, pointer + 46 + filenameLength);
    const filename = decodeFilename(filenameBytes);
    const directory = filename.endsWith('/') || (externalAttributes & 0x10) !== 0;
    const path = validateArchivePath(filename, directory, limits);
    rejectSpecialUnixFile(madeBy >>> 8, externalAttributes, directory, path);
    if (!directory && compressionMethod !== 0 && compressionMethod !== 8) {
      throw new ArchiveValidationError(
        'UNSUPPORTED_COMPRESSION',
        `Unsupported ZIP compression method ${compressionMethod} for ${path}`,
      );
    }
    output.push({
      path,
      directory,
      compressedSize,
      uncompressedSize,
      compressionMethod,
      crc32: checksum,
      localHeaderOffset,
      generalPurposeFlags: flags,
      externalAttributes,
      madeByHost: madeBy >>> 8,
    });
    pointer += totalLength;
  }
  if (pointer !== centralOffset + centralSize) {
    throw new ArchiveValidationError('INVALID_ZIP', 'ZIP central-directory size is inconsistent');
  }
  return output;
}

function extractCentralEntry(archive: Buffer, entry: CentralEntry, maximumOutput: number): Buffer {
  const offset = entry.localHeaderOffset;
  ensureReadable(archive, offset, 30, `local header for ${entry.path}`);
  if (archive.readUInt32LE(offset) !== 0x04034b50) {
    throw new ArchiveValidationError('INVALID_ZIP', `Invalid local header for ${entry.path}`);
  }
  const localFlags = archive.readUInt16LE(offset + 6);
  const localMethod = archive.readUInt16LE(offset + 8);
  const filenameLength = archive.readUInt16LE(offset + 26);
  const extraLength = archive.readUInt16LE(offset + 28);
  if ((localFlags & 0x1) !== 0 || localMethod !== entry.compressionMethod) {
    throw new ArchiveValidationError('HEADER_MISMATCH', `Local header mismatch for ${entry.path}`);
  }
  ensureReadable(archive, offset, 30 + filenameLength + extraLength, `local header for ${entry.path}`);
  const localName = decodeFilename(archive.subarray(offset + 30, offset + 30 + filenameLength));
  if (localName.normalize('NFC').replace(/\/$/, '') !== entry.path) {
    throw new ArchiveValidationError('HEADER_MISMATCH', `Local filename mismatch for ${entry.path}`);
  }
  const dataStart = offset + 30 + filenameLength + extraLength;
  ensureReadable(archive, dataStart, entry.compressedSize, `compressed data for ${entry.path}`);
  const compressed = archive.subarray(dataStart, dataStart + entry.compressedSize);
  if (entry.compressionMethod === 0) {
    return Buffer.from(compressed);
  }
  try {
    return inflateRawSync(compressed, { maxOutputLength: maximumOutput });
  } catch (error) {
    throw new ArchiveValidationError(
      'DECOMPRESSION_FAILED',
      `Could not safely decompress ${entry.path}: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
  }
}

function validateArchivePath(
  originalPath: string,
  directory: boolean,
  limits: ArchiveLimits,
): string {
  const normalized = originalPath.normalize('NFC');
  if (
    normalized.length === 0 ||
    normalized.length > limits.maximumPathLength ||
    /[\u0000-\u001f\u007f-\u009f]/.test(normalized) ||
    normalized.includes('\\') ||
    normalized.startsWith('/') ||
    /^[A-Za-z]:/.test(normalized)
  ) {
    throw new ArchiveValidationError('UNSAFE_PATH', `Unsafe archive path: ${printablePath(originalPath)}`);
  }
  const withoutTrailingSlash = directory ? normalized.replace(/\/+$/, '') : normalized;
  const components = withoutTrailingSlash.split('/');
  if (
    withoutTrailingSlash.length === 0 ||
    components.length > limits.maximumPathDepth ||
    components.some((component) => component === '' || component === '.' || component === '..')
  ) {
    throw new ArchiveValidationError('UNSAFE_PATH', `Unsafe archive path: ${printablePath(originalPath)}`);
  }
  return withoutTrailingSlash;
}

function rejectSpecialUnixFile(
  madeByHost: number,
  externalAttributes: number,
  directory: boolean,
  path: string,
): void {
  if (madeByHost !== 3) {
    return;
  }
  const mode = externalAttributes >>> 16;
  const fileType = mode & 0xf000;
  if (fileType === 0xa000) {
    throw new ArchiveValidationError('SYMLINK_REJECTED', `Symbolic link is not allowed: ${path}`);
  }
  if (
    fileType !== 0 &&
    fileType !== 0x8000 &&
    !(directory && fileType === 0x4000)
  ) {
    throw new ArchiveValidationError('SPECIAL_FILE_REJECTED', `Special file is not allowed: ${path}`);
  }
}

function decodeFilename(value: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(value);
  } catch {
    throw new ArchiveValidationError('INVALID_FILENAME', 'ZIP filename is not valid UTF-8');
  }
}

function ensureReadable(buffer: Buffer, offset: number, length: number, description: string): void {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset + length > buffer.byteLength
  ) {
    throw new ArchiveValidationError('TRUNCATED_ZIP', `Truncated ${description}`);
  }
}

function findEndOfCentralDirectory(buffer: Buffer): number {
  const minimum = Math.max(0, buffer.byteLength - 22 - 0xffff);
  for (let offset = buffer.byteLength - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      return offset;
    }
  }
  return -1;
}

function normalizedCollisionKey(path: string): string {
  return path.normalize('NFC').toLocaleLowerCase('en-US');
}

function addDuplicateSuffix(path: string, suffix: number): string {
  const slash = path.lastIndexOf('/');
  const directory = slash < 0 ? '' : path.slice(0, slash + 1);
  const filename = slash < 0 ? path : path.slice(slash + 1);
  const dot = filename.lastIndexOf('.');
  if (dot <= 0) {
    return `${directory}${filename}~${suffix}`;
  }
  return `${directory}${filename.slice(0, dot)}~${suffix}${filename.slice(dot)}`;
}

function printablePath(path: string): string {
  return JSON.stringify(path).slice(0, 1_100);
}

function validateLimits(limits: ArchiveLimits): void {
  const integerValues = [
    limits.maximumFiles,
    limits.maximumFileBytes,
    limits.maximumExpandedBytes,
    limits.maximumPathDepth,
    limits.maximumPathLength,
    limits.maximumArchiveNesting,
  ];
  if (integerValues.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error('Archive limits must be non-negative safe integers');
  }
  if (!Number.isFinite(limits.maximumCompressionRatio) || limits.maximumCompressionRatio < 1) {
    throw new Error('maximumCompressionRatio must be at least 1');
  }
}

let crcTable: Uint32Array | undefined;

function crc32(bytes: Uint8Array): number {
  const table = crcTable ?? (crcTable = createCrcTable());
  let checksum = 0xffffffff;
  for (const byte of bytes) {
    checksum = table[(checksum ^ byte) & 0xff]! ^ (checksum >>> 8);
  }
  return (checksum ^ 0xffffffff) >>> 0;
}

function createCrcTable(): Uint32Array {
  const table = new Uint32Array(256);
  for (let value = 0; value < 256; value += 1) {
    let item = value;
    for (let bit = 0; bit < 8; bit += 1) {
      item = (item & 1) !== 0 ? 0xedb88320 ^ (item >>> 1) : item >>> 1;
    }
    table[value] = item >>> 0;
  }
  return table;
}
