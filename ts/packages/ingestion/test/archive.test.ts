import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync } from 'fflate';
import {
  ArchiveValidationError,
  SafeZipExtractor,
  inspectZipEntries,
} from '../src/index.js';

test('safe archive extraction returns deterministic paths and bytes', () => {
  const zip = zipSync(
    {
      'src/index.ts': Buffer.from('export const value = 1;\n'),
      'README.md': Buffer.from('# Example\n'),
    },
    { level: 0 },
  );
  const result = new SafeZipExtractor().extract(zip);
  assert.deepEqual(
    result.entries.map((entry) => entry.path),
    ['src/index.ts', 'README.md'],
  );
  assert.equal(Buffer.from(result.entries[0]!.bytes).toString(), 'export const value = 1;\n');
  assert.equal(inspectZipEntries(zip).length, 2);
});

test('archives reject traversal, absolute paths, controls, symlinks, and deep paths', () => {
  for (const path of ['../escape.txt', '/absolute.txt', 'C:/drive.txt', 'bad\u0001name.txt']) {
    const zip = zipSync({ [path]: Buffer.from('bad') }, { level: 0 });
    assert.throws(
      () => new SafeZipExtractor().extract(zip),
      (error: unknown) => error instanceof ArchiveValidationError && error.code === 'UNSAFE_PATH',
      path,
    );
  }

  const symlink = markFirstEntryAsSymlink(
    zipSync({ 'link.txt': Buffer.from('../target') }, { level: 0 }),
  );
  assert.throws(
    () => new SafeZipExtractor().extract(symlink),
    (error: unknown) => error instanceof ArchiveValidationError && error.code === 'SYMLINK_REJECTED',
  );

  const deep = zipSync({ 'a/b/c/d.txt': Buffer.from('deep') }, { level: 0 });
  assert.throws(
    () => new SafeZipExtractor({ maximumPathDepth: 3 }).extract(deep),
    /Unsafe archive path/,
  );
});

test('archive limits reject file count, per-file size, expanded total, ratio, and nesting', () => {
  const twoFiles = zipSync({ 'a.txt': Buffer.from('a'), 'b.txt': Buffer.from('b') }, { level: 0 });
  assert.throws(
    () => new SafeZipExtractor({ maximumFiles: 1 }).extract(twoFiles),
    code('FILE_COUNT_EXCEEDED'),
  );

  const large = zipSync({ 'large.txt': Buffer.alloc(20, 1) }, { level: 0 });
  assert.throws(
    () => new SafeZipExtractor({ maximumFileBytes: 10 }).extract(large),
    code('FILE_SIZE_EXCEEDED'),
  );
  assert.throws(
    () => new SafeZipExtractor({ maximumExpandedBytes: 10 }).extract(large),
    code('EXPANDED_SIZE_EXCEEDED'),
  );

  const compressed = zipSync({ 'zeros.txt': Buffer.alloc(10_000) }, { level: 9 });
  assert.throws(
    () => new SafeZipExtractor({ maximumCompressionRatio: 2 }).extract(compressed),
    code('COMPRESSION_RATIO_EXCEEDED'),
  );

  const nested = zipSync(
    { 'inner.zip': zipSync({ 'leaf.txt': Buffer.from('leaf') }, { level: 0 }) },
    { level: 0 },
  );
  assert.throws(
    () => new SafeZipExtractor({ maximumArchiveNesting: 0 }).extract(nested),
    code('ARCHIVE_NESTING_EXCEEDED'),
  );
});

test('duplicate handling is explicit and deterministic', () => {
  const duplicate = zipSync(
    {
      'Readme.md': Buffer.from('first'),
      'README.md': Buffer.from('second'),
    },
    { level: 0 },
  );
  assert.throws(
    () => new SafeZipExtractor().extract(duplicate),
    code('DUPLICATE_PATH'),
  );
  const kept = new SafeZipExtractor({ duplicatePolicy: 'keep-first' }).extract(duplicate);
  assert.equal(kept.entries.length, 1);
  assert.match(kept.warnings[0]!, /Ignored duplicate/);
  const renamed = new SafeZipExtractor({ duplicatePolicy: 'rename' }).extract(duplicate);
  assert.deepEqual(
    renamed.entries.map((entry) => entry.path),
    ['Readme.md', 'README~2.md'],
  );
});

test('archive corruption is detected by CRC verification', () => {
  const zip = Buffer.from(zipSync({ 'plain.txt': Buffer.from('original') }, { level: 0 }));
  const localNameLength = zip.readUInt16LE(26);
  const localExtraLength = zip.readUInt16LE(28);
  const dataOffset = 30 + localNameLength + localExtraLength;
  zip[dataOffset] = zip[dataOffset]! ^ 0xff;
  assert.throws(
    () => new SafeZipExtractor().extract(zip),
    code('CHECKSUM_MISMATCH'),
  );
});

function code(expected: string): (error: unknown) => boolean {
  return (error: unknown) =>
    error instanceof ArchiveValidationError && error.code === expected;
}

function markFirstEntryAsSymlink(input: Uint8Array): Uint8Array {
  const zip = Buffer.from(input);
  const central = findSignature(zip, 0x02014b50);
  zip.writeUInt16LE((3 << 8) | 20, central + 4);
  zip.writeUInt32LE((0xa1ff << 16) >>> 0, central + 38);
  return zip;
}

function findSignature(buffer: Buffer, signature: number): number {
  for (let offset = 0; offset <= buffer.byteLength - 4; offset += 1) {
    if (buffer.readUInt32LE(offset) === signature) {
      return offset;
    }
  }
  throw new Error('ZIP signature not found');
}
