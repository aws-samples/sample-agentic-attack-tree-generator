export const THREATFOREST_REPORT_SCHEMA_VERSION = 1;
export const THREATFOREST_REPORT_MANIFEST = 'threatforest_report.json';
export const THREATFOREST_REPORT_CONTENT_TYPE = 'application/zip';

export interface ThreatforestReportVersion {
  readonly id: string;
  readonly entries: readonly {
    readonly path: string;
    readonly body: Uint8Array;
  }[];
}

export interface ThreatforestReportArchiveOptions {
  readonly applicationId: string;
  readonly applicationName: string;
  readonly applicationSlug: string;
  readonly applicationDescription: string;
  readonly applicationCreatedAt: string;
  readonly businessContext?: Readonly<Record<string, unknown>> | null;
  readonly versions: readonly ThreatforestReportVersion[];
  readonly includeScannerContext: boolean;
  readonly exportedAt: string;
  readonly threatforestVersion?: string;
}

interface ZipEntry {
  readonly name: string;
  readonly data: Buffer;
  readonly crc: number;
  readonly offset: number;
}

export function buildThreatforestReportArchive(
  options: ThreatforestReportArchiveOptions,
): Buffer {
  if (options.versions.length === 0) {
    throw new Error('a ThreatForest report must contain at least one version');
  }
  const zip = new ZipWriter();
  const versionIds = options.versions.map((version) =>
    safePathSegment(version.id, 'version ID'),
  );
  zip.addJson(THREATFOREST_REPORT_MANIFEST, {
    schema_version: THREATFOREST_REPORT_SCHEMA_VERSION,
    exported_at: options.exportedAt,
    exported_by_threatforest: options.threatforestVersion ?? '',
    source_app_id: options.applicationId,
    source_app_name: options.applicationName,
    source_app_slug: safePathSegment(
      options.applicationSlug,
      'application slug',
    ),
    include_scanner_context: options.includeScannerContext,
    scope:
      options.versions.length === 1
        ? 'single-version'
        : 'full-application',
    versions: versionIds,
  });
  zip.addJson('application/metadata.json', {
    name: options.applicationName,
    description: options.applicationDescription,
    created_at: options.applicationCreatedAt,
  });
  if (options.businessContext !== null && options.businessContext !== undefined) {
    zip.addJson('application/business_context.json', options.businessContext);
  }

  for (const [index, version] of options.versions.entries()) {
    const versionId = versionIds[index]!;
    for (const entry of version.entries) {
      const relativePath = safeRelativePath(entry.path);
      if (
        !options.includeScannerContext &&
        relativePath === 'state/scanner_context.json'
      ) {
        continue;
      }
      zip.addFile(
        `versions/${versionId}/${relativePath}`,
        Buffer.from(entry.body),
      );
    }
  }
  return zip.finish();
}

function safePathSegment(value: string, label: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized === '.' ||
    normalized === '..' ||
    normalized.includes('/') ||
    normalized.includes('\\') ||
    normalized.includes('\0')
  ) {
    throw new Error(`${label} is not a safe archive path segment`);
  }
  return normalized;
}

function safeRelativePath(value: string): string {
  const normalized = value.replaceAll('\\', '/').replace(/^\/+/, '');
  const segments = normalized.split('/');
  if (
    normalized.length === 0 ||
    segments.some(
      (segment) =>
        segment.length === 0 ||
        segment === '.' ||
        segment === '..' ||
        segment.includes('\0'),
    )
  ) {
    throw new Error(`invalid ThreatForest report entry path: ${value}`);
  }
  return normalized;
}

function sortedJson(value: unknown): string {
  return `${JSON.stringify(sortKeysDeep(value), null, 2)}\n`;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

const CRC_TABLE: readonly number[] = (() => {
  const table: number[] = [];
  for (let n = 0; n < 256; n += 1) {
    let value = n;
    for (let bit = 0; bit < 8; bit += 1) {
      value =
        (value & 1) === 1
          ? 0xedb88320 ^ (value >>> 1)
          : value >>> 1;
    }
    table[n] = value >>> 0;
  }
  return table;
})();

function crc32(buffer: Buffer): number {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = CRC_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

class ZipWriter {
  readonly #entries: ZipEntry[] = [];
  readonly #chunks: Buffer[] = [];
  readonly #names = new Set<string>();
  #offset = 0;

  addJson(name: string, value: unknown): void {
    this.addFile(name, Buffer.from(sortedJson(value), 'utf8'));
  }

  addFile(name: string, data: Buffer): void {
    const safeName = safeRelativePath(name);
    if (this.#names.has(safeName)) {
      throw new Error(`duplicate ThreatForest report entry: ${safeName}`);
    }
    const nameBuffer = Buffer.from(safeName, 'utf8');
    if (nameBuffer.byteLength > 0xffff || data.byteLength > 0xffffffff) {
      throw new Error(`ThreatForest report entry is too large: ${safeName}`);
    }
    this.#names.add(safeName);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.byteLength, 18);
    local.writeUInt32LE(data.byteLength, 22);
    local.writeUInt16LE(nameBuffer.byteLength, 26);
    local.writeUInt16LE(0, 28);

    const offset = this.#offset;
    this.#push(local);
    this.#push(nameBuffer);
    this.#push(data);
    this.#entries.push({ name: safeName, data, crc, offset });
  }

  finish(): Buffer {
    if (this.#entries.length > 0xffff) {
      throw new Error('ThreatForest report contains too many entries');
    }
    const centralStart = this.#offset;
    for (const entry of this.#entries) {
      const nameBuffer = Buffer.from(entry.name, 'utf8');
      const central = Buffer.alloc(46);
      central.writeUInt32LE(0x02014b50, 0);
      central.writeUInt16LE(20, 4);
      central.writeUInt16LE(20, 6);
      central.writeUInt16LE(0, 8);
      central.writeUInt16LE(0, 10);
      central.writeUInt16LE(0, 12);
      central.writeUInt16LE(0, 14);
      central.writeUInt32LE(entry.crc, 16);
      central.writeUInt32LE(entry.data.byteLength, 20);
      central.writeUInt32LE(entry.data.byteLength, 24);
      central.writeUInt16LE(nameBuffer.byteLength, 28);
      central.writeUInt16LE(0, 30);
      central.writeUInt16LE(0, 32);
      central.writeUInt16LE(0, 34);
      central.writeUInt16LE(0, 36);
      central.writeUInt32LE(0, 38);
      central.writeUInt32LE(entry.offset, 42);
      this.#push(central);
      this.#push(nameBuffer);
    }
    const centralSize = this.#offset - centralStart;
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(0, 4);
    end.writeUInt16LE(0, 6);
    end.writeUInt16LE(this.#entries.length, 8);
    end.writeUInt16LE(this.#entries.length, 10);
    end.writeUInt32LE(centralSize, 12);
    end.writeUInt32LE(centralStart, 16);
    end.writeUInt16LE(0, 20);
    this.#push(end);
    return Buffer.concat(this.#chunks);
  }

  #push(buffer: Buffer): void {
    this.#chunks.push(buffer);
    this.#offset += buffer.byteLength;
  }
}
