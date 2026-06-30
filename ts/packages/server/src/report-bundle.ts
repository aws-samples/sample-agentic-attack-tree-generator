/**
 * Build `.tfreport` bundles for export — TS port of `src/server/report_bundle.py`.
 *
 * A `.tfreport` is a plain zip with this layout:
 *
 *   threatforest_report.json          ← manifest (always at root)
 *   application/metadata.json          ← name + description, `path` stripped
 *   application/business_context.json  ← only when a v2 record exists
 *   versions/<YYYYMMDD_HHMMSS>/output/{threatforest_data.json,threat_model_report.md,attack_trees_dashboard.html}
 *   versions/<YYYYMMDD_HHMMSS>/state/{threats,attack_trees,ttp_mappings,mitigations}.json (+scanner_context.json when included)
 *   versions/<YYYYMMDD_HHMMSS>/{mitigation_overrides.json,run_metadata.json}
 *
 * The bundle is built in-memory and returned as a Buffer so the route can stream
 * it without touching disk again.
 *
 * NOTE: Python used the stdlib `zipfile` (ZIP_DEFLATED). Node's stdlib has no zip
 * writer, so this implements a minimal STORE-method ZIP writer (no compression).
 * The on-the-wire layout + entry paths are byte-identical; only the compression
 * method byte differs, which every unzip implementation (incl. the importer)
 * handles transparently.
 */
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { ApplicationRepository } from './applications.js';
import type { ApplicationRegistry } from './registry.js';

export const SCHEMA_VERSION = 1;
export const MANIFEST_FILENAME = 'threatforest_report.json';

const OUTPUT_FILES = [
  'threatforest_data.json',
  'threat_model_report.md',
  'attack_trees_dashboard.html',
] as const;
const STATE_FILES = [
  'threats.json',
  'attack_trees.json',
  'ttp_mappings.json',
  'mitigations.json',
] as const;
const RUN_DIR_FILES = ['mitigation_overrides.json', 'run_metadata.json'] as const;

export class ReportBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReportBundleError';
  }
}

export interface BuildReportBundleOptions {
  folderId: string;
  versionIds: string[];
  includeScannerContext: boolean;
  registry: ApplicationRegistry;
  appRepository?: ApplicationRepository | null;
  threatforestVersion?: string;
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function loadJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Recursively sort object keys (matches Python `sort_keys=True`). */
function sortedJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value), null, 2);
}
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/**
 * Build a `.tfreport` zip and return its bytes.
 *
 * @throws ReportBundleError if the folder doesn't resolve, no versions are
 *   supplied, or a requested version has no completed output.
 */
export function buildReportBundle(opts: BuildReportBundleOptions): Buffer {
  const {
    folderId,
    versionIds,
    includeScannerContext,
    registry,
    appRepository = null,
    threatforestVersion = '',
  } = opts;

  if (versionIds.length === 0) {
    throw new ReportBundleError('At least one version_id is required.');
  }

  const projectDir = registry.getProjectDir(folderId);
  if (projectDir === null) {
    throw new ReportBundleError(`Application folder '${folderId}' not found.`);
  }

  const projectMeta = loadJson(join(projectDir, 'metadata.json')) ?? {};

  const persistentApp = appRepository ? appRepository.findByRunDirName(folderId) : null;
  const sourceAppId = persistentApp ? persistentApp.id : folderId;
  const sourceAppName = persistentApp
    ? persistentApp.name
    : ((projectMeta.name as string | undefined) ?? folderId);

  const zip = new ZipWriter();

  // ─── manifest ──────────────────────────────────────────
  const scope = versionIds.length === 1 ? 'single-version' : 'full-application';
  const manifest = {
    schema_version: SCHEMA_VERSION,
    exported_at: new Date().toISOString(),
    exported_by_threatforest: threatforestVersion,
    source_app_id: sourceAppId,
    source_app_name: sourceAppName,
    source_app_slug: folderId,
    include_scanner_context: includeScannerContext,
    scope,
    versions: [...versionIds],
  };
  zip.addText(MANIFEST_FILENAME, sortedJson(manifest));

  // ─── application/ ──────────────────────────────────────
  const appMetadata = {
    name: sourceAppName,
    description: (projectMeta.description as string | undefined) ?? '',
    created_at: (projectMeta.created_at as string | undefined) ?? '',
  };
  zip.addText('application/metadata.json', sortedJson(appMetadata));
  if (persistentApp !== null) {
    zip.addText('application/business_context.json', sortedJson(persistentApp.business_context));
  }

  // ─── versions/ ─────────────────────────────────────────
  for (const versionId of versionIds) {
    const runDir = registry.getVersionRunDir(folderId, versionId);
    if (runDir === null) {
      throw new ReportBundleError(
        `Version '${versionId}' not found for application '${folderId}'.`,
      );
    }
    const dataFile = join(runDir, 'output', 'threatforest_data.json');
    if (!isFile(dataFile)) {
      throw new ReportBundleError(
        `Version '${versionId}' has no completed output and cannot be exported.`,
      );
    }

    const base = `versions/${versionId}`;

    for (const fname of OUTPUT_FILES) {
      const src = join(runDir, 'output', fname);
      if (isFile(src)) zip.addFile(`${base}/output/${fname}`, readFileSync(src));
    }
    for (const fname of STATE_FILES) {
      const src = join(runDir, 'state', fname);
      if (isFile(src)) zip.addFile(`${base}/state/${fname}`, readFileSync(src));
    }
    if (includeScannerContext) {
      const ctx = join(runDir, 'state', 'scanner_context.json');
      if (isFile(ctx)) zip.addFile(`${base}/state/scanner_context.json`, readFileSync(ctx));
    }
    for (const fname of RUN_DIR_FILES) {
      const src = join(runDir, fname);
      if (isFile(src)) zip.addFile(`${base}/${fname}`, readFileSync(src));
    }
  }

  return zip.finish();
}

// ---------------------------------------------------------------------------
// Minimal ZIP writer (STORE method). Produces a standards-compliant archive
// without a third-party dependency. CRC-32 computed per entry.
// ---------------------------------------------------------------------------

interface ZipEntry {
  name: string;
  data: Buffer;
  crc: number;
  offset: number;
}

const CRC_TABLE: number[] = (() => {
  const table: number[] = [];
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    c = CRC_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

class ZipWriter {
  private readonly entries: ZipEntry[] = [];
  private readonly chunks: Buffer[] = [];
  private offset = 0;

  addText(name: string, content: string): void {
    this.addFile(name, Buffer.from(content, 'utf-8'));
  }

  addFile(name: string, data: Buffer): void {
    const crc = crc32(data);
    const nameBuf = Buffer.from(name, 'utf-8');
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // method: STORE
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0, 12); // mod date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra length

    const entryOffset = this.offset;
    this.push(local);
    this.push(nameBuf);
    this.push(data);

    this.entries.push({ name, data, crc, offset: entryOffset });
  }

  finish(): Buffer {
    const centralStart = this.offset;
    for (const e of this.entries) {
      const nameBuf = Buffer.from(e.name, 'utf-8');
      const central = Buffer.alloc(46);
      central.writeUInt32LE(0x02014b50, 0); // central dir signature
      central.writeUInt16LE(20, 4); // version made by
      central.writeUInt16LE(20, 6); // version needed
      central.writeUInt16LE(0, 8); // flags
      central.writeUInt16LE(0, 10); // method: STORE
      central.writeUInt16LE(0, 12); // mod time
      central.writeUInt16LE(0, 14); // mod date
      central.writeUInt32LE(e.crc, 16);
      central.writeUInt32LE(e.data.length, 20);
      central.writeUInt32LE(e.data.length, 24);
      central.writeUInt16LE(nameBuf.length, 28);
      central.writeUInt16LE(0, 30); // extra length
      central.writeUInt16LE(0, 32); // comment length
      central.writeUInt16LE(0, 34); // disk number
      central.writeUInt16LE(0, 36); // internal attrs
      central.writeUInt32LE(0, 38); // external attrs
      central.writeUInt32LE(e.offset, 42);
      this.push(central);
      this.push(nameBuf);
    }
    const centralSize = this.offset - centralStart;

    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); // end of central dir signature
    eocd.writeUInt16LE(0, 4); // disk number
    eocd.writeUInt16LE(0, 6); // central dir disk
    eocd.writeUInt16LE(this.entries.length, 8);
    eocd.writeUInt16LE(this.entries.length, 10);
    eocd.writeUInt32LE(centralSize, 12);
    eocd.writeUInt32LE(centralStart, 16);
    eocd.writeUInt16LE(0, 20); // comment length
    this.push(eocd);

    return Buffer.concat(this.chunks);
  }

  private push(buf: Buffer): void {
    this.chunks.push(buf);
    this.offset += buf.length;
  }
}
