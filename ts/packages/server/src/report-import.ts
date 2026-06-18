/**
 * Process `.tfreport` bundles dropped into `.threatforest/imports/`.
 * TS port of `src/server/report_import.py`.
 *
 * Called from `ApplicationRegistry.discoverApplications` (passive drop-folder
 * import) and from the `/api/imports/tfreport` upload route. Each bundle is
 * opened, validated, and extracted. Successful bundles move to
 * `imports/processed/`; failures to `imports/failed/` with a sibling
 * `.error.txt`. The function never throws — every error is captured into the
 * returned ImportResult list so application listing keeps working.
 *
 * NOTE: Node's stdlib has no zip reader, so this ships a minimal one that
 * handles both STORE (method 0, written by report-bundle.ts) and DEFLATE
 * (method 8, written by the Python exporter) entries — covering every bundle
 * either side produces.
 */
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import type { ApplicationRegistry } from './registry.js';
import { MANIFEST_FILENAME, SCHEMA_VERSION } from './report-bundle.js';

export interface ImportResult {
  bundle: string;
  status: string; // "imported" | "merged" | "skipped" | "failed"
  folder_name: string | null;
  versions_added: string[];
  versions_skipped: string[];
  error: string | null;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}
function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
function readMeta(folder: string): Record<string, unknown> {
  const metaFile = join(folder, 'metadata.json');
  if (!isFile(metaFile)) return {};
  try {
    const data: unknown = JSON.parse(readFileSync(metaFile, 'utf-8'));
    return typeof data === 'object' && data !== null && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

/**
 * Process every `*.tfreport` in `importsDir`. Successful bundles are moved to
 * `processed/`; failed ones to `failed/` with a sibling error file. Never throws.
 */
export function processPendingImports(
  importsDir: string,
  registry: ApplicationRegistry,
): ImportResult[] {
  if (!isDir(importsDir)) return [];

  const processedDir = join(importsDir, 'processed');
  const failedDir = join(importsDir, 'failed');

  const results: ImportResult[] = [];
  const names = readdirSync(importsDir).sort();
  for (const name of names) {
    const bundle = join(importsDir, name);
    if (isDir(bundle) || !name.endsWith('.tfreport')) continue;

    let result: ImportResult;
    try {
      result = importBundle(bundle, name, registry);
    } catch (err) {
      result = {
        bundle: name,
        status: 'failed',
        folder_name: null,
        versions_added: [],
        versions_skipped: [],
        error: `Unhandled error: ${(err as Error).message}`,
      };
    }

    if (result.status === 'failed') {
      mkdirSync(failedDir, { recursive: true });
      try {
        renameSync(bundle, join(failedDir, name));
        writeFileSync(join(failedDir, `${name}.error.txt`), result.error ?? 'Unknown error', 'utf-8');
      } catch {
        /* best-effort move */
      }
    } else {
      mkdirSync(processedDir, { recursive: true });
      try {
        renameSync(bundle, join(processedDir, name));
      } catch {
        /* best-effort move */
      }
    }

    results.push(result);
  }

  return results;
}

function importBundle(
  bundlePath: string,
  bundleName: string,
  registry: ApplicationRegistry,
): ImportResult {
  let entries: Map<string, Buffer>;
  try {
    entries = readZip(readFileSync(bundlePath));
  } catch {
    return failed(bundleName, 'File is not a valid zip archive.');
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = readManifest(entries);
    validateZipPaths(entries);
  } catch (err) {
    return failed(bundleName, (err as Error).message);
  }

  const [, folderName, mode] = resolveTargetFolder(manifest, registry);
  if (folderName === null) {
    return failed(
      bundleName,
      'Cannot disambiguate target folder — every candidate name is taken. ' +
        'Rename the source application and re-export.',
    );
  }

  const targetDir = join(registry.runsRoot, folderName);
  const [versionsAdded, versionsSkipped] = extractVersions(entries, manifest, targetDir);
  const bundleAppMeta = readBundleApplicationMetadata(entries);
  extractBusinessContext(entries, targetDir);
  writeImportedMetadata(targetDir, manifest, bundleAppMeta, mode);

  if (versionsAdded.length === 0 && versionsSkipped.length > 0) {
    return {
      bundle: bundleName,
      status: 'skipped',
      folder_name: folderName,
      versions_added: [],
      versions_skipped: versionsSkipped,
      error: null,
    };
  }
  return {
    bundle: bundleName,
    status: mode === 'merge' ? 'merged' : 'imported',
    folder_name: folderName,
    versions_added: versionsAdded,
    versions_skipped: versionsSkipped,
    error: null,
  };
}

function failed(bundle: string, error: string): ImportResult {
  return { bundle, status: 'failed', folder_name: null, versions_added: [], versions_skipped: [], error };
}

// ─── manifest + zip safety ────────────────────────────────────────

function readManifest(entries: Map<string, Buffer>): Record<string, unknown> {
  const raw = entries.get(MANIFEST_FILENAME);
  if (raw === undefined) {
    throw new Error(`Bundle is missing ${MANIFEST_FILENAME} — not a ThreatForest report.`);
  }
  let manifest: unknown;
  try {
    manifest = JSON.parse(raw.toString('utf-8'));
  } catch (err) {
    throw new Error(`Manifest is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
    throw new Error('Manifest must be a JSON object.');
  }
  const m = manifest as Record<string, unknown>;
  if (m.schema_version !== SCHEMA_VERSION) {
    throw new Error(
      `Unsupported schema_version ${JSON.stringify(m.schema_version)}; this server expects ${SCHEMA_VERSION}.`,
    );
  }
  if (!m.source_app_slug) {
    throw new Error('Manifest is missing source_app_slug.');
  }
  if (!Array.isArray(m.versions) || m.versions.length === 0) {
    throw new Error('Manifest has no versions to import.');
  }
  return m;
}

function validateZipPaths(entries: Map<string, Buffer>): void {
  for (const name of entries.keys()) {
    if (name.startsWith('/') || name.startsWith('\\')) {
      throw new Error(`Bundle contains absolute path: ${JSON.stringify(name)}`);
    }
    const parts = name.replace(/\\/g, '/').split('/');
    if (parts.some((p) => p === '..')) {
      throw new Error(`Bundle contains parent-directory escape: ${JSON.stringify(name)}`);
    }
  }
}

// ─── target folder resolution ─────────────────────────────────────

function resolveTargetFolder(
  manifest: Record<string, unknown>,
  registry: ApplicationRegistry,
): [string, string | null, string] {
  const runsRoot = registry.runsRoot;
  mkdirSync(runsRoot, { recursive: true });

  const sourceSlug = manifest.source_app_slug as string;
  const sourceAppId = manifest.source_app_id as string | undefined;
  const scope = (manifest.scope as string | undefined) ?? 'single-version';

  // 1. Same-source-app merge.
  if (sourceAppId && scope === 'single-version') {
    for (const child of readdirSync(runsRoot)) {
      const childPath = join(runsRoot, child);
      if (!isDir(childPath)) continue;
      const meta = readMeta(childPath);
      if (meta.imported_from_app_id === sourceAppId) {
        return [sourceSlug, child, 'merge'];
      }
    }
  }

  // 2. Slug is free.
  if (!existsSync(join(runsRoot, sourceSlug))) {
    return [sourceSlug, sourceSlug, 'new'];
  }

  // 3. Suffix with `--imported`, then `--imported-2`, … up to 99.
  const base = `${sourceSlug}--imported`;
  if (!existsSync(join(runsRoot, base))) {
    return [sourceSlug, base, 'new'];
  }
  for (let n = 2; n < 100; n += 1) {
    const candidate = `${base}-${n}`;
    if (!existsSync(join(runsRoot, candidate))) {
      return [sourceSlug, candidate, 'new'];
    }
  }
  return [sourceSlug, null, 'new'];
}

// ─── extraction ───────────────────────────────────────────────────

function extractVersions(
  entries: Map<string, Buffer>,
  manifest: Record<string, unknown>,
  targetDir: string,
): [string[], string[]] {
  mkdirSync(targetDir, { recursive: true });

  const declared = (manifest.versions as string[] | undefined) ?? [];
  const added: string[] = [];
  const skipped: string[] = [];

  for (const versionId of declared) {
    const versionDir = join(targetDir, versionId);
    if (existsSync(versionDir)) {
      skipped.push(versionId);
      continue;
    }
    const prefix = `versions/${versionId}/`;
    const matching = [...entries.keys()].filter((n) => n.startsWith(prefix) && !n.endsWith('/'));
    if (matching.length === 0) {
      skipped.push(versionId);
      continue;
    }
    mkdirSync(versionDir, { recursive: true });
    for (const entry of matching) {
      const relative = entry.slice(prefix.length);
      const dest = join(versionDir, relative);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, entries.get(entry)!);
    }
    added.push(versionId);
  }

  return [added, skipped];
}

function readBundleApplicationMetadata(entries: Map<string, Buffer>): Record<string, unknown> {
  const raw = entries.get('application/metadata.json');
  if (raw === undefined) return {};
  try {
    const data: unknown = JSON.parse(raw.toString('utf-8'));
    return typeof data === 'object' && data !== null && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function extractBusinessContext(entries: Map<string, Buffer>, targetDir: string): void {
  const raw = entries.get('application/business_context.json');
  if (raw === undefined) return;
  let data: unknown;
  try {
    data = JSON.parse(raw.toString('utf-8'));
  } catch {
    return;
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return;
  mkdirSync(targetDir, { recursive: true });
  writeFileSync(
    join(targetDir, 'business_context.json'),
    JSON.stringify(sortKeysDeep(data), null, 2),
    'utf-8',
  );
}

function writeImportedMetadata(
  targetDir: string,
  manifest: Record<string, unknown>,
  bundleAppMeta: Record<string, unknown>,
  mode: string,
): void {
  const metaFile = join(targetDir, 'metadata.json');
  const now = new Date().toISOString();
  const existing = mode === 'merge' ? readMeta(targetDir) : {};

  const meta: Record<string, unknown> = {
    ...existing,
    name: (manifest.source_app_name as string | undefined) ?? existing.name ?? 'Imported app',
    description: existing.description || bundleAppMeta.description || '',
    imported_from_app_id: manifest.source_app_id ?? '',
    imported_from_app_name:
      (manifest.source_app_name as string | undefined) ?? existing.imported_from_app_name ?? '',
    imported_at: existing.imported_at ?? now,
    last_imported_at: now,
    created_at: existing.created_at || now,
  };
  writeFileSync(metaFile, JSON.stringify(sortKeysDeep(meta), null, 2), 'utf-8');
}

/** Create `importsDir` and seed a README on first run. */
export function ensureImportsDir(importsDir: string): void {
  mkdirSync(importsDir, { recursive: true });
  const readme = join(importsDir, 'README.md');
  if (!isFile(readme)) {
    writeFileSync(readme, README_BODY, 'utf-8');
  }
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

// ---------------------------------------------------------------------------
// Minimal ZIP reader — central-directory walk, STORE + DEFLATE only.
// ---------------------------------------------------------------------------

// Decompression-bomb guards. A `.tfreport` is foreign, attacker-controllable
// input (the import route exists to ingest bundles from another install), and
// the upload-size limit only bounds the COMPRESSED blob — DEFLATE amplifies
// ~1000x, so without an output cap a small bundle can inflate to many GB and
// OOM the process. Bound each entry's inflated size AND the running total
// across all entries (readZip holds them all in memory at once).
const MAX_ENTRY_BYTES = 64 * 1024 * 1024; // 64 MB per file — well above any real state file
const MAX_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024; // 256 MB across the whole bundle

function readZip(buf: Buffer): Map<string, Buffer> {
  const eocd = findEocd(buf);
  if (eocd < 0) throw new Error('Not a zip archive (no end-of-central-directory record).');

  const total = buf.readUInt16LE(eocd + 10);
  let ptr = buf.readUInt32LE(eocd + 16); // central directory offset

  const out = new Map<string, Buffer>();
  let totalUncompressed = 0;
  for (let i = 0; i < total; i += 1) {
    if (buf.readUInt32LE(ptr) !== 0x02014b50) {
      throw new Error('Corrupt central directory header.');
    }
    const method = buf.readUInt16LE(ptr + 10);
    const compSize = buf.readUInt32LE(ptr + 20);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    const localOffset = buf.readUInt32LE(ptr + 42);
    const name = buf.toString('utf-8', ptr + 46, ptr + 46 + nameLen);

    if (!name.endsWith('/')) {
      const data = extractLocal(buf, localOffset, method, compSize);
      totalUncompressed += data.length;
      if (totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES) {
        throw new Error(
          `Bundle decompresses to more than ${Math.floor(MAX_TOTAL_UNCOMPRESSED_BYTES / (1024 * 1024))} MB (possible zip bomb).`,
        );
      }
      out.set(name, data);
    }

    ptr += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

function extractLocal(buf: Buffer, localOffset: number, method: number, compSize: number): Buffer {
  if (buf.readUInt32LE(localOffset) !== 0x04034b50) {
    throw new Error('Corrupt local file header.');
  }
  const nameLen = buf.readUInt16LE(localOffset + 26);
  const extraLen = buf.readUInt16LE(localOffset + 28);
  const dataStart = localOffset + 30 + nameLen + extraLen;
  const compressed = buf.subarray(dataStart, dataStart + compSize);
  if (method === 0) {
    // STORE: the "uncompressed" size IS the entry size, so cap it directly.
    if (compressed.length > MAX_ENTRY_BYTES) {
      throw new Error(`Zip entry exceeds the ${Math.floor(MAX_ENTRY_BYTES / (1024 * 1024))} MB per-file limit.`);
    }
    return Buffer.from(compressed);
  }
  if (method === 8) {
    // DEFLATE: hard-cap the inflated output. Node throws RangeError
    // (ERR_BUFFER_TOO_LARGE) if the stream would exceed maxOutputLength,
    // which importBundle's try/catch turns into a clean per-bundle failure
    // instead of an OOM.
    return inflateRawSync(compressed, { maxOutputLength: MAX_ENTRY_BYTES });
  }
  throw new Error(`Unsupported zip compression method: ${method}`);
}

function findEocd(buf: Buffer): number {
  // EOCD signature 0x06054b50, scanning backward (comment is empty in our bundles).
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) return i;
  }
  return -1;
}

const README_BODY = `# ThreatForest report imports

Drop \`*.tfreport\` files in this directory to import threat models from
another ThreatForest install. They will appear on the Applications page
the next time it is loaded.

Subdirectories are managed by ThreatForest — do not place bundles inside
them:

- \`processed/\` — bundles successfully imported.
- \`failed/\` — bundles that could not be imported, with a sibling
  \`.error.txt\` explaining the reason.

Imported applications are read-only — the recipient does not have the
source code, so re-running is disabled. Their version history is editable
(mitigation status overrides) just like locally-scanned apps.
`;
