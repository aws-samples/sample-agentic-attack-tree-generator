import {
  ArchiveValidationError,
  SafeZipExtractor,
  type ExtractedArchiveEntry,
} from '@threatforest/ingestion';
import {
  BusinessContextSchema,
  VersionSummarySchema,
  type BusinessContext,
  type VersionSummary,
} from '@threatforest/types';
import { unprocessable } from './errors.js';

export const REPORT_MANIFEST_PATH = 'threatforest_report.json';
export const REPORT_SCHEMA_VERSION = 1;
export const REPORT_CONTENT_TYPE = 'application/zip';

const VERSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REQUIRED_VERSION_ENTRY = 'output/threatforest_data.json';

export interface ReportManifest {
  schema_version: 1;
  exported_at: string;
  exported_by_threatforest: string;
  source_app_id: string;
  source_app_name: string;
  source_app_slug: string;
  include_scanner_context: boolean;
  scope: 'single-version' | 'full-application';
  versions: string[];
}

export interface ParsedReportVersion {
  id: string;
  createdAt: string;
  summary: VersionSummary;
  data: Record<string, unknown>;
  entries: ReadonlyArray<{
    path: string;
    body: Uint8Array;
    sha256: string;
    contentType: string;
  }>;
}

export interface ParsedThreatforestReport {
  manifest: ReportManifest;
  application: {
    name: string;
    description: string;
    createdAt: string;
    businessContext: BusinessContext | null;
  };
  versions: ParsedReportVersion[];
}

export function parseThreatforestReportArchive(
  bytes: Uint8Array,
): ParsedThreatforestReport {
  try {
    return parseThreatforestReportArchiveUnsafe(bytes);
  } catch (error) {
    if (error instanceof ArchiveValidationError) {
      throw unprocessable(`Report archive is invalid: ${error.message}`);
    }
    if (
      typeof error === 'object' &&
      error !== null &&
      'name' in error &&
      (error as { name: unknown }).name === 'ZodError'
    ) {
      throw unprocessable(
        error instanceof Error
          ? `Report metadata is invalid: ${error.message}`
          : 'Report metadata is invalid.',
      );
    }
    throw error;
  }
}

function parseThreatforestReportArchiveUnsafe(
  bytes: Uint8Array,
): ParsedThreatforestReport {
  const extracted = new SafeZipExtractor({
    maximumFiles: 5_000,
    maximumFileBytes: 64 * 1024 * 1024,
    maximumExpandedBytes: 256 * 1024 * 1024,
    maximumPathDepth: 24,
    maximumPathLength: 1_024,
    maximumArchiveNesting: 0,
    maximumCompressionRatio: 1_000,
    duplicatePolicy: 'reject',
  }).extract(bytes);
  const entries = new Map(extracted.entries.map((entry) => [entry.path, entry]));
  const manifest = parseManifest(requiredEntry(entries, REPORT_MANIFEST_PATH));
  const metadata = optionalJsonObject(entries.get('application/metadata.json'));
  const businessContextEntry = entries.get('application/business_context.json');
  const businessContext =
    businessContextEntry === undefined
      ? null
      : BusinessContextSchema.parse(jsonValue(businessContextEntry));

  const versions = manifest.versions.map((versionId) => {
    const prefix = `versions/${versionId}/`;
    const versionEntries = extracted.entries
      .filter((entry) => entry.path.startsWith(prefix))
      .map((entry) => ({
        path: entry.path.slice(prefix.length),
        body: entry.bytes,
        sha256: entry.sha256,
        contentType: reportEntryContentType(entry.path.slice(prefix.length)),
      }));
    if (
      !versionEntries.some((entry) => entry.path === REQUIRED_VERSION_ENTRY)
    ) {
      throw unprocessable(
        `Report version '${versionId}' is missing ${REQUIRED_VERSION_ENTRY}.`,
      );
    }
    const dataEntry = versionEntries.find(
      (entry) => entry.path === REQUIRED_VERSION_ENTRY,
    )!;
    const data = asObject(
      JSON.parse(Buffer.from(dataEntry.body).toString('utf8')) as unknown,
      `${REQUIRED_VERSION_ENTRY} must contain a JSON object.`,
    );
    const runMetadataEntry = versionEntries.find(
      (entry) => entry.path === 'run_metadata.json',
    );
    const runMetadata =
      runMetadataEntry === undefined
        ? {}
        : optionalJsonObject({
            path: 'run_metadata.json',
            bytes: runMetadataEntry.body,
          });
    const createdAt = timestamp(
      runMetadata.started_at,
      runMetadata.created_at,
      runMetadata.run_date,
      manifest.exported_at,
    );
    return {
      id: versionId,
      createdAt,
      data,
      summary: versionSummary(versionId, createdAt, data),
      entries: versionEntries,
    };
  });

  return {
    manifest,
    application: {
      name:
        nonEmptyString(metadata.name) ??
        nonEmptyString(manifest.source_app_name) ??
        'Imported application',
      description: nonEmptyString(metadata.description) ?? '',
      createdAt: timestamp(metadata.created_at, manifest.exported_at),
      businessContext,
    },
    versions,
  };
}

function parseManifest(entry: ExtractedArchiveEntry): ReportManifest {
  const input = asObject(
    jsonValue(entry),
    `${REPORT_MANIFEST_PATH} must contain a JSON object.`,
  );
  if (input.schema_version !== REPORT_SCHEMA_VERSION) {
    throw unprocessable(
      `Unsupported report schema_version ${JSON.stringify(input.schema_version)}.`,
    );
  }
  if (
    input.scope !== 'single-version' &&
    input.scope !== 'full-application'
  ) {
    throw unprocessable('Report scope must be single-version or full-application.');
  }
  if (!Array.isArray(input.versions) || input.versions.length === 0) {
    throw unprocessable('Report manifest must contain at least one version.');
  }
  const versions = input.versions.map((value) => {
    if (typeof value !== 'string' || !VERSION_ID_PATTERN.test(value)) {
      throw unprocessable('Report version IDs must be safe opaque identifiers.');
    }
    return value;
  });
  if (new Set(versions).size !== versions.length) {
    throw unprocessable('Report manifest contains duplicate version IDs.');
  }
  if (input.scope === 'single-version' && versions.length !== 1) {
    throw unprocessable('A single-version report must contain exactly one version.');
  }
  const sourceAppId = requiredString(input.source_app_id, 'source_app_id');
  const sourceAppSlug = requiredString(input.source_app_slug, 'source_app_slug');
  if (!VERSION_ID_PATTERN.test(sourceAppSlug)) {
    throw unprocessable('source_app_slug must be a safe opaque identifier.');
  }
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    exported_at: timestamp(input.exported_at),
    exported_by_threatforest: nonEmptyString(input.exported_by_threatforest) ?? '',
    source_app_id: sourceAppId,
    source_app_name: nonEmptyString(input.source_app_name) ?? sourceAppSlug,
    source_app_slug: sourceAppSlug,
    include_scanner_context: input.include_scanner_context !== false,
    scope: input.scope,
    versions,
  };
}

function requiredEntry(
  entries: ReadonlyMap<string, ExtractedArchiveEntry>,
  path: string,
): ExtractedArchiveEntry {
  const entry = entries.get(path);
  if (entry === undefined) {
    throw unprocessable(`Report is missing ${path}.`);
  }
  return entry;
}

function jsonValue(
  entry: Pick<ExtractedArchiveEntry, 'path' | 'bytes'>,
): unknown {
  try {
    return JSON.parse(Buffer.from(entry.bytes).toString('utf8')) as unknown;
  } catch {
    throw unprocessable(`${entry.path} is not valid JSON.`);
  }
}

function optionalJsonObject(
  entry: Pick<ExtractedArchiveEntry, 'path' | 'bytes'> | undefined,
): Record<string, unknown> {
  if (entry === undefined) return {};
  const value = jsonValue(entry);
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asObject(value: unknown, message: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw unprocessable(message);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, field: string): string {
  const parsed = nonEmptyString(value);
  if (parsed === null || parsed.length > 256 || /[\u0000-\u001f]/.test(parsed)) {
    throw unprocessable(`${field} must be a non-empty safe string.`);
  }
  return parsed;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

function timestamp(...values: unknown[]): string {
  for (const value of values) {
    if (
      typeof value === 'string' &&
      Number.isFinite(Date.parse(value))
    ) {
      return new Date(value).toISOString();
    }
  }
  throw unprocessable('Report does not contain a valid timestamp.');
}

function versionSummary(
  id: string,
  createdAt: string,
  data: Record<string, unknown>,
): VersionSummary {
  const extraction =
    typeof data.extraction_summary === 'object' &&
    data.extraction_summary !== null &&
    !Array.isArray(data.extraction_summary)
      ? (data.extraction_summary as Record<string, unknown>)
      : {};
  const categories = Array.isArray(data.categories)
    ? data.categories.filter(
        (value): value is string => typeof value === 'string',
      )
    : [];
  return VersionSummarySchema.parse({
    id,
    run_date: createdAt,
    status:
      typeof data.status === 'string' && data.status.length > 0
        ? data.status
        : 'complete',
    threat_count: nonNegativeInteger(
      data.threat_count,
      extraction.total_threats,
    ),
    high_severity_count: nonNegativeInteger(
      data.high_severity_count,
      extraction.high_severity_count,
    ),
    categories: [...new Set(categories)],
    display_name: '',
    run_id: id,
  });
}

function nonNegativeInteger(...values: unknown[]): number {
  for (const value of values) {
    const number = typeof value === 'number' ? value : Number(value);
    if (Number.isSafeInteger(number) && number >= 0) return number;
  }
  return 0;
}

export function reportEntryContentType(path: string): string {
  if (path.endsWith('.json')) return 'application/json';
  if (path.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (path.endsWith('.html')) return 'text/html; charset=utf-8';
  return 'application/octet-stream';
}
