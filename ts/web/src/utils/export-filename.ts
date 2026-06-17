/**
 * Slugify a free-text label into something filename-safe — lowercase, ASCII
 * alphanumerics + dashes only. Empty input returns empty string so callers
 * can fall back to a sibling identifier without an awkward leading dash.
 */
export function slugify(label: string | null | undefined): string {
  if (!label) return '';
  return String(label)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/**
 * Normalise a version label like ``"Version 3"`` to ``"version3"``. Falls
 * back to slugifying the raw versionId (a YYYYMMDD_HHMMSS folder name) when
 * the label isn't loaded yet.
 */
export function versionSlug(
  versionLabel: string | null | undefined,
  versionId: string | null | undefined,
): string {
  if (versionLabel) {
    const m = String(versionLabel).match(/version\s*(\d+)/i);
    if (m) return `version${m[1]}`;
    const slug = slugify(versionLabel);
    if (slug) return slug;
  }
  if (versionId === 'latest') return 'latest';
  return slugify(versionId) || 'version';
}

/** Arguments for {@link buildExportFilename}. */
export interface BuildExportFilenameArgs {
  appId: string;
  versionId: string;
  /** Resolved Application name. */
  appName?: string | null;
  /** e.g. "Version 3" or "Latest". */
  versionLabel?: string | null;
  /** "threats" | "mitigations" | null (full). */
  scope?: string | null;
  /** "pdf" | "csv". */
  extension: string;
}

/**
 * Compose ``[app-name]-[version]-[scope].[ext]`` from the human-friendly
 * names used elsewhere in the UI. Falls back to ``app_id`` / raw
 * ``versionId`` only when the names haven't been resolved yet.
 *
 * Used by ExportButton on the threat-model summary + per-threat pages, and
 * by the per-row export menu on AppOverviewPage so filenames stay identical
 * regardless of which surface initiated the export.
 */
export function buildExportFilename({
  appId,
  versionId,
  appName,
  versionLabel,
  scope,
  extension,
}: BuildExportFilenameArgs): string {
  const parts: string[] = [];
  parts.push(slugify(appName) || slugify(appId) || 'threat-model');
  parts.push(versionSlug(versionLabel, versionId));
  parts.push(scope || 'full');
  return `${parts.join('-')}.${extension}`;
}
