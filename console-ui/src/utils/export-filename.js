/**
 * Slugify a free-text label into something filename-safe — lowercase, ASCII
 * alphanumerics + dashes only. Empty input returns empty string so callers
 * can fall back to a sibling identifier without an awkward leading dash.
 */
export function slugify(label) {
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
export function versionSlug(versionLabel, versionId) {
  if (versionLabel) {
    const m = String(versionLabel).match(/version\s*(\d+)/i);
    if (m) return `version${m[1]}`;
    const slug = slugify(versionLabel);
    if (slug) return slug;
  }
  if (versionId === 'latest') return 'latest';
  return slugify(versionId) || 'version';
}

/**
 * Compose ``[app-name]-[version]-[scope].[ext]`` from the human-friendly
 * names used elsewhere in the UI. Falls back to ``app_id`` / raw
 * ``versionId`` only when the names haven't been resolved yet.
 *
 * Used by ExportButton on the threat-model summary + per-threat pages, and
 * by the per-row export menu on AppOverviewPage so filenames stay identical
 * regardless of which surface initiated the export.
 *
 * @param {Object} args
 * @param {string} args.appId
 * @param {string} args.versionId
 * @param {string|null} args.appName       — resolved Application name
 * @param {string|null} args.versionLabel  — e.g. "Version 3" or "Latest"
 * @param {string|null} args.scope         — "threats" | "mitigations" | null (full)
 * @param {string} args.extension          — "pdf" | "csv"
 */
export function buildExportFilename({ appId, versionId, appName, versionLabel, scope, extension }) {
  const parts = [];
  parts.push(slugify(appName) || slugify(appId) || 'threat-model');
  parts.push(versionSlug(versionLabel, versionId));
  parts.push(scope || 'full');
  return `${parts.join('-')}.${extension}`;
}
