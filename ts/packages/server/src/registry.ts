/**
 * Application registry — discovers ThreatForest runs from the centralized
 * `.threatforest/runs/` directory. Port of `src/server/registry.py`.
 *
 * Layout:
 *
 *     <runs_root>/
 *         <project_name>/
 *             metadata.json          // { path, description, name, created_at }
 *             <YYYYMMDD_HHMMSS>/     // one per scan run
 *                 state/             // intermediate agent state files
 *                 output/            // final artifacts (threatforest_data.json, report)
 *         <parent--project_name>/    // disambiguated when names collide
 *             ...
 */
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { LocalFilesystemWorkspace } from '@threatforest/engine';
import type { ApplicationSummary, BusinessContext, VersionSummary } from '@threatforest/types';
import { BusinessContextSchema } from '@threatforest/types';

export const PAUSE_STATE_KEY = 'pause_state.json';

const METADATA_FILE = 'threatforest_data.json';

/** Matches a timestamped run directory name, e.g. `20250131_143022`. */
const TIMESTAMP_RE = /^\d{8}_\d{6}$/;

function _workspace(runDir: string): LocalFilesystemWorkspace {
  return new LocalFilesystemWorkspace(runDir);
}

/** Convert a project directory name into a URL-safe slug. */
export function slugify(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return slug.replace(/^-+|-+$/g, '');
}

/**
 * Return the centralized runs directory.
 *
 * The legacy Python anchored this to the repo root via `__file__`; in the
 * compiled TS layout there is no such anchor, so we resolve relative to the
 * server's working directory — matching the `runsRoot` default in
 * `executor.ts` (`process.cwd()/.threatforest/runs`) so the whole server
 * agrees on one location.
 */
export function getRunsRoot(): string {
  return join(process.cwd(), '.threatforest', 'runs');
}

/** Expand a leading `~` to the user's home directory before resolving. */
function expandUser(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return p;
}

/** Absolute, resolved form of a path (with `~` expansion). */
function resolvePath(p: string): string {
  return resolve(expandUser(p));
}

function readJsonFile(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Determine the folder name under `.threatforest/runs/` for a project.
 *
 * Returns `[folderName, runsRoot]`. If a project with the same base name
 * already exists but points to a different path, the parent directory is
 * prepended as `<parent>--<project>` to disambiguate.
 *
 * @throws if the disambiguated name also collides.
 */
export function resolveProjectFolder(projectPath: string): [string, string] {
  const project = resolvePath(projectPath);
  const baseName = basename(project);
  const runsRoot = getRunsRoot();
  mkdirSync(runsRoot, { recursive: true });

  const candidate = join(runsRoot, baseName);
  if (isDir(candidate)) {
    const metaFile = join(candidate, 'metadata.json');
    if (isFile(metaFile)) {
      const existing = readJsonFile(metaFile) ?? {};
      const existingPath = resolve(String(existing.path ?? ''));
      if (existingPath !== project) {
        // Disambiguate: prepend parent folder name.
        const parentName = basename(dirname(project));
        const disambiguated = `${parentName}--${baseName}`;
        const candidate2 = join(runsRoot, disambiguated);
        if (isDir(candidate2)) {
          const meta2File = join(candidate2, 'metadata.json');
          if (isFile(meta2File)) {
            const existing2 = readJsonFile(meta2File) ?? {};
            if (resolve(String(existing2.path ?? '')) !== project) {
              throw new Error(
                `A project named '${baseName}' already exists at '${existingPath}'. ` +
                  `Cannot register '${project}' — disambiguated name ` +
                  `'${disambiguated}' is also taken.`,
              );
            }
          }
          return [disambiguated, runsRoot];
        }
        return [disambiguated, runsRoot];
      }
    }
  }
  return [baseName, runsRoot];
}

/** Format a Date as a UTC `YYYYMMDD_HHMMSS` timestamp. */
function utcTimestamp(d: Date): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return (
    `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `_${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`
  );
}

/**
 * Create a timestamped run directory for a project scan.
 *
 * Returns `[runDir, projectDir]` where `runDir` is
 * `<runsRoot>/<projectFolder>/<YYYYMMDD_HHMMSS>/` and `projectDir` is
 * `<runsRoot>/<projectFolder>/`. Also creates/updates `metadata.json`.
 *
 * `folderName` pins the project folder to a specific name (used by v2
 * Application-scoped runs). `displayName` overrides the human-readable
 * `name` written into `metadata.json`.
 */
export function createRunDirectory(
  projectPath: string,
  folderName?: string | null,
  displayName?: string | null,
): [string, string] {
  const project = resolvePath(projectPath);
  let folder: string;
  let runsRoot: string;
  if (folderName == null) {
    [folder, runsRoot] = resolveProjectFolder(project);
  } else {
    folder = folderName;
    runsRoot = getRunsRoot();
    mkdirSync(runsRoot, { recursive: true });
  }
  const projectDir = join(runsRoot, folder);
  mkdirSync(projectDir, { recursive: true });

  const timestamp = utcTimestamp(new Date());
  const runDir = join(projectDir, timestamp);
  mkdirSync(runDir, { recursive: true });

  mkdirSync(join(runDir, 'state'), { recursive: true });
  mkdirSync(join(runDir, 'output'), { recursive: true });

  const metaFile = join(projectDir, 'metadata.json');
  let meta: Record<string, unknown>;
  if (isFile(metaFile)) {
    meta = readJsonFile(metaFile) ?? {};
    meta.path = project;
    // Refresh the display name if the caller provided an authoritative one.
    if (displayName) {
      meta.name = displayName;
    }
  } else {
    meta = {
      name: displayName || basename(project),
      path: project,
      description: '',
      created_at: new Date().toISOString(),
    };
  }
  writeFileSync(metaFile, JSON.stringify(meta, null, 2), 'utf-8');

  return [runDir, projectDir];
}

/** Derive an ISO-format run date from a `YYYYMMDD_HHMMSS` directory name. */
function extractRunDate(versionDir: string): string {
  const name = basename(versionDir);
  const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(name);
  if (m) {
    const [, y, mo, d, h, mi, s] = m;
    return new Date(
      Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)),
    ).toISOString();
  }
  // Fallback: filesystem mtime.
  try {
    return new Date(statSync(versionDir).mtimeMs).toISOString();
  } catch {
    return new Date(0).toISOString();
  }
}

/** List the timestamped run directory names directly under a project dir. */
function listVersionDirNames(projectDir: string): string[] {
  if (!isDir(projectDir)) return [];
  try {
    return readdirSync(projectDir).filter(
      (n) => TIMESTAMP_RE.test(n) && isDir(join(projectDir, n)),
    );
  } catch {
    return [];
  }
}

/**
 * Resolve the most recent `YYYYMMDD_HHMMSS` directory name, or `null`.
 *
 * Prefers the most recent run that has `output/threatforest_data.json` on
 * disk — a completed model the API can serve. Falls back to the most recent
 * folder of any kind only if no completed run exists.
 */
function resolveLatestVersion(projectDir: string): string | null {
  const candidates = listVersionDirNames(projectDir).sort().reverse();
  if (candidates.length === 0) return null;
  for (const name of candidates) {
    if (isFile(join(projectDir, name, 'output', 'threatforest_data.json'))) {
      return name;
    }
  }
  return candidates[0] ?? null;
}

/**
 * Discovers applications from the centralized `.threatforest/runs/` directory.
 */
export class ApplicationRegistry {
  static readonly METADATA_FILE = METADATA_FILE;

  readonly runsRoot: string;

  constructor() {
    this.runsRoot = getRunsRoot();
  }

  /**
   * Scan `.threatforest/runs/` and return discovered applications.
   *
   * The legacy server processed `*.tfreport` bundles dropped into
   * `.threatforest/imports/` here. That importer is a separate workstream and
   * is not yet ported; the original wrapped it in a never-raise guard so app
   * listing always loads, and a no-op preserves that contract.
   */
  discoverApplications(): ApplicationSummary[] {
    if (!isDir(this.runsRoot)) return [];

    const apps: ApplicationSummary[] = [];
    for (const name of readdirSync(this.runsRoot).sort()) {
      const projectDir = join(this.runsRoot, name);
      if (!isDir(projectDir)) continue;
      const metaFile = join(projectDir, 'metadata.json');
      if (!isFile(metaFile)) continue;

      const summary = this.buildApplicationSummary(projectDir);
      if (summary !== null) apps.push(summary);
    }
    return apps;
  }

  /**
   * Return version summaries for `appId`, sorted by run date descending.
   *
   * Each version is labelled `"Version N"` where `N` counts from 1 for the
   * oldest run. `activeRunIds` maps version folder names to the in-flight
   * `run_id` tracked by `RunManager`; matching versions are forced
   * `in-progress` and tagged with that live id.
   */
  getVersions(
    appId: string,
    activeRunIds?: Record<string, string> | null,
  ): VersionSummary[] {
    const projectDir = this.findProjectDir(appId);
    if (projectDir === null) return [];

    const versions: VersionSummary[] = [];
    const children = readdirSync(projectDir).sort().reverse();
    for (const childName of children) {
      const child = join(projectDir, childName);
      if (!isDir(child) || childName === '__pycache__') continue;
      if (!TIMESTAMP_RE.test(childName)) continue;
      const activeRunId = (activeRunIds ?? {})[childName] ?? null;
      const version = this.buildVersionSummary(child, activeRunId);
      if (version !== null) versions.push(version);
    }

    // `versions` is sorted newest-first, so the first element gets the count.
    const total = versions.length;
    versions.forEach((v, idx) => {
      v.display_name = `Version ${total - idx}`;
    });
    return versions;
  }

  /** Return the project directory for an appId, or null. */
  getProjectDir(appId: string): string | null {
    return this.findProjectDir(appId);
  }

  /**
   * Remove a single timestamped run directory for an application.
   *
   * Returns `true` if the folder was deleted, `false` if the project dir or
   * version folder could not be found. `versionId` must be the on-disk
   * `YYYYMMDD_HHMMSS` folder name — `"latest"` is not accepted.
   *
   * @throws if the folder exists but removal fails.
   */
  deleteVersion(appId: string, versionId: string): boolean {
    const projectDir = this.findProjectDir(appId);
    if (projectDir === null) return false;
    if (!TIMESTAMP_RE.test(versionId)) return false;
    const versionDir = join(projectDir, versionId);
    if (!isDir(versionDir)) return false;
    rmSync(versionDir, { recursive: true, force: true });
    return true;
  }

  /**
   * Return the path to `threatforest_data.json` for a specific version.
   *
   * If `versionId` is `"latest"`, resolves to the most recent timestamped
   * run directory.
   */
  getVersionDataPath(appId: string, versionId: string): string | null {
    const projectDir = this.findProjectDir(appId);
    if (projectDir === null) return null;

    let vid = versionId;
    if (vid === 'latest') {
      const latest = resolveLatestVersion(projectDir);
      if (latest === null) return null;
      vid = latest;
    }
    // A non-"latest" versionId comes straight from the URL path; reject anything
    // that isn't a literal timestamp folder name so a `%2F`-encoded `../` can't
    // escape the project dir (mirrors the guard in deleteVersion).
    if (!TIMESTAMP_RE.test(vid)) return null;

    const dataFile = join(projectDir, vid, 'output', METADATA_FILE);
    return isFile(dataFile) ? dataFile : null;
  }

  /**
   * Return the run directory itself (parent of `output/`) for a version.
   *
   * Used by the mitigation-overrides endpoints to locate the sidecar file
   * next to `run_metadata.json`. Returns `null` if it cannot be resolved.
   */
  getVersionRunDir(appId: string, versionId: string): string | null {
    const projectDir = this.findProjectDir(appId);
    if (projectDir === null) return null;
    let vid = versionId;
    if (vid === 'latest') {
      const latest = resolveLatestVersion(projectDir);
      if (latest === null) return null;
      vid = latest;
    }
    // Same path-traversal guard as getVersionDataPath: this run dir feeds the
    // mitigation-overrides writeFileSync, so an unvalidated `vid` would allow an
    // arbitrary-location file write.
    if (!TIMESTAMP_RE.test(vid)) return null;
    const runDir = join(projectDir, vid);
    return isDir(runDir) ? runDir : null;
  }

  // ------------------------------------------------------------------
  // Internal helpers
  // ------------------------------------------------------------------

  /** Locate the project directory for a given appId. */
  private findProjectDir(appId: string): string | null {
    if (!isDir(this.runsRoot)) return null;
    for (const name of readdirSync(this.runsRoot)) {
      const projectDir = join(this.runsRoot, name);
      if (!isDir(projectDir)) continue;
      // Match either an exact folder name (v2 apps create runs under a folder
      // named exactly the app_id, e.g. "app_6a32...") or the legacy
      // folder-derived scheme where app_id == slugify(folder).
      if (name === appId || slugify(name) === appId) return projectDir;
    }
    return null;
  }

  private buildApplicationSummary(projectDir: string): ApplicationSummary | null {
    const metaFile = join(projectDir, 'metadata.json');
    const meta = readJsonFile(metaFile);
    if (meta === null) return null;

    const rawName = basename(projectDir);
    const appId = slugify(rawName);

    const versionDirs = listVersionDirNames(projectDir);
    const versionCount = versionDirs.length;

    // Last run date from the most recent timestamp dir.
    let lastRunDate: string;
    if (versionDirs.length > 0) {
      const latest = [...versionDirs].sort().reverse()[0] ?? '';
      lastRunDate = extractRunDate(join(projectDir, latest));
    } else {
      lastRunDate = String(meta.created_at ?? '');
    }

    // Display name: convert "parent--project" back to "Parent/Project".
    let displayName: string;
    if (rawName.includes('--')) {
      const idx = rawName.indexOf('--');
      const head = rawName.slice(0, idx);
      const tail = rawName.slice(idx + 2);
      displayName = `${titleCase(head)}/${tail}`;
    } else {
      displayName = String(meta.name ?? rawName);
    }

    // Description: prefer metadata.json, fall back to latest run's data.
    let description = String(meta.description ?? '');
    if (!description && versionDirs.length > 0) {
      const latest = [...versionDirs].sort().reverse()[0] ?? '';
      const runData = readJsonFile(join(projectDir, latest, 'output', METADATA_FILE));
      if (runData) {
        const projectInfo = (runData.project_info as Record<string, unknown>) ?? {};
        description = String(
          runData.description ?? projectInfo.short_summary ?? projectInfo.summary ?? '',
        );
        // Persist back to metadata.json for future reads.
        if (description) {
          meta.description = description;
          try {
            writeFileSync(metaFile, JSON.stringify(meta, null, 2), 'utf-8');
          } catch {
            /* best-effort persistence; never block listing */
          }
        }
      }
    }

    // Imported-app marker (bundles write `imported_from_app_*` into metadata).
    const imported = Boolean(meta.imported_from_app_id);
    const importedFrom = imported
      ? ((meta.imported_from_app_name as string | undefined) ?? null)
      : null;

    // Imported apps may carry a sidecar `business_context.json`.
    let businessContext: BusinessContext | null = null;
    if (imported) {
      const bcFile = join(projectDir, 'business_context.json');
      if (isFile(bcFile)) {
        const bcRaw = readJsonFile(bcFile);
        if (bcRaw) {
          const parsed = BusinessContextSchema.safeParse(bcRaw);
          businessContext = parsed.success ? parsed.data : null;
        }
      }
    }

    return {
      id: appId,
      name: displayName,
      description,
      version_count: versionCount,
      last_run_date: lastRunDate,
      business_context: businessContext,
      imported,
      imported_from: importedFrom,
    };
  }

  private buildVersionSummary(
    versionDir: string,
    activeRunId: string | null = null,
  ): VersionSummary | null {
    const runDate = extractRunDate(versionDir);

    const dataFile = join(versionDir, 'output', METADATA_FILE);
    const hasOutput = isFile(dataFile);
    let metadata: Record<string, unknown> = {};
    if (hasOutput) {
      metadata = readJsonFile(dataFile) ?? {};
    }

    let threatCount = Number(metadata.threat_count ?? 0);
    let highSeverityCount = Number(metadata.high_severity_count ?? 0);
    const extraction = (metadata.extraction_summary as Record<string, unknown>) ?? {};
    if (extraction && Object.keys(extraction).length > 0) {
      threatCount = threatCount || Number(extraction.total_threats ?? 0);
      highSeverityCount = highSeverityCount || Number(extraction.high_severity_count ?? 0);
    }
    const categories = (metadata.categories as string[]) ?? [];

    // Status resolution:
    //   output present  → trust its `status` (default "complete" for legacy)
    //   no output, live  → "in-progress"
    //   no output, dead  → "abandoned"
    let status: string;
    if (hasOutput) {
      status = String(metadata.status ?? 'complete');
    } else if (activeRunId !== null) {
      status = 'in-progress';
    } else {
      status = 'abandoned';
    }

    return {
      id: basename(versionDir),
      run_date: runDate,
      status,
      threat_count: threatCount,
      high_severity_count: highSeverityCount,
      categories,
      display_name: '',
      run_id: activeRunId,
    };
  }

  /**
   * Return applications whose most recent run has a `pause_state.json` with
   * intent `"pause"`. Each entry contains the application summary fields plus
   * pause metadata so the UI can offer a resume action.
   */
  discoverPausedRuns(): Array<Record<string, unknown>> {
    if (!isDir(this.runsRoot)) return [];

    const paused: Array<Record<string, unknown>> = [];
    for (const name of readdirSync(this.runsRoot).sort()) {
      const projectDir = join(this.runsRoot, name);
      if (!isDir(projectDir)) continue;
      const metaFile = join(projectDir, 'metadata.json');
      if (!isFile(metaFile)) continue;

      // Use the CHRONOLOGICALLY-latest run dir, not resolveLatestVersion():
      // the latter prefers the newest *completed* version (one with
      // output/threatforest_data.json) for display, but a paused run is by
      // definition incomplete and is the most recent activity. If a completed
      // run exists alongside, resolveLatestVersion would return the completed
      // one and we'd never see the paused dir's pause_state.json.
      const latest = listVersionDirNames(projectDir).sort().reverse()[0] ?? null;
      if (latest === null) continue;

      const workspace = _workspace(join(projectDir, latest));
      if (!workspace.exists(PAUSE_STATE_KEY)) continue;

      let pauseData: Record<string, unknown>;
      try {
        pauseData = workspace.readJson<Record<string, unknown>>(PAUSE_STATE_KEY);
      } catch {
        continue;
      }
      if (
        typeof pauseData !== 'object' ||
        pauseData === null ||
        pauseData.intent !== 'pause'
      ) {
        continue;
      }

      const meta = readJsonFile(metaFile) ?? {};
      const appId = slugify(name);
      let displayName: string;
      if (name.includes('--')) {
        const idx = name.indexOf('--');
        displayName = `${titleCase(name.slice(0, idx))}/${name.slice(idx + 2)}`;
      } else {
        displayName = String(meta.name ?? name);
      }

      paused.push({
        id: appId,
        name: displayName,
        project_path: String(meta.path ?? ''),
        paused_at: pauseData.paused_at ?? '',
        completed_nodes: pauseData.completed_nodes ?? [],
        run_dir: join(projectDir, latest),
        config: pauseData.config ?? {},
      });
    }
    return paused;
  }

  /**
   * Remove `pause_state.json` from the latest run of an application.
   *
   * Returns `true` if a file was deleted, `false` if nothing was found.
   */
  deletePauseState(appId: string): boolean {
    const projectDir = this.findProjectDir(appId);
    if (projectDir === null) return false;

    const latest = resolveLatestVersion(projectDir);
    if (latest === null) return false;

    const workspace = _workspace(join(projectDir, latest));
    // The engine's `delete` is best-effort and returns void; mirror the
    // Python contract (bool "did we delete something?") by probing first.
    if (!workspace.exists(PAUSE_STATE_KEY)) return false;
    workspace.delete(PAUSE_STATE_KEY);
    return true;
  }

  /**
   * Read `pause_state.json` directly from a run-dir ROOT (not an app id). Used by
   * the RunManager's resume path to recover `completed_nodes` (→ skip_nodes) and
   * the persisted config. This disk source survives a process restart, where the
   * in-memory RunState would be gone. Returns null if no valid pause state.
   */
  readPauseState(runDir: string): {
    intent: string;
    completed_nodes: string[];
    config: Record<string, unknown>;
  } | null {
    const workspace = _workspace(runDir);
    if (!workspace.exists(PAUSE_STATE_KEY)) return null;
    try {
      const data = workspace.readJson<Record<string, unknown>>(PAUSE_STATE_KEY);
      if (typeof data !== 'object' || data === null) return null;
      return {
        intent: typeof data.intent === 'string' ? data.intent : 'pause',
        completed_nodes: Array.isArray(data.completed_nodes)
          ? (data.completed_nodes as string[])
          : [],
        config:
          typeof data.config === 'object' && data.config !== null
            ? (data.config as Record<string, unknown>)
            : {},
      };
    } catch {
      return null;
    }
  }
}

/** Capitalize the first letter of each whitespace-delimited word. */
function titleCase(s: string): string {
  return s.replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Version / run discovery helpers used by the applications + runs routes.
// ---------------------------------------------------------------------------

/**
 * List version summaries for an app via a fresh registry instance. Thin
 * convenience used by route handlers that don't hold a registry reference.
 */
export function listVersionsForApp(
  appId: string,
  activeRunIds?: Record<string, string> | null,
): VersionSummary[] {
  return new ApplicationRegistry().getVersions(appId, activeRunIds);
}

/** List all discovered applications via a fresh registry instance. */
export function listApplications(): ApplicationSummary[] {
  return new ApplicationRegistry().discoverApplications();
}

/** Resolve the project dir for an app via a fresh registry instance. */
export function getProjectDirForApp(appId: string): string | null {
  return new ApplicationRegistry().getProjectDir(appId);
}
