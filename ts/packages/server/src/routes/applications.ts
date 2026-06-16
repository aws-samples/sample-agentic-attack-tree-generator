/**
 * Application discovery + version routes — TS port of
 * `src/server/routes/applications.py`. Mounted under `/api`.
 *
 * Owns the module-level ApplicationRegistry singleton (shared with the imports
 * route, matching the Python `from server.routes.applications import get_registry`).
 */
import { Router, type Request, type Response } from 'express';
import { readFileSync, statSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import {
  type Application,
  type ApplicationSummary,
  ApplicationCreateRequestSchema,
  ApplicationUpdateRequestSchema,
  MitigationOverrideRequestSchema,
  MitigationOverrideSchema,
} from '@threatforest/types';
import { ApplicationRegistry } from '../registry.js';
import {
  getRepository,
  ApplicationNotFoundError,
  ApplicationNameConflictError,
  ApplicationPathConflictError,
} from '../applications.js';
import { getRunManager } from './runs.js';
import { buildReportBundle, ReportBundleError } from '../report-bundle.js';
import { param } from '../http-util.js';

export const applicationsRouter: Router = Router();

// ---------------------------------------------------------------------------
// Module-level registry singleton — reconfigured by app.ts at startup, shared
// with the imports route.
// ---------------------------------------------------------------------------

let _registry = new ApplicationRegistry();

export function getRegistry(): ApplicationRegistry {
  return _registry;
}

export function setRegistry(registry: ApplicationRegistry): void {
  _registry = registry;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Map `version_folder_basename -> run_id` for live (pending/running) runs whose
 * ScanControl points at a timestamped subdir under `folderId`.
 */
function activeRunsForFolder(folderId: string): Record<string, string> {
  const manager = getRunManager();
  const active: Record<string, string> = {};
  for (const [runId, state] of manager.activeRuns.entries()) {
    if (state.status !== 'pending' && state.status !== 'running') continue;
    const control = manager.getControl(runId);
    const runDir = control?.runDir ?? null;
    if (!runDir) continue;
    // Match by parent folder name (the project folder under runs/).
    if (basename(dirname(runDir)) !== folderId) continue;
    active[basename(runDir)] = runId;
  }
  return active;
}

/** Translate a route `app_id` to the on-disk folder name (run_dir_name). */
function resolveFolderId(appId: string): string {
  try {
    return getRepository().getApplication(appId).run_dir_name;
  } catch {
    return appId;
  }
}

function isoNow(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// Application CRUD + discovery
// ---------------------------------------------------------------------------

/** GET /applications — merge persistent records with folder-derived ones. */
applicationsRouter.get('/applications', (_req: Request, res: Response) => {
  const registry = getRegistry();
  const folderApps = registry.discoverApplications();

  const repo = getRepository();
  const persistent = repo.listApplications();
  const persistentRunDirs = new Set(persistent.map((a) => a.run_dir_name));

  const merged: ApplicationSummary[] = [];
  for (const app of persistent) {
    const versions = registry.getVersions(app.run_dir_name, activeRunsForFolder(app.run_dir_name));
    merged.push({
      id: app.id,
      name: app.name,
      description: app.business_context.description,
      version_count: versions.length,
      last_run_date: versions.length > 0 ? versions[0]!.run_date : '',
      business_context: app.business_context,
      imported: false,
      imported_from: null,
    });
  }

  for (const folderApp of folderApps) {
    if (persistentRunDirs.has(folderApp.id)) continue;
    merged.push(folderApp);
  }

  res.json({ applications: merged });
});

/** POST /applications — create a new application (201). */
applicationsRouter.post('/applications', async (req: Request, res: Response) => {
  const parsed = ApplicationCreateRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const repo = getRepository();
  try {
    const app = await repo.createApplication(parsed.data);
    res.status(201).json(app);
  } catch (err) {
    if (err instanceof ApplicationNameConflictError || err instanceof ApplicationPathConflictError) {
      res.status(409).json({ detail: err.message });
      return;
    }
    throw err;
  }
});

/** GET /applications/by-id/:id — full persistent record. */
applicationsRouter.get('/applications/by-id/:appId', (req: Request, res: Response) => {
  const repo = getRepository();
  const appId = param(req, 'appId');
  try {
    res.json(repo.getApplication(appId));
  } catch {
    const app = repo.findByRunDirName(appId);
    if (app === null) {
      res.status(404).json({ detail: `Unknown application: ${appId}` });
      return;
    }
    res.json(app);
  }
});

/** PATCH /applications/by-id/:id — partial update. */
applicationsRouter.patch('/applications/by-id/:appId', async (req: Request, res: Response) => {
  const parsed = ApplicationUpdateRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const repo = getRepository();
  try {
    const app = await repo.updateApplication(param(req, 'appId'), parsed.data);
    res.json(app);
  } catch (err) {
    if (err instanceof ApplicationNotFoundError) {
      res.status(404).json({ detail: err.message });
      return;
    }
    if (err instanceof ApplicationNameConflictError || err instanceof ApplicationPathConflictError) {
      res.status(409).json({ detail: err.message });
      return;
    }
    throw err;
  }
});

/** DELETE /applications/by-id/:id — remove record + on-disk artefacts. */
applicationsRouter.delete('/applications/by-id/:appId', async (req: Request, res: Response) => {
  const repo = getRepository();
  const appId = param(req, 'appId');
  let app: Application;
  try {
    app = repo.getApplication(appId);
  } catch (err) {
    res.status(404).json({ detail: (err as Error).message });
    return;
  }

  const registry = getRegistry();
  const projectDir = registry.getProjectDir(app.run_dir_name);

  try {
    await repo.deleteApplication(appId);
  } catch (err) {
    if (err instanceof ApplicationNotFoundError) {
      res.status(404).json({ detail: err.message });
      return;
    }
    throw err;
  }

  if (projectDir !== null && isDir(projectDir)) {
    try {
      rmSync(projectDir, { recursive: true, force: true });
    } catch (err) {
      res.status(500).json({
        detail: `Application record deleted, but on-disk folder ${projectDir} could not be removed: ${(err as Error).message}`,
      });
      return;
    }
  }

  res.status(200).json({ success: true, message: `Application '${appId}' deleted` });
});

// ---------------------------------------------------------------------------
// Paused runs (registered before /applications/:id/... so they don't collide).
// ---------------------------------------------------------------------------

/** GET /paused-runs — applications whose most recent run is paused. */
applicationsRouter.get('/paused-runs', (_req: Request, res: Response) => {
  res.json({ paused_runs: getRegistry().discoverPausedRuns() });
});

/** DELETE /paused-runs/:id — clear the pause_state.json for an app. */
applicationsRouter.delete('/paused-runs/:appId', (req: Request, res: Response) => {
  const deleted = getRegistry().deletePauseState(param(req, 'appId'));
  if (!deleted) {
    res.status(404).json({ detail: `No paused run found for '${param(req, 'appId')}'` });
    return;
  }
  res.json({ success: true, message: `Paused run for '${param(req, 'appId')}' removed` });
});

// ---------------------------------------------------------------------------
// Version listing / data / deletion (folder-derived identifiers).
// ---------------------------------------------------------------------------

/** GET /applications/:id/versions — threat-model versions, newest first. */
applicationsRouter.get('/applications/:appId/versions', (req: Request, res: Response) => {
  const registry = getRegistry();
  const appId = param(req, 'appId');
  const folderId = resolveFolderId(appId);
  const versions = registry.getVersions(folderId, activeRunsForFolder(folderId));
  if (versions.length === 0) {
    // A freshly created v2 app legitimately has zero runs → empty list, not 404.
    try {
      getRepository().getApplication(appId);
      res.json({ versions: [] });
      return;
    } catch {
      /* fall through to folder-derived 404 check */
    }
    const apps = registry.discoverApplications();
    const appIds = new Set(apps.map((a) => a.id));
    if (!appIds.has(folderId)) {
      res.status(404).json({ detail: `Application '${appId}' not found` });
      return;
    }
  }
  res.json({ versions });
});

/** GET /applications/:id/versions/:vid/data — merged threatforest_data.json. */
applicationsRouter.get(
  '/applications/:appId/versions/:versionId/data',
  (req: Request, res: Response) => {
    const registry = getRegistry();
    const appId = param(req, 'appId');
    const versionId = param(req, 'versionId');
    const folderId = resolveFolderId(appId);
    const dataFile = registry.getVersionDataPath(folderId, versionId);

    if (dataFile === null) {
      res.status(404).json({ detail: `Version '${versionId}' not found for application '${appId}'` });
      return;
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(readFileSync(dataFile, 'utf-8')) as Record<string, unknown>;
    } catch {
      res.status(500).json({ detail: 'Failed to parse threat data' });
      return;
    }

    // Attach run-level metadata from the sidecar, or derive started_at from the
    // run-folder timestamp for older runs without the sidecar.
    const runMetaFile = join(dirname(dirname(dataFile)), 'run_metadata.json');
    if (isFile(runMetaFile)) {
      try {
        data.run_metadata = JSON.parse(readFileSync(runMetaFile, 'utf-8'));
      } catch {
        /* leave run_metadata unset on malformed sidecar */
      }
    } else {
      const folderName = basename(dirname(dirname(dataFile))); // YYYYMMDD_HHMMSS
      const m = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})$/.exec(folderName);
      if (m) {
        const [, y, mo, d, h, mi, s] = m;
        const started = new Date(
          Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)),
        ).toISOString();
        data.run_metadata = {
          model_id: '',
          frameworks: [],
          attack_version: '',
          started_at: started,
          completed_at: null,
          duration_seconds: null,
        };
      }
    }

    // Strip per-mapping `reasoning` (matches Python). The Python build also
    // enriches each mapping with `technique_url` and STIX-derived `mitigations`
    // via threatforest.frameworks / MitigationMapper — those depend on the
    // Python-only ML/MITRE layer (see WS-1) and are intentionally not duplicated
    // here; the dashboard already tolerates their absence.
    const attackTrees = (data.attack_trees as Array<Record<string, unknown>> | undefined) ?? [];
    for (const tree of attackTrees) {
      const mappings = (tree.ttc_mappings as Array<Record<string, unknown>> | undefined) ?? [];
      for (const mapping of mappings) {
        delete mapping.reasoning;
      }
    }

    // Merge user-edited mitigation overrides over the immutable pipeline output.
    const overrides = loadMitigationOverrides(folderId, versionId);
    if (Object.keys(overrides).length > 0) {
      applyMitigationOverrides(data, overrides);
    }

    res.json(data);
  },
);

/** DELETE /applications/:id/versions/:vid — delete one timestamped run folder. */
applicationsRouter.delete(
  '/applications/:appId/versions/:versionId',
  (req: Request, res: Response) => {
    const registry = getRegistry();
    const appId = param(req, 'appId');
    const versionId = param(req, 'versionId');
    const folderId = resolveFolderId(appId);

    const active = activeRunsForFolder(folderId);
    if (versionId in active) {
      res.status(400).json({
        detail: `Version '${versionId}' is currently running (run_id=${active[versionId]}). Cancel the run before deleting.`,
      });
      return;
    }

    let deleted: boolean;
    try {
      deleted = registry.deleteVersion(folderId, versionId);
    } catch (err) {
      res.status(500).json({ detail: `Failed to delete version '${versionId}': ${(err as Error).message}` });
      return;
    }

    if (!deleted) {
      res.status(404).json({ detail: `Version '${versionId}' not found for application '${appId}'` });
      return;
    }

    res.json({ success: true, message: `Version '${versionId}' deleted` });
  },
);

// ---------------------------------------------------------------------------
// .tfreport export bundles.
// ---------------------------------------------------------------------------

function slugifyForFilename(text: string): string {
  const out = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return out || 'threatforest';
}

function bundleFilename(appName: string, versionLabel: string | null): string {
  const base = slugifyForFilename(appName);
  if (versionLabel) return `${base}-${slugifyForFilename(versionLabel)}.tfreport`;
  return `${base}-full.tfreport`;
}

function buildAndRespond(
  res: Response,
  folderId: string,
  versionIds: string[],
  includeScannerContext: boolean,
  filename: string,
): void {
  let payload: Buffer;
  try {
    payload = buildReportBundle({
      folderId,
      versionIds,
      includeScannerContext,
      registry: getRegistry(),
      appRepository: getRepository(),
      threatforestVersion: '',
    });
  } catch (err) {
    if (err instanceof ReportBundleError) {
      res.status(404).json({ detail: err.message });
      return;
    }
    throw err;
  }
  res.status(200);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(payload);
}

/** GET /applications/:id/versions/:vid/report — single-version .tfreport. */
applicationsRouter.get(
  '/applications/:appId/versions/:versionId/report',
  (req: Request, res: Response) => {
    const appId = param(req, 'appId');
    let versionId = param(req, 'versionId');
    const includeScannerContext = parseBoolQuery(req.query.include_scanner_context, true);
    const registry = getRegistry();
    const folderId = resolveFolderId(appId);

    if (versionId === 'latest') {
      // The registry resolves "latest" (preferring completed output) when given
      // the literal — derive the concrete version id from the run-dir basename
      // so the manifest carries a real timestamp.
      const runDir = registry.getVersionRunDir(folderId, 'latest');
      if (runDir === null) {
        res.status(404).json({ detail: `No completed versions for application '${appId}' to export.` });
        return;
      }
      versionId = basename(runDir);
    }

    let appName = folderId;
    try {
      appName = getRepository().getApplication(appId).name;
    } catch {
      const record = getRepository().findByRunDirName(folderId);
      if (record !== null) appName = record.name;
    }

    buildAndRespond(res, folderId, [versionId], includeScannerContext, bundleFilename(appName, versionId));
  },
);

/** GET /applications/:id/report — full-application .tfreport (all completed). */
applicationsRouter.get('/applications/:appId/report', (req: Request, res: Response) => {
  const appId = param(req, 'appId');
  const includeScannerContext = parseBoolQuery(req.query.include_scanner_context, true);
  const registry = getRegistry();
  const folderId = resolveFolderId(appId);

  const versions = registry.getVersions(folderId);
  const completed = versions.filter((v) => v.status === 'complete').map((v) => v.id);
  if (completed.length === 0) {
    res.status(404).json({ detail: `No completed versions for application '${appId}' to export.` });
    return;
  }
  // Oldest-first so the recipient labels them Version 1,2,3 consistently.
  completed.reverse();

  let appName = folderId;
  try {
    appName = getRepository().getApplication(appId).name;
  } catch {
    const record = getRepository().findByRunDirName(folderId);
    if (record !== null) appName = record.name;
  }

  buildAndRespond(res, folderId, completed, includeScannerContext, bundleFilename(appName, null));
});

// ---------------------------------------------------------------------------
// Mitigation overrides (M3 v1).
// ---------------------------------------------------------------------------

const MITIGATION_OVERRIDES_FILE = 'mitigation_overrides.json';
const MITIGATION_OVERRIDES_VERSION = 1;

function overridesPath(folderId: string, versionId: string): string | null {
  const runDir = getRegistry().getVersionRunDir(folderId, versionId);
  if (runDir === null) return null;
  return join(runDir, MITIGATION_OVERRIDES_FILE);
}

function loadMitigationOverrides(
  folderId: string,
  versionId: string,
): Record<string, Record<string, unknown>> {
  const path = overridesPath(folderId, versionId);
  if (path === null || !isFile(path)) return {};
  try {
    const raw = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
    const overrides = raw.overrides;
    return overrides && typeof overrides === 'object' && !Array.isArray(overrides)
      ? (overrides as Record<string, Record<string, unknown>>)
      : {};
  } catch {
    return {};
  }
}

function saveMitigationOverrides(
  res: Response,
  folderId: string,
  versionId: string,
  overrides: Record<string, Record<string, unknown>>,
): boolean {
  const path = overridesPath(folderId, versionId);
  if (path === null) {
    res.status(404).json({ detail: `Version '${versionId}' not found for application` });
    return false;
  }
  const payload = { version: MITIGATION_OVERRIDES_VERSION, overrides };
  writeFileSync(path, JSON.stringify(payload, null, 2), 'utf-8');
  return true;
}

function applyMitigationOverrides(
  data: Record<string, unknown>,
  overrides: Record<string, Record<string, unknown>>,
): void {
  const stitch = (mit: Record<string, unknown>): void => {
    const key =
      (mit.mitigation_text as string | undefined) ||
      (mit.name as string | undefined) ||
      (mit.mitigation as string | undefined) ||
      '';
    if (!key) return;
    const record = overrides[key];
    if (!record) return;
    mit.override_status = record.status;
    mit.override_comment = record.comment;
    mit.override_updated_at = record.updated_at;
  };

  const attackTrees = (data.attack_trees as Array<Record<string, unknown>> | undefined) ?? [];
  for (const tree of attackTrees) {
    const mappings = (tree.ttc_mappings as Array<Record<string, unknown>> | undefined) ?? [];
    for (const mapping of mappings) {
      for (const mit of (mapping.mitigations as Array<Record<string, unknown>> | undefined) ?? []) {
        stitch(mit);
      }
    }
    for (const mit of (tree.mitigations as Array<Record<string, unknown>> | undefined) ?? []) {
      stitch(mit);
    }
  }
}

/** GET /applications/:id/versions/:vid/mitigation-overrides — all overrides. */
applicationsRouter.get(
  '/applications/:appId/versions/:versionId/mitigation-overrides',
  (req: Request, res: Response) => {
    const folderId = resolveFolderId(param(req, 'appId'));
    res.json({ overrides: loadMitigationOverrides(folderId, param(req, 'versionId')) });
  },
);

/** PUT /applications/:id/versions/:vid/mitigation-overrides/*key — set one. */
applicationsRouter.put(
  '/applications/:appId/versions/:versionId/mitigation-overrides/*mitigationKey',
  (req: Request, res: Response) => {
    const parsed = MitigationOverrideRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(422).json({ detail: parsed.error.issues });
      return;
    }
    const folderId = resolveFolderId(param(req, 'appId'));
    const versionId = param(req, 'versionId');
    const mitigationKey = param(req, 'mitigationKey');
    const overrides = loadMitigationOverrides(folderId, versionId);
    const record = MitigationOverrideSchema.parse({
      status: parsed.data.status,
      comment: parsed.data.comment.trim(),
      updated_at: isoNow(),
    });
    overrides[mitigationKey] = record as unknown as Record<string, unknown>;
    if (!saveMitigationOverrides(res, folderId, versionId, overrides)) return;
    res.json({ override: overrides[mitigationKey] });
  },
);

/** DELETE /applications/:id/versions/:vid/mitigation-overrides/*key — clear one. */
applicationsRouter.delete(
  '/applications/:appId/versions/:versionId/mitigation-overrides/*mitigationKey',
  (req: Request, res: Response) => {
    const folderId = resolveFolderId(param(req, 'appId'));
    const versionId = param(req, 'versionId');
    const mitigationKey = param(req, 'mitigationKey');
    const overrides = loadMitigationOverrides(folderId, versionId);
    delete overrides[mitigationKey];
    if (!saveMitigationOverrides(res, folderId, versionId, overrides)) return;
    res.json({ success: true });
  },
);

// ---------------------------------------------------------------------------
// Legacy folder-derived delete (registered LAST so the more specific routes
// above win). Mirrors the Python `DELETE /applications/{app_id}`.
// ---------------------------------------------------------------------------

/** DELETE /applications/:id — delete a folder-derived application's runs/ dir. */
applicationsRouter.delete('/applications/:appId', (req: Request, res: Response) => {
  const registry = getRegistry();
  const projectDir = registry.getProjectDir(param(req, 'appId'));
  if (projectDir === null) {
    res.status(404).json({ detail: `Application '${param(req, 'appId')}' not found` });
    return;
  }
  try {
    rmSync(projectDir, { recursive: true, force: true });
  } catch (err) {
    res.status(500).json({ detail: `Failed to delete: ${(err as Error).message}` });
    return;
  }
  res.json({ success: true, message: `Application '${param(req, 'appId')}' deleted successfully` });
});

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** Parse a boolean query param the way FastAPI does (true/1/yes → true). */
function parseBoolQuery(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const v = String(value).toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  return fallback;
}
