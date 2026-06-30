/**
 * Run initiation + control routes — TS port of `src/server/routes/runs.py`.
 *
 * Mounted under `/api`. Exposes the frozen run-lifecycle contract:
 *   GET    /runs                 list runs (?status filter)
 *   POST   /runs                 start a run (202, RunResponse)
 *   GET    /runs/:id             current RunState
 *   POST   /runs/:id/pause       request pause   (200)
 *   POST   /runs/:id/stop        request stop    (200)
 *   POST   /runs/:id/resume      resume          (202, ResumeResponse)
 *   POST   /runs/:id/respond     interviewer answer (200)
 *
 * The WebSocket progress endpoint lives in `../ws.ts` (mounted at root, no /api).
 */
import { Router, type Request, type Response } from 'express';
import {
  type Application,
  type RunConfig,
  RunConfigSchema,
  ApplicationUpdateRequestSchema,
  InteractionResponseSchema,
} from '@threatforest/types';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { RunManager } from '../run-manager.js';
import {
  getRepository,
  ApplicationNotFoundError,
  ApplicationPathConflictError,
} from '../applications.js';
import { param } from '../http-util.js';

/** Absolute, resolved form of a project path (with `~` expansion) for comparison. */
function normalisePath(p: string): string {
  const expanded = p === '~' ? homedir() : p.startsWith('~/') ? `${homedir()}/${p.slice(2)}` : p;
  return resolve(expanded);
}

/** Heartbeat interval (seconds) — shared with the WS handler. */
export const WS_HEARTBEAT_INTERVAL = 15.0;

// Module-level RunManager — swappable for testing, matches the Python pattern.
let _runManager = new RunManager();

export function getRunManager(): RunManager {
  return _runManager;
}

export function setRunManager(manager: RunManager): void {
  _runManager = manager;
}

export const runsRouter: Router = Router();

/** GET /runs — list runs, optional `?status=running,pending` filter. */
runsRouter.get('/runs', (req: Request, res: Response) => {
  const manager = getRunManager();
  let runs = [...manager.activeRuns.values()];
  const status = typeof req.query.status === 'string' ? req.query.status : undefined;
  if (status) {
    const allowed = new Set(status.split(',').map((s) => s.trim()));
    runs = runs.filter((r) => allowed.has(r.status));
  }
  // Most recent first.
  runs = [...runs].sort((a, b) => (a.started_at < b.started_at ? 1 : a.started_at > b.started_at ? -1 : 0));
  res.status(200).json({ runs });
});

/** POST /runs — start a new pipeline run. */
runsRouter.post('/runs', async (req: Request, res: Response) => {
  const parsed = RunConfigSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  let config: RunConfig = parsed.data;

  if (config.resume_run_dir === null) {
    if (config.app_id === null) {
      res.status(400).json({ detail: 'app_id is required to start a new run' });
      return;
    }
    const repo = getRepository();
    let app: Application;
    try {
      app = repo.getApplication(config.app_id);
    } catch (err) {
      if (!(err instanceof ApplicationNotFoundError)) throw err;
      // Fall back to run-dir-name lookup so folder-slug URLs still resolve.
      const fallback = repo.findByRunDirName(config.app_id);
      if (fallback === null) {
        res.status(404).json({ detail: `Unknown application: ${config.app_id}` });
        return;
      }
      app = fallback;
    }

    // Users can edit project_path per run (folder renames / moves). Persist a
    // changed path so future runs pick up the new location.
    const submitted = config.project_path;
    if (submitted && normalisePath(submitted) !== normalisePath(app.project_path)) {
      try {
        app = await repo.updateApplication(
          app.id,
          ApplicationUpdateRequestSchema.parse({ project_path: submitted }),
        );
      } catch (err) {
        if (err instanceof ApplicationPathConflictError) {
          res.status(409).json({ detail: err.message });
          return;
        }
        throw err;
      }
    }

    // Normalise to the canonical (project_path, app_id) pair.
    config = { ...config, project_path: app.project_path, app_id: app.id };
  }

  const manager = getRunManager();
  let runId: string;
  try {
    runId = manager.startRun(config);
  } catch (err) {
    const msg = (err as Error).message;
    // FileNotFound / NotADirectory equivalents → 400; missing executor → 500.
    if (/no orchestrator executor configured/i.test(msg)) {
      res.status(500).json({ detail: msg });
      return;
    }
    res.status(400).json({ detail: msg });
    return;
  }
  res.status(202).json({ run_id: runId });
});

/** GET /runs/:id — return the current state of a run. */
runsRouter.get('/runs/:runId', (req: Request, res: Response) => {
  const manager = getRunManager();
  const runId = param(req, 'runId');
  const state = manager.activeRuns.get(runId);
  if (state === undefined) {
    res.status(404).json({ detail: `Unknown run_id: ${runId}` });
    return;
  }
  res.status(200).json(state);
});

/** POST /runs/:id/pause — request a pause after the current stage. */
runsRouter.post('/runs/:runId/pause', (req: Request, res: Response) => {
  const manager = getRunManager();
  try {
    manager.pauseRun(param(req, 'runId'));
  } catch (err) {
    sendLifecycleError(res, err as Error);
    return;
  }
  res.status(200).json({ status: 'pause_requested' });
});

/** POST /runs/:id/stop — request a stop after the current stage. */
runsRouter.post('/runs/:runId/stop', (req: Request, res: Response) => {
  const manager = getRunManager();
  try {
    manager.stopRun(param(req, 'runId'));
  } catch (err) {
    sendLifecycleError(res, err as Error);
    return;
  }
  res.status(200).json({ status: 'stop_requested' });
});

/** POST /runs/:id/resume — resume a paused/stopped run. */
runsRouter.post('/runs/:runId/resume', (req: Request, res: Response) => {
  const manager = getRunManager();
  let newRunId: string;
  try {
    newRunId = manager.resumeRun(param(req, 'runId'));
  } catch (err) {
    const msg = (err as Error).message;
    if (/unknown run_id/i.test(msg)) {
      res.status(404).json({ detail: msg });
      return;
    }
    res.status(400).json({ detail: msg });
    return;
  }
  res.status(202).json({ new_run_id: newRunId });
});

/** POST /runs/:id/respond — deliver a user answer to the interviewer agent. */
runsRouter.post('/runs/:runId/respond', (req: Request, res: Response) => {
  const parsed = InteractionResponseSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    res.status(422).json({ detail: parsed.error.issues });
    return;
  }
  const manager = getRunManager();
  try {
    manager.submitInteractionResponse(param(req, 'runId'), parsed.data.text);
  } catch (err) {
    res.status(404).json({ detail: (err as Error).message });
    return;
  }
  res.status(200).json({ ok: true });
});

/**
 * Map a RunManager lifecycle error to the right status: unknown run_id → 404,
 * any other (illegal-state) error → 400. Mirrors the Python KeyError/RuntimeError
 * split.
 */
function sendLifecycleError(res: Response, err: Error): void {
  if (/unknown run_id/i.test(err.message)) {
    res.status(404).json({ detail: err.message });
    return;
  }
  res.status(400).json({ detail: err.message });
}
