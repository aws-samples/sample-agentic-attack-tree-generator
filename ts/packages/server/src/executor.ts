/**
 * Executor — bridges the RunManager to the engine graph. Port of the relevant
 * parts of `src/server/executor.py`.
 *
 * Resolves the project path from the Application record (or resume dir), creates
 * a run directory, streams the engine graph, and forwards node lifecycle events
 * as ProgressEvents. The engine's `runGraph` runs the full pipeline; we wrap it
 * to surface per-stage progress for the WebSocket clients.
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { runGraph, LocalFilesystemWorkspace } from '@threatforest/engine';
import type { SimpleInterrupt, InteractionResponse } from '@threatforest/engine';
import type { RunConfig } from '@threatforest/types';
import type { OrchestratorExecutor, ProgressEvent, ScanControl } from './run-manager.js';
import { resolveProjectPathForApp, resolveRunDirNameForApp } from './applications.js';
import { PAUSE_STATE_KEY } from './registry.js';
import { createRunDirectory } from './registry.js';

const STAGES = [
  'scanner',
  'scanner_verifier',
  'scanner_review',
  'interviewer',
  'threat',
  'threat_verifier',
  'threat_review',
  'parallel_pipeline',
  'parallel_verifier',
  'probability',
  'report',
  'report_verifier',
] as const;

function progress(
  type: string,
  stage: string,
  percentage: number,
  message: string,
  details: Record<string, unknown> = {},
): ProgressEvent {
  return { type, stage, percentage, message, details, server_ts: Date.now() };
}

/** Compute a stage's rough percentage for the progress bar. */
function stagePct(stage: string): number {
  const idx = STAGES.indexOf(stage as (typeof STAGES)[number]);
  return idx < 0 ? 0 : Math.round(((idx + 1) / STAGES.length) * 100);
}

/** Human-readable label for a graph node id, used in progress messages. */
const STAGE_LABELS: Record<string, string> = {
  scanner: 'Repository analysis',
  scanner_verifier: 'Validating scanner output',
  scanner_review: 'Scanner review',
  interviewer: 'Context interview',
  threat: 'Threat generation',
  threat_verifier: 'Validating threats',
  threat_review: 'Threat review',
  parallel_pipeline: 'Attack trees, TTP mapping & mitigations',
  parallel_verifier: 'Validating mitigations',
  probability: 'Probability analysis',
  report: 'Dashboard generation',
  report_verifier: 'Validating report',
};

function stageLabel(nodeId: string): string {
  return STAGE_LABELS[nodeId] ?? nodeId;
}

export interface ExecutorOptions {
  /** Root dir under which per-run directories are created (default .threatforest/runs). */
  runsRoot?: string;
}

/**
 * Build an OrchestratorExecutor closure for the RunManager. The returned fn runs
 * one pipeline invocation and returns the terminal status.
 */
export function createOrchestratorExecutor(_opts: ExecutorOptions = {}): OrchestratorExecutor {
  // Run-dir layout is owned by the registry's createRunDirectory (rooted at
  // getRunsRoot()), so the executor no longer computes its own runsRoot.
  return async (
    config: RunConfig,
    onProgress: (e: ProgressEvent) => void,
    control: ScanControl,
    interactionFn: ((reason: Record<string, unknown>) => Promise<string | null>) | null,
  ): Promise<{ status: string; output_dir?: string; app_id?: string; error?: string }> => {
    // Resolve project path: resume dir reuses the prior run dir; new runs resolve
    // the Application's project_path.
    const projectPath = config.app_id
      ? resolveProjectPathForApp(config.app_id) ?? config.project_path
      : config.project_path;

    // Create the run dir via the registry's canonical helper so the layout the
    // version registry later scans matches what we write here:
    //   <runsRoot>/<run_dir_name>/<YYYYMMDD_HHMMSS>/{state,output}
    // The folder MUST be the app's `run_dir_name`, because the API resolves
    // versions by that name (routes/applications.ts calls
    // getVersions(app.run_dir_name)). The previous hand-rolled
    // `sanitize(projectPath)/<ISO timestamp>` layout wrote to an unrecognized
    // folder with a non-matching timestamp format, so completed runs never
    // surfaced under GET /applications/:id/versions.
    const folderName = config.app_id ? resolveRunDirNameForApp(config.app_id) : null;
    let runDir: string;
    if (config.resume_run_dir) {
      runDir = config.resume_run_dir;
      mkdirSync(join(runDir, 'state'), { recursive: true });
      mkdirSync(join(runDir, 'output'), { recursive: true });
    } else {
      [runDir] = createRunDirectory(projectPath, folderName);
    }
    control.runDir = runDir;

    onProgress(progress('run_started', 'scanner', 0, 'Pipeline started'));

    try {
      // The engine runGraph drives the whole graph. We surface a coarse
      // Stream node lifecycle + intra-stage ticks as ProgressEvents so the WS
      // progress page advances live (it previously only saw the single
      // run_started event and looked stuck for the whole run). The page reads:
      //   - stage_start/stage_complete: `percentage` = overall stage boundary %
      //   - stage_progress: `percentage` = INTRA-stage fraction (0-100); the
      //     page folds it into overall as (stageIdx + pct/100)/numStages.
      // Bridge the run-manager's HITL callback (which emits `awaiting_input`
      // and blocks on a promise the `/respond` route resolves with the user's
      // text) into the engine's interrupt shape. The run-manager fn is keyed by
      // the interrupt `reason` (which carries phase/questions/threats/scanner
      // data the UI modal reads); we wrap the returned text — or `null` for a
      // skip — back into the `InteractionResponse[]` the HITL nodes consume.
      // Passing `null` here (the previous behavior) made every HITL node
      // auto-skip, so the human "add context" gates never fired.
      const engineInteractionFn = interactionFn
        ? async (interrupts: SimpleInterrupt[]): Promise<InteractionResponse[] | null> => {
            if (interrupts.length === 0) return null;
            const responses: InteractionResponse[] = [];
            for (const intr of interrupts) {
              const text = await interactionFn(intr.reason);
              if (text === null) return null; // user skipped/dismissed this round
              responses.push({ interruptResponse: { interruptId: intr.id, response: text } });
            }
            return responses;
          }
        : null;

      const result = await runGraph(projectPath, {
        runDir,
        frameworks: config.frameworks,
        interactionFn: engineInteractionFn,
        // Cooperative pause/stop: the engine polls this at each node boundary and
        // stops cleanly when a pause/stop is requested, leaving completed-node
        // output on disk for resume.
        shouldInterrupt: () => control.shouldInterrupt,
        // Resume: skip nodes whose output already exists from the paused run.
        skipNodes: config.skip_nodes ?? [],
        onNodeEvent: ({ phase, nodeId, fraction, detail }) => {
          if (phase === 'start') {
            onProgress(
              progress('stage_start', nodeId, stagePct(nodeId), `Started: ${stageLabel(nodeId)}`),
            );
          } else if (phase === 'complete') {
            onProgress(
              progress('stage_complete', nodeId, stagePct(nodeId), `Completed: ${stageLabel(nodeId)}`),
            );
          } else {
            // Intra-stage tick: percentage is the 0-100 fraction WITHIN the stage.
            const pct = Math.round(Math.min(1, Math.max(0, fraction ?? 0)) * 100);
            onProgress(
              progress('stage_progress', nodeId, pct, detail ?? stageLabel(nodeId)),
            );
          }
        },
      });

      // Interrupted: the engine stopped at a node boundary because pause/stop was
      // requested. Persist pause_state.json to the RUN DIR ROOT (where
      // registry.discoverPausedRuns looks) so the run shows up as resumable and
      // a resume can skip the completed nodes. `output_dir` MUST be the run dir
      // root (not runDir/output) so resumeRun reuses the correct tree.
      if (result.status === 'interrupted') {
        const intent = control.stopRequested ? 'stop' : 'pause';
        try {
          new LocalFilesystemWorkspace(runDir).writeJson(PAUSE_STATE_KEY, {
            intent,
            paused_at: new Date().toISOString(),
            completed_nodes: result.completed_nodes,
            config: {
              project_path: config.project_path,
              threat_source: config.threat_source,
              threat_file_path: config.threat_file_path ?? null,
              app_id: config.app_id ?? null,
            },
          });
        } catch (e) {
          // Persisting pause state is best-effort; surface but don't crash.
          // eslint-disable-next-line no-console
          console.error('[executor] failed to write pause_state.json:', (e as Error).message);
        }
        if (intent === 'stop') {
          onProgress(progress('run_stopped', 'stopped', stagePct('report'), 'Run stopped'));
          return { status: 'stop', output_dir: runDir };
        }
        onProgress(progress('run_paused', 'paused', stagePct('report'), 'Run paused'));
        return { status: 'pause', output_dir: runDir };
      }

      // Terminal (success OR failure): remove any stale pause_state.json so the
      // run no longer appears in the paused-runs list. This matters on a
      // resume-then-fail: the run reuses the prior paused run's dir, which still
      // holds the ORIGINAL pause_state.json — without this delete a failed
      // resumed run would reappear as "resumable" with stale completed_nodes.
      try {
        new LocalFilesystemWorkspace(runDir).delete(PAUSE_STATE_KEY);
      } catch {
        /* best-effort: no-op if absent */
      }

      onProgress(
        progress(
          result.status === 'success' ? 'run_complete' : 'run_failed',
          'report',
          100,
          result.status === 'success' ? 'Pipeline complete' : `Pipeline failed: ${result.error ?? ''}`,
        ),
      );
      return {
        status: result.status === 'success' ? 'complete' : 'failed',
        output_dir: result.output_dir,
        app_id: config.app_id ?? undefined,
        ...(result.error ? { error: result.error } : {}),
      };
    } catch (err) {
      // A thrown failure is terminal — clear any stale pause_state.json (e.g.
      // from a prior pause whose resumed run is the one that just threw) so the
      // failed run doesn't linger as "resumable".
      try {
        new LocalFilesystemWorkspace(runDir).delete(PAUSE_STATE_KEY);
      } catch {
        /* best-effort */
      }
      onProgress(progress('run_failed', 'error', 0, `Pipeline error: ${(err as Error).message}`));
      return { status: 'failed', error: (err as Error).message };
    }
  };
}
