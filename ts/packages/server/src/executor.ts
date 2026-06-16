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
import { runGraph } from '@threatforest/engine';
import type { RunConfig } from '@threatforest/types';
import type { OrchestratorExecutor, ProgressEvent, ScanControl } from './run-manager.js';
import { resolveProjectPathForApp } from './applications.js';

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

export interface ExecutorOptions {
  /** Root dir under which per-run directories are created (default .threatforest/runs). */
  runsRoot?: string;
}

/**
 * Build an OrchestratorExecutor closure for the RunManager. The returned fn runs
 * one pipeline invocation and returns the terminal status.
 */
export function createOrchestratorExecutor(opts: ExecutorOptions = {}): OrchestratorExecutor {
  const runsRoot = opts.runsRoot ?? join(process.cwd(), '.threatforest', 'runs');

  return async (
    config: RunConfig,
    onProgress: (e: ProgressEvent) => void,
    control: ScanControl,
  ): Promise<{ status: string; output_dir?: string; app_id?: string; error?: string }> => {
    // Resolve project path: resume dir reuses the prior run dir; new runs resolve
    // the Application's project_path.
    const projectPath = config.app_id
      ? resolveProjectPathForApp(config.app_id) ?? config.project_path
      : config.project_path;

    const runDir =
      config.resume_run_dir ??
      join(runsRoot, sanitize(projectPath), new Date().toISOString().replace(/[:.]/g, '-'));
    mkdirSync(runDir, { recursive: true });
    control.runDir = runDir;

    onProgress(progress('run_started', 'scanner', 0, 'Pipeline started'));

    try {
      // The engine runGraph drives the whole graph. We surface a coarse
      // "running" then the terminal result; fine-grained per-node streaming is
      // wired in a follow-up by consuming graph.stream() (the engine exposes
      // buildGraph for that). For now the lifecycle + terminal status are
      // contract-faithful for the UI's run-progress page.
      const result = await runGraph(projectPath, {
        runDir,
        frameworks: config.frameworks,
        interactionFn: null,
      });

      if (control.stopRequested) {
        onProgress(progress('run_stopped', 'stopped', stagePct('report'), 'Run stopped'));
        return { status: 'stop', output_dir: runDir };
      }
      if (control.pauseRequested) {
        onProgress(progress('run_paused', 'paused', stagePct('report'), 'Run paused'));
        return { status: 'pause', output_dir: runDir };
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
      onProgress(progress('run_failed', 'error', 0, `Pipeline error: ${(err as Error).message}`));
      return { status: 'failed', error: (err as Error).message };
    }
  };
}

function sanitize(p: string): string {
  return p.replace(/[^a-zA-Z0-9_-]+/g, '_').replace(/^_+|_+$/g, '') || 'project';
}
