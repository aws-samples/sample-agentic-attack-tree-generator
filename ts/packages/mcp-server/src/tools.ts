import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runGraph, type RunGraphResult, type NodeProgressEvent } from '@threatforest/engine';
import type { ScanInput, GetRunInput, GetFindingsInput } from './schemas.js';

interface RunRecord {
  run_id: string;
  status: 'running' | 'complete' | 'failed';
  project_path: string;
  started_at: string;
  completed_at: string | null;
  output_dir: string | null;
  error: string | null;
  current_stage: string | null;
  progress_pct: number;
}

const runs = new Map<string, RunRecord>();

export async function scanTool(input: ScanInput): Promise<Record<string, unknown>> {
  const runId = randomUUID().replace(/-/g, '');
  const record: RunRecord = {
    run_id: runId,
    status: 'running',
    project_path: input.project_path,
    started_at: new Date().toISOString(),
    completed_at: null,
    output_dir: null,
    error: null,
    current_stage: 'initializing',
    progress_pct: 0,
  };
  runs.set(runId, record);

  void executeRun(runId, input);

  return {
    run_id: runId,
    status: 'running',
    estimated_minutes: '5-30',
    message: `Threat model scan started for ${input.project_path}. Poll with threatforest_get_run to check progress.`,
  };
}

async function executeRun(runId: string, input: ScanInput): Promise<void> {
  const record = runs.get(runId)!;
  const stages = [
    'scanner', 'scanner_verifier', 'scanner_review', 'interviewer',
    'threat', 'threat_verifier', 'threat_review', 'parallel_pipeline',
    'parallel_verifier', 'probability', 'report', 'report_verifier',
  ];

  const onNodeEvent = (e: NodeProgressEvent): void => {
    if (e.phase === 'start') {
      record.current_stage = e.nodeId;
      const idx = stages.indexOf(e.nodeId);
      if (idx >= 0) record.progress_pct = Math.round((idx / stages.length) * 100);
    } else if (e.phase === 'complete') {
      const idx = stages.indexOf(e.nodeId);
      if (idx >= 0) record.progress_pct = Math.round(((idx + 1) / stages.length) * 100);
    }
  };

  try {
    const result: RunGraphResult = await runGraph(input.project_path, {
      frameworks: input.frameworks,
      onNodeEvent,
    });

    if (result.status === 'success') {
      record.status = 'complete';
      record.output_dir = result.output_dir;
      record.progress_pct = 100;
      record.current_stage = null;
    } else {
      record.status = 'failed';
      record.error = result.error ?? `Run ended with status: ${result.status}`;
    }
  } catch (err) {
    record.status = 'failed';
    record.error = (err as Error).message;
  } finally {
    record.completed_at = new Date().toISOString();
  }
}

export function getRunTool(input: GetRunInput): Record<string, unknown> {
  const record = runs.get(input.run_id);
  if (!record) {
    return { error: `Unknown run_id: ${input.run_id}` };
  }

  const result: Record<string, unknown> = {
    run_id: record.run_id,
    status: record.status,
    project_path: record.project_path,
    started_at: record.started_at,
    progress_pct: record.progress_pct,
  };

  if (record.current_stage) result.current_stage = record.current_stage;
  if (record.completed_at) result.completed_at = record.completed_at;
  if (record.output_dir) result.output_dir = record.output_dir;
  if (record.error) result.error = record.error;

  if (record.status === 'complete' && record.output_dir) {
    const dataPath = join(record.output_dir, 'threatforest_data.json');
    if (existsSync(dataPath)) {
      try {
        const data = JSON.parse(readFileSync(dataPath, 'utf-8'));
        const trees = data.attack_trees ?? [];
        result.summary = {
          threat_count: trees.length,
          attack_tree_count: trees.length,
          ttp_mapping_count: trees.reduce(
            (n: number, t: { ttc_mappings?: unknown[] }) => n + (t.ttc_mappings?.length ?? 0),
            0,
          ),
        };
      } catch { /* ignore parse errors */ }
    }
  }

  return result;
}

export function listRunsTool(): Record<string, unknown> {
  const list = [...runs.values()].map((r) => ({
    run_id: r.run_id,
    status: r.status,
    project_path: r.project_path,
    started_at: r.started_at,
    progress_pct: r.progress_pct,
  }));
  return { runs: list };
}

export function getFindingsTool(input: GetFindingsInput): Record<string, unknown> {
  const record = runs.get(input.run_id);
  if (!record) {
    return { error: `Unknown run_id: ${input.run_id}` };
  }
  if (record.status !== 'complete') {
    return { error: `Run is not complete (status: ${record.status}). Poll with threatforest_get_run.` };
  }
  if (!record.output_dir) {
    return { error: 'Run completed but has no output directory.' };
  }

  const dataPath = join(record.output_dir, 'threatforest_data.json');
  if (!existsSync(dataPath)) {
    return { error: `Output file not found at ${dataPath}` };
  }

  try {
    const data = JSON.parse(readFileSync(dataPath, 'utf-8'));
    return data;
  } catch (err) {
    return { error: `Failed to read findings: ${(err as Error).message}` };
  }
}
