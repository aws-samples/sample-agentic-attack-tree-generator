import type { RunLogEntry } from '@threatforest/types';

export const LOG_PHASES = [
  ['scanner', 'Repository analysis'], ['scanner_verifier', 'Scanner validation'],
  ['scanner_review', 'Context review'], ['interviewer', 'Context validation'],
  ['threat', 'Threat generation'], ['threat_verifier', 'Threat validation'],
  ['threat_review', 'Threat review'], ['parallel_pipeline', 'Attack paths and mitigations'],
  ['parallel_verifier', 'Coverage validation'], ['probability', 'Risk scoring'],
  ['report', 'Report generation'], ['report_verifier', 'Report validation'],
] as const;

export function logPhaseLabel(stage: string | null | undefined): string {
  return LOG_PHASES.find(([id]) => id === stage)?.[1] ?? (stage ? stage.replace(/[_-]/g, ' ') : 'Other activity');
}
export function compareRunLogs(a: RunLogEntry, b: RunLogEntry): number {
  return a.started_at.localeCompare(b.started_at) ||
    Number(a.details['sequence'] ?? 0) - Number(b.details['sequence'] ?? 0) ||
    a.id.localeCompare(b.id);
}
export function mergeRunLogs(previous: readonly RunLogEntry[], incoming: readonly RunLogEntry[]): RunLogEntry[] {
  const entries = new Map(previous.map((entry) => [entry.id, entry]));
  for (const entry of incoming) entries.set(entry.id, entry);
  return [...entries.values()].sort(compareRunLogs);
}
export function matchesRunLog(entry: RunLogEntry, query: string): boolean {
  const value = query.trim().toLowerCase();
  return !value || [entry.title, entry.summary, entry.agent_name, logPhaseLabel(entry.stage),
    ...(entry.content ?? []).map((block) => block.text), JSON.stringify(entry.details),
  ].some((part) => part?.toLowerCase().includes(value));
}
export interface LogTask {
  key: string; stage: string; name: string; entries: RunLogEntry[];
  status: 'running' | 'completed' | 'error';
  startedAt: string; completedAt: string | null; description: string;
}
export function groupLogTasks(entries: readonly RunLogEntry[]): LogTask[] {
  const grouped = new Map<string, RunLogEntry[]>();
  for (const entry of entries) {
    const stage = entry.stage ?? 'other';
    const key = `${stage}:${entry.agent_id ?? (entry.category === 'stage' || entry.category === 'hitl' ? 'stage' : entry.agent_name ?? 'agent')}`;
    const taskEntries = grouped.get(key) ?? [];
    taskEntries.push(entry);
    grouped.set(key, taskEntries);
  }
  return [...grouped.entries()].map(([key, unsorted]) => {
    const logs = [...unsorted].sort(compareRunLogs);
    const first = logs[0]!;
    const last = logs.at(-1)!;
    const latestInvocation = last.invocation_id;
    const currentLogs = latestInvocation ? logs.filter((entry) => entry.invocation_id === latestInvocation) : logs;
    const pending = new Map<string, RunLogEntry['status']>();
    for (const entry of currentLogs) {
      const operation = entry.details['operation_id'];
      if (typeof operation === 'string') pending.set(operation, entry.status);
    }
    // A final agent response closes the task, including previously failed
    // model attempts. Individual errors remain visible in the timeline.
    const finalAgent = currentLogs.filter((entry) => entry.category === 'agent' && entry.status !== 'running').at(-1);
    const status = finalAgent?.status ?? (last.status === 'error' ? 'error'
      : [...pending.values()].includes('running') ? 'running' : last.status);
    return {
      key, stage: first.stage ?? 'other', name: first.agent_name ?? logPhaseLabel(first.stage),
      entries: logs, status, startedAt: first.started_at,
      completedAt: status === 'running' ? null : last.completed_at ?? last.started_at,
      description: logs.find((entry) => entry.category === 'agent' && entry.content?.some((block) => block.kind === 'request'))?.summary ?? first.summary,
    };
  });
}
export function formatLogDuration(milliseconds: number | null): string {
  if (milliseconds === null) return '—';
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${Math.floor(milliseconds / 60_000)} min ${Math.floor(milliseconds % 60_000 / 1000)} s`;
}
