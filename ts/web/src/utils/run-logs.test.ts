import { expect, it } from 'vitest';
import { RunLogEntrySchema } from '@threatforest/types';
import { groupLogTasks, mergeRunLogs, matchesRunLog } from './run-logs';

function entry(id: string, overrides: Record<string, unknown> = {}) {
  return RunLogEntrySchema.parse({
    id, run_id: 'run_test', trace_id: 'trace', span_id: id, category: 'agent',
    stage: 'parallel_pipeline', agent_id: 'tree-t1', agent_name: 'Attack tree · THR-1',
    invocation_id: 'invocation-1', title: 'Agent request', summary: 'Analyze payment integrity.',
    status: 'running', started_at: '2026-09-16T12:00:00.000Z',
    ...overrides,
  });
}
it('updates entries in place and orders overlap and late arrivals chronologically', () => {
  const merged = mergeRunLogs([entry('a'), entry('b', { started_at: '2026-09-16T12:00:02.000Z' })], [
    entry('a', { status: 'completed' }), entry('c', { started_at: '2026-09-16T11:59:00.000Z' }),
  ]);
  expect(merged.map((log) => log.id)).toEqual(['c', 'a', 'b']);
  expect(merged[1]?.status).toBe('completed');
});
it('separates parallel workers and keeps retries running after a prior completed invocation', () => {
  const tasks = groupLogTasks([
    entry('a', { status: 'completed' }),
    entry('b', { agent_id: 'mitigation-t1', agent_name: 'Mitigation · THR-1' }),
    entry('c', { invocation_id: 'invocation-2', started_at: '2026-09-16T12:00:10.000Z' }),
  ]);
  expect(tasks).toHaveLength(2);
  expect(tasks[0]?.status).toBe('running');
  expect(tasks[0]?.completedAt).toBeNull();
});
it('pairs operations and closes recovered model failures only after the agent response', () => {
  const logs = [
    entry('a', { category: 'model', status: 'running', details: { operation_id: 'model', sequence: 1 } }),
    entry('b', { category: 'model', status: 'error', details: { operation_id: 'model', sequence: 2 } }),
    entry('c', { status: 'completed', title: 'Agent response', details: { sequence: 3 } }),
  ];
  expect(groupLogTasks(logs)[0]?.status).toBe('completed');
});
it('searches recorded reasoning and response bodies', () => {
  const log = entry('a', { content: [{ kind: 'reasoning', text: 'Tenant scoping protects settlement integrity.' }] });
  expect(matchesRunLog(log, 'settlement integrity')).toBe(true);
  expect(matchesRunLog(log, 'made up rationale')).toBe(false);
});
