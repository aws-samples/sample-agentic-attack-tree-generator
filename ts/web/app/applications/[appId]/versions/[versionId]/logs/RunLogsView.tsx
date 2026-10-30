'use client';

import { useEffect, useMemo, useState } from 'react';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Alert from '@cloudscape-design/components/alert';
import Spinner from '@cloudscape-design/components/spinner';
import Button from '@cloudscape-design/components/button';
import { fontFamilyBase } from '@cloudscape-design/design-tokens';
import { runDisplayName } from '@threatforest/types';
import AppShell from '@/components/AppShell';
import ActivityFeed, { activityFromRunLog } from '@/components/ActivityFeed';
import { useRealParams } from '@/hooks/useRealParams';
import { useRunLogs } from '@/hooks/useRunLogs';
import { getApplication, getApplicationVersions } from '@/api/client';
import { LOG_PHASES, formatLogDuration, groupLogTasks, logPhaseLabel, matchesRunLog } from '@/utils/run-logs';
import styles from '@/components/execution-logs.module.css';

export default function RunLogsView() {
  const { appId, versionId } = useRealParams<{ appId: string; versionId: string }>('/applications/[appId]/versions/[versionId]/logs');
  const [appName, setAppName] = useState('Application');
  const [runId, setRunId] = useState('');
  const [runName, setRunName] = useState('Threat model');
  const [selectedKey, setSelectedKey] = useState('');
  const [filter, setFilter] = useState('');
  const [kind, setKind] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const logs = useRunLogs(runId);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    setRunId('');
    setSelectedKey('');
    Promise.all([getApplication(appId), getApplicationVersions(appId)])
      .then(([application, versions]) => {
        if (cancelled) return;
        const version = versions.versions.find((candidate) => candidate.id === versionId);
        if (!version?.run_id) throw new Error('Execution logs were not recorded for this threat model.');
        setAppName(application.name);
        setRunId(version.run_id);
        setRunName(version.display_name || runDisplayName(application.name, version.run_date));
      })
      .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : 'Failed to load execution logs.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [appId, versionId]);

  const tasks = useMemo(() => groupLogTasks(logs.entries), [logs.entries]);
  const selected = tasks.find((task) => task.key === selectedKey) ??
    tasks.find((task) => task.entries.some((entry) => entry.category === 'agent')) ?? tasks[0];
  const phases = [...LOG_PHASES.map(([id, label]) => ({ id: String(id), label })),
    ...[...new Set(tasks.map((task) => task.stage))].filter((stage) => !LOG_PHASES.some(([id]) => id === stage))
      .map((id) => ({ id, label: logPhaseLabel(id) }))];
  const visible = (selected?.entries ?? []).filter((entry) => matchesRunLog(entry, filter) &&
    (!kind || entry.content?.some((block) => block.kind === kind)));
  const busy = loading || (logs.loading && logs.entries.length === 0);
  const model = selected?.entries.find((entry) => entry.details['model_id'])?.details['model_id'];

  return (
    <AppShell activePage="/applications" breadcrumbs={[
      { text: 'Home', href: '/' }, { text: 'Applications', href: '/applications' },
      { text: appName, href: `/applications/${appId}` },
      { text: 'Threat model', href: `/applications/${appId}/versions/${versionId}` },
      { text: 'Logs', href: `/applications/${appId}/versions/${versionId}/logs` },
    ]}>
      <SpaceBetween size="l">
        <Header variant="h1" description={`${appName} · Requests, responses, and recorded reasoning by pipeline phase`}
          actions={<Button iconName="refresh" ariaLabel="Refresh logs" disabled={!runId || logs.loadingMore} loading={logs.loading} onClick={logs.refresh}>Refresh</Button>}>
          Execution logs
        </Header>
        {(error || logs.error) && <Alert type="error">{error || logs.error}</Alert>}
        {logs.loadingMore && <Box color="text-status-inactive"><Spinner /> Loading more logs… {logs.entries.length} entries loaded.</Box>}
        {busy ? <Box textAlign="center" padding="xxl"><Spinner size="large" /></Box> : !runId ? null : (
          <div className={styles.workspace} style={{ fontFamily: fontFamilyBase }}>
            <nav aria-label="Pipeline phases and agents" className={styles.navigation}>
              {phases.map((phase) => {
                const phaseTasks = tasks.filter((task) => task.stage === phase.id);
                return (
                  <details key={`${phase.id}:${phaseTasks.length > 0}`} className={styles.phase} open={phaseTasks.length > 0}>
                    <summary className={styles.phaseSummary}>{phase.label} <span className={styles.phaseCount}>({phaseTasks.length})</span></summary>
                    {phaseTasks.length === 0 ? <div className={styles.emptyPhase}>No recorded activity</div> : phaseTasks.map((task) => (
                      <button key={task.key} type="button" aria-pressed={selected?.key === task.key}
                        className={`${styles.taskCard} ${selected?.key === task.key ? styles.selectedTask : ''}`}
                        onClick={() => { setSelectedKey(task.key); setKind(''); }}>
                        <div className={styles.taskTitle}>{task.name}<span className={styles.selectionDot} aria-hidden="true" /></div>
                        <span className={`${styles.badge} ${styles[task.status]}`}>{task.status === 'running' ? 'Running' : task.status === 'error' ? 'Failed' : 'Completed'}</span>
                        <div className={styles.taskMeta}>Started: {new Date(task.startedAt).toLocaleString()}<br />
                          Duration: {task.completedAt ? formatLogDuration(Date.parse(task.completedAt) - Date.parse(task.startedAt)) : 'In progress'} · {task.entries.length} logs</div>
                        <p className={styles.taskDescription}>{task.description}</p>
                      </button>
                    ))}
                  </details>
                );
              })}
            </nav>
            <section aria-label="Selected task logs">
              {selected ? <>
                <div className={styles.taskDetail}>
                  <Header variant="h2">{selected.name}</Header>
                  <div className={styles.detailGrid}>
                    <div><div className={styles.detailLabel}>Phase</div><div className={styles.detailValue}>{logPhaseLabel(selected.stage)}</div></div>
                    <div><div className={styles.detailLabel}>Status</div><div className={styles.detailValue}>{selected.status === 'running' ? 'Running' : selected.status === 'error' ? 'Failed' : 'Completed'}</div></div>
                    {model ? <div><div className={styles.detailLabel}>Model</div><div className={styles.detailValue}>{String(model)}</div></div> : null}
                    <div><div className={styles.detailLabel}>Run</div><div className={styles.detailValue} title={runId}>{runName}</div></div>
                  </div>
                  <div className={styles.detailLabel}>Description</div><div className={styles.description}>{selected.description}</div>
                </div>
                <div className={styles.toolbar}>
                  <h2>Task logs ({visible.length})</h2>
                  <select className={styles.filter} aria-label="Filter log content" value={kind} onChange={(event) => setKind(event.target.value)}>
                    <option value="">All events</option><option value="request">Requests</option><option value="response">Responses</option>
                    <option value="reasoning">Reasoning</option><option value="tool_input">Tool inputs</option><option value="tool_result">Tool results</option><option value="error">Errors</option>
                  </select>
                </div>
                <div className={styles.toolbar}><input className={styles.filter} type="search" aria-label="Search task logs" placeholder="Search requests, responses, and reasoning" value={filter} onChange={(event) => setFilter(event.target.value)} style={{ width: '100%' }} /></div>
                {visible.length ? <ActivityFeed key={selected.key} entries={visible.map(activityFromRunLog)} maxHeight="720px" autoScroll={false} /> :
                  <Box padding="m">No task logs match this filter.</Box>}
              </> : <Box padding="l">No execution logs are available yet. Refresh to check for delayed log delivery.</Box>}
            </section>
          </div>
        )}
      </SpaceBetween>
    </AppShell>
  );
}
