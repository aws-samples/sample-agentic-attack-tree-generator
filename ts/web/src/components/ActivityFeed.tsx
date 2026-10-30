'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import Box from '@cloudscape-design/components/box';
import type { RunLogEntry } from '@threatforest/types';
import ExecutionLogEntry from './ExecutionLogEntry';
import { logPhaseLabel, matchesRunLog } from '@/utils/run-logs';
import styles from './execution-logs.module.css';

export type ActivityEntryType = 'stage-start' | 'stage-complete' | 'threat-complete' | 'agent' | 'model' | 'tool' | 'hitl' | 'error';
export interface ActivityEntry {
  time: string;
  message: string;
  type: ActivityEntryType;
  id?: string;
  timestamp?: string;
  stage?: string | null;
  details?: Record<string, unknown>;
  executionLog?: RunLogEntry;
}
export function activityFromRunLog(entry: RunLogEntry): ActivityEntry {
  return {
    id: entry.id, timestamp: entry.started_at, time: new Date(entry.started_at).toLocaleTimeString(),
    message: `${entry.title}: ${entry.summary}`,
    type: entry.status === 'error' ? 'error' : entry.category === 'stage'
      ? entry.status === 'running' ? 'stage-start' : 'stage-complete' : entry.category,
    stage: entry.stage, executionLog: entry,
  };
}
function indicator(type: ActivityEntryType): StatusIndicatorProps.Type {
  return type === 'error' ? 'error' : type === 'stage-complete' || type === 'threat-complete' ? 'success' : 'info';
}
export interface ActivityFeedProps {
  entries?: ActivityEntry[];
  maxHeight?: string;
  autoScroll?: boolean;
  showFilters?: boolean;
}
export default function ActivityFeed({ entries = [], maxHeight = '560px', autoScroll = true, showFilters = false }: ActivityFeedProps) {
  const viewport = useRef<HTMLDivElement>(null);
  const [following, setFollowing] = useState(autoScroll);
  const [phase, setPhase] = useState('');
  const [query, setQuery] = useState('');
  const phases = [...new Set(entries.flatMap((entry) => entry.stage ? [entry.stage] : []))];
  const visible = useMemo(() => entries.filter((entry) => {
    if (phase && entry.stage !== phase) return false;
    return entry.executionLog ? matchesRunLog(entry.executionLog, query) : entry.message.toLowerCase().includes(query.toLowerCase());
  }), [entries, phase, query]);

  useEffect(() => {
    if (autoScroll && following && viewport.current) viewport.current.scrollTop = viewport.current.scrollHeight;
  }, [visible, following, autoScroll]);

  return (
    <div>
      {(showFilters || autoScroll) && <div className={styles.toolbar}>
        {showFilters && <>
          <select aria-label="Filter activity by phase" className={styles.filter} value={phase} onChange={(event) => setPhase(event.target.value)}>
            <option value="">All phases</option>
            {phases.map((value) => <option key={value} value={value}>{logPhaseLabel(value)}</option>)}
          </select>
          <input aria-label="Search activity logs" className={styles.filter} type="search" placeholder="Search requests and responses" value={query} onChange={(event) => setQuery(event.target.value)} />
        </>}
        {autoScroll && <label className={styles.followLabel}>
          <input type="checkbox" checked={following} onChange={(event) => setFollowing(event.target.checked)} /> Follow latest
        </label>}
      </div>}
      <div ref={viewport} data-testid="activity-feed" className={styles.timeline} style={{ maxHeight }}
        onScroll={() => {
          const element = viewport.current;
          if (autoScroll && following && element && element.scrollHeight - element.scrollTop - element.clientHeight > 100) setFollowing(false);
        }}>
        {visible.length === 0 ? <Box color="text-status-inactive">{entries.length ? 'No activity matches this filter.' : 'Waiting for activity…'}</Box> :
          visible.map((entry, index) => entry.executionLog ? (
            <ExecutionLogEntry key={entry.id} entry={entry.executionLog} showPhase={showFilters} />
          ) : (
            <div key={entry.id ?? `${entry.timestamp}:${index}`} className={styles.milestone} data-testid="activity-feed-entry">
              <time dateTime={entry.timestamp}>{entry.time}</time>
              <StatusIndicator type={indicator(entry.type)}>{entry.message}</StatusIndicator>
            </div>
          ))}
        <div data-testid="activity-feed-bottom" />
      </div>
    </div>
  );
}
