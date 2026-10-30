'use client';

import { useState } from 'react';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import type { RunLogContent, RunLogEntry } from '@threatforest/types';
import { formatLogDuration, logPhaseLabel } from '@/utils/run-logs';
import styles from './execution-logs.module.css';

const LABELS: Record<RunLogContent['kind'], string> = {
  request: 'Request', response: 'Response', reasoning: 'Reasoning (model-provided)',
  tool_input: 'Tool input', tool_result: 'Tool result', error: 'Error',
};

function CodeBlock({ block }: { block: RunLogContent }) {
  const [expanded, setExpanded] = useState(false);
  const lines = block.text.split('\n');
  const preview = lines.slice(0, 12).join('\n').slice(0, 1400);
  const more = preview.length < block.text.length;
  return (
    <section className={styles.contentBlock} data-log-kind={block.kind}>
      <div className={styles.contentLabel}>{LABELS[block.kind]}{block.role ? ` · ${block.role}` : ''}</div>
      <pre className={styles.code}><code>{expanded ? block.text : preview || 'Content omitted.'}</code></pre>
      {more && (
        <button className={styles.expandButton} type="button" onClick={() => setExpanded(!expanded)}>
          {expanded ? 'Show less' : lines.length > 12 ? `Show more (${lines.length - 12} more lines)` : `Show more (${block.text.length - preview.length} more characters)`}
        </button>
      )}
      {block.truncated && <div className={styles.captureNote}>This event exceeded the capture limit. The recorded content is truncated.</div>}
    </section>
  );
}

export default function ExecutionLogEntry({ entry, showPhase = false }: { entry: RunLogEntry; showPhase?: boolean }) {
  const content = entry.content ?? [];
  const date = new Date(entry.started_at);
  const tooltip = date.toLocaleString();
  return (
    <article className={styles.logEntry} data-testid="execution-log-entry" data-entry-id={entry.id}>
      <div className={styles.eventHeader}>
        <StatusIndicator type={entry.status === 'error' ? 'error' : entry.status === 'running' ? 'in-progress' : 'success'}>
          <time dateTime={entry.started_at} title={tooltip}>{date.toLocaleTimeString()}</time>
          {' · '}<strong>{entry.title}</strong>
        </StatusIndicator>
        {!!entry.duration_ms && <span className={styles.duration}>{formatLogDuration(entry.duration_ms)}</span>}
      </div>
      {showPhase && <div className={styles.eventPhase}>{logPhaseLabel(entry.stage)}{entry.agent_name ? ` / ${entry.agent_name}` : ''}</div>}
      <div className={styles.eventBody}>
        {content.length === 0 ? (
          <p className={styles.summary}>{entry.summary || 'No content was recorded for this event.'}</p>
        ) : content.map((block, index) => <CodeBlock key={`${block.kind}:${index}`} block={block} />)}
        {entry.status !== 'running' && entry.category === 'model' && !content.some((block) => block.kind === 'reasoning') && (
          <div className={styles.captureNote}>No reasoning content was recorded for this response.</div>
        )}
        {Object.keys(entry.details).length > 0 && (
          <details className={styles.metadata}>
            <summary>Invocation details</summary>
            <pre className={styles.code}>{JSON.stringify(entry.details, null, 2)}</pre>
          </details>
        )}
      </div>
    </article>
  );
}
