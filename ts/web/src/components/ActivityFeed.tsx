'use client';

import { useEffect, useRef } from 'react';
import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import Box from '@cloudscape-design/components/box';

export type ActivityEntryType =
  | 'stage-start'
  | 'stage-complete'
  | 'threat-complete'
  | 'error';

export interface ActivityEntry {
  time: string;
  message: string;
  type: ActivityEntryType;
}

/**
 * Map activity feed entry type to Cloudscape StatusIndicator type.
 */
function getIndicatorType(entryType: ActivityEntryType): StatusIndicatorProps.Type {
  switch (entryType) {
    case 'stage-start':
      return 'info';
    case 'stage-complete':
      return 'success';
    case 'threat-complete':
      return 'info';
    case 'error':
      return 'error';
    default:
      return 'info';
  }
}

export interface ActivityFeedProps {
  entries?: ActivityEntry[];
}

/**
 * ActivityFeed — renders a curated list of milestone events replacing the
 * raw log panel. Auto-scrolls to the most recent entry as new events arrive.
 */
export default function ActivityFeed({ entries = [] }: ActivityFeedProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when entries change
  useEffect(() => {
    if (bottomRef.current && typeof bottomRef.current.scrollIntoView === 'function') {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [entries]);

  return (
    <div
      data-testid="activity-feed"
      style={{
        maxHeight: '300px',
        overflowY: 'auto',
        padding: '12px',
        borderRadius: '4px',
        backgroundColor: 'var(--color-background-container-content, #f2f3f3)',
      }}
    >
      {entries.length === 0 ? (
        <Box color="text-status-inactive">Waiting for activity…</Box>
      ) : (
        entries.map((entry, i) => (
          <div
            key={i}
            data-testid="activity-feed-entry"
            style={{
              display: 'flex',
              alignItems: 'baseline',
              gap: '8px',
              padding: '4px 0',
            }}
          >
            <span
              style={{
                color: '#666',
                fontSize: '12px',
                fontFamily: 'monospace',
                whiteSpace: 'nowrap',
              }}
            >
              [{entry.time}]
            </span>
            <StatusIndicator type={getIndicatorType(entry.type)}>
              {entry.message}
            </StatusIndicator>
          </div>
        ))
      )}
      <div ref={bottomRef} data-testid="activity-feed-bottom" />
    </div>
  );
}
