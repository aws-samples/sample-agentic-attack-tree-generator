import React, { useEffect, useRef } from 'react';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Box from '@cloudscape-design/components/box';

/**
 * Map activity feed entry type to Cloudscape StatusIndicator type.
 * @param {string} entryType
 * @returns {string}
 */
function getIndicatorType(entryType) {
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

/**
 * ActivityFeed — renders a curated list of milestone events replacing the
 * raw log panel. Auto-scrolls to the most recent entry as new events arrive.
 *
 * @param {Object} props
 * @param {Array<{time: string, message: string, type: string}>} props.entries
 *   type: 'stage-start' | 'stage-complete' | 'threat-complete' | 'error'
 */
export default function ActivityFeed({ entries = [] }) {
  const bottomRef = useRef(null);

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
