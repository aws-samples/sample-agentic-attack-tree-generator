import React from 'react';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Box from '@cloudscape-design/components/box';
import { useElapsedTimer, formatElapsed } from '../hooks/useElapsedTimer';

/**
 * Map stage status to Cloudscape StatusIndicator type.
 * @param {string} status
 * @returns {string}
 */
function getIndicatorType(status) {
  switch (status) {
    case 'completed':
      return 'success';
    case 'in-progress':
      return 'in-progress';
    case 'failed':
      return 'error';
    default:
      return 'pending';
  }
}

/**
 * StageCard — renders a single pipeline stage with status, progress,
 * sub-step text, elapsed timer, threat progress, and error display.
 *
 * @param {Object} props
 * @param {string} props.name - Stage display name
 * @param {string} props.status - 'pending' | 'in-progress' | 'completed' | 'failed'
 * @param {number} props.progress - 0-100 percentage
 * @param {string} props.statusText - Current sub-step description
 * @param {number|null} props.startTime - Epoch ms when stage started
 * @param {number|null} props.endTime - Epoch ms when stage completed
 * @param {Object|null} props.threatProgress - { current, total, completed }
 * @param {string|null} props.errorMessage - Error message if stage failed
 */
export default function StageCard({
  name,
  status = 'pending',
  progress = 0,
  statusText = '',
  startTime = null,
  endTime = null,
  threatProgress = null,
  errorMessage = null,
  findings = null,
  workers = null,
}) {
  // Elapsed timer via extracted hook
  const elapsed = useElapsedTimer(startTime, endTime);

  const isPending = status === 'pending';
  const isInProgress = status === 'in-progress';
  const isCompleted = status === 'completed';
  const isFailed = status === 'failed';

  return (
    <div
      data-testid={`stage-card-${name.replace(/\s+/g, '-').toLowerCase()}`}
      style={{
        padding: '12px 16px',
        borderBottom: '1px solid var(--color-border-divider-default, #e9ebed)',
        opacity: isPending ? 0.6 : 1,
      }}
    >
      {/* Row 1: Status indicator + name + elapsed timer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <StatusIndicator type={getIndicatorType(status)}>
          {name}
        </StatusIndicator>

        {/* Elapsed timer: live when in-progress, final when completed */}
        {(isInProgress || isCompleted) && startTime && (
          <Box color="text-status-inactive" fontSize="body-s" data-testid="elapsed-timer">
            {formatElapsed(elapsed)}
          </Box>
        )}
      </div>

      {/* Row 2: Progress bar (only when in-progress) */}
      {isInProgress && (
        <div style={{ marginTop: '8px' }}>
          <ProgressBar value={progress} />
        </div>
      )}

      {/* Row 3: Sub-step text */}
      {isInProgress && statusText && (
        <Box color="text-status-inactive" fontSize="body-s" margin={{ top: 'xxs' }} data-testid="sub-step-text">
          {statusText}
        </Box>
      )}

      {/* Row 4: Threat progress ("Processing threat X of Y") */}
      {isInProgress && threatProgress && (
        <Box color="text-status-inactive" fontSize="body-s" margin={{ top: 'xxs' }} data-testid="threat-progress">
          Processing threat {threatProgress.current} of {threatProgress.total}
        </Box>
      )}

      {/* Row 5: Parallel workers with phase legend */}
      {isInProgress && workers && workers.length > 0 && (
        <div style={{ marginTop: '8px' }} data-testid="parallel-workers">
          {/* Phase legend */}
          <div style={{
            display: 'flex',
            gap: '16px',
            marginBottom: '8px',
            padding: '6px 10px',
            background: '#f9fafb',
            borderRadius: '6px',
            fontSize: '11px',
            color: '#6b7280',
          }} data-testid="phase-legend">
            <span>🌳 Attack Tree</span>
            <span>📐 TTP Embedding</span>
            <span>🤖 TTP Review</span>
            <span>🛡️ Mitigations</span>
            <span>✅ Complete</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '6px' }}>
            {workers.map((w) => (
              <div key={w.id} style={{
                padding: '6px 10px',
                borderRadius: '6px',
                fontSize: '12px',
                background: w.status === 'completed' ? '#f0fdf4' : w.status === 'in-progress' ? '#eff6ff' : '#f9fafb',
                border: `1px solid ${w.status === 'completed' ? '#bbf7d0' : w.status === 'in-progress' ? '#bfdbfe' : '#e5e7eb'}`,
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}>
                <span>{w.status === 'completed' ? '✅' : w.status === 'in-progress' ? '⚡' : '⏳'}</span>
                <span style={{ fontWeight: w.status === 'in-progress' ? 600 : 400, color: w.status === 'pending' ? '#9ca3af' : '#1f2937' }}>
                  T{w.id + 1}: {w.stage}{w.detail ? ` — ${w.detail.slice(0, 40)}` : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error message when failed */}
      {isFailed && errorMessage && (
        <Box color="text-status-error" fontSize="body-s" margin={{ top: 'xxs' }} data-testid="error-message">
          {errorMessage}
        </Box>
      )}

      {/* Findings summary when completed */}
      {isCompleted && findings && findings.length > 0 && (
        <div style={{ marginTop: '6px', paddingLeft: '24px' }} data-testid="stage-findings">
          {findings.map((f, i) => (
            <Box key={i} color="text-status-inactive" fontSize="body-s" margin={{ top: 'xxxs' }}>
              {f}
            </Box>
          ))}
        </div>
      )}
    </div>
  );
}
