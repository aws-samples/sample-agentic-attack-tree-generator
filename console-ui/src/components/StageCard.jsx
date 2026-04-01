import React, { useState } from 'react';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import { useElapsedTimer, formatElapsed } from '../hooks/useElapsedTimer';
import ScannerReviewEditModal, { BadgeList } from './ScannerReviewPanel';

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
    case 'awaiting-input':
      return 'warning';
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
  scannerReview = null,
  onScannerReviewConfirm = null,
  onScannerReviewEdit = null,
  onScannerReviewSkip = null,
}) {
  const [editModalVisible, setEditModalVisible] = useState(false);

  // Elapsed timer via extracted hook
  const elapsed = useElapsedTimer(startTime, endTime);

  const isPending = status === 'pending';
  const isInProgress = status === 'in-progress';
  const isAwaitingInput = status === 'awaiting-input';
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

      {/* Awaiting input: scanner review (inline) or interviewer (pointer to panel) */}
      {isAwaitingInput && scannerReview && (
        <div style={{ marginTop: '10px' }} data-testid="scanner-review-inline">
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '10px 24px',
            padding: '10px 12px',
            background: '#f9fafb',
            borderRadius: '6px',
            fontSize: '13px',
          }}>
            <div><Box variant="awsui-key-label" fontSize="body-s">Cloud</Box><BadgeList items={scannerReview._cloudTokens} /></div>
            <div><Box variant="awsui-key-label" fontSize="body-s">Stack</Box><BadgeList items={scannerReview._techTokens} /></div>
            <div><Box variant="awsui-key-label" fontSize="body-s">Industry</Box><div>{scannerReview.industry || '\u2014'}</div></div>
            <div><Box variant="awsui-key-label" fontSize="body-s">Services</Box><BadgeList items={scannerReview.services} /></div>
            <div><Box variant="awsui-key-label" fontSize="body-s">Auth</Box><BadgeList items={scannerReview.auth_mechanisms} /></div>
            <div><Box variant="awsui-key-label" fontSize="body-s">Compliance</Box><BadgeList items={scannerReview.compliance_requirements} /></div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '10px' }}>
            <Button variant="primary" onClick={onScannerReviewConfirm} data-testid="scanner-review-confirm">
              Looks good
            </Button>
            <Button variant="normal" onClick={() => setEditModalVisible(true)} data-testid="scanner-review-edit">
              Edit
            </Button>
            <span style={{ flex: 1 }} />
            <Button variant="link" onClick={onScannerReviewSkip} data-testid="scanner-review-skip">
              Skip
            </Button>
          </div>
          <ScannerReviewEditModal
            visible={editModalVisible}
            scannerData={scannerReview}
            onSubmit={(edits) => { setEditModalVisible(false); onScannerReviewEdit(edits); }}
            onDismiss={() => setEditModalVisible(false)}
          />
        </div>
      )}
      {isAwaitingInput && !scannerReview && (
        <Box color="text-status-warning" fontSize="body-s" margin={{ top: 'xs' }} data-testid="awaiting-input">
          Waiting for your input — see the Context Validation panel below
        </Box>
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
