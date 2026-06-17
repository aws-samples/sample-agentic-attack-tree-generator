'use client';

import { useState } from 'react';
import StatusIndicator, { type StatusIndicatorProps } from '@cloudscape-design/components/status-indicator';
import ProgressBar from '@cloudscape-design/components/progress-bar';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import { useElapsedTimer, formatElapsed } from '@/hooks/useElapsedTimer';
import ScannerReviewEditModal, {
  BadgeList,
  type ScannerData,
  type ScannerReviewEdits,
} from './ScannerReviewPanel';

const FIELD_HELP = {
  cloud: 'Cloud platform(s) hosting the application (e.g. AWS, Azure, GCP).',
  stack: 'Primary languages, frameworks, and runtimes detected in the repository.',
  industry: 'Business domain of the application — shapes threat relevance and compliance.',
  services: 'Discrete services, components, or modules that make up the system.',
  auth: 'How users and services authenticate (e.g. IAM roles, OAuth2, API keys).',
  compliance: 'Regulatory or contractual frameworks the system must meet (e.g. SOC2, HIPAA).',
  ciaPriority: 'Ranking of the CIA objectives the application owner declared when the application was created — the threat set is weighted ~50/30/20 across rank 1, 2, 3.',
};

const CIA_PRIORITY_LABELS: Record<string, string> = {
  confidentiality: 'Confidentiality',
  integrity: 'Integrity',
  availability: 'Availability',
};

/**
 * Render a CIA priority list either from the new ``cia_priority`` array or
 * (for older runs that only emitted the legacy single value) by promoting
 * ``main_cia_risk`` to rank 1 with the rest in canonical order.
 */
function formatCiaPriority(ctx: ScannerData | null): string {
  if (!ctx) return '—';
  const list = Array.isArray(ctx.cia_priority) ? ctx.cia_priority : null;
  if (list && list.length === 3 && new Set(list).size === 3) {
    return list.map((v, i) => `${i + 1}. ${CIA_PRIORITY_LABELS[v] || v}`).join('   ');
  }
  const legacy = ctx.main_cia_risk;
  if (legacy && CIA_PRIORITY_LABELS[legacy]) {
    return `1. ${CIA_PRIORITY_LABELS[legacy]} (legacy single value)`;
  }
  return '—';
}

function InfoIcon({ text }: { text: string }) {
  return (
    <span
      title={text}
      aria-label={text}
      role="img"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '13px',
        height: '13px',
        borderRadius: '50%',
        border: '1px solid #5f6b7a',
        color: '#5f6b7a',
        fontSize: '9px',
        fontStyle: 'italic',
        fontFamily: 'serif',
        lineHeight: 1,
        cursor: 'help',
        marginLeft: '4px',
        verticalAlign: 'middle',
      }}
    >
      i
    </span>
  );
}

function FieldLabel({ text, info }: { text: string; info: string }) {
  return (
    <Box variant="awsui-key-label" fontSize="body-s">
      <span style={{ display: 'inline-flex', alignItems: 'center' }}>
        {text}
        <InfoIcon text={info} />
      </span>
    </Box>
  );
}

export type StageStatus =
  | 'pending'
  | 'in-progress'
  | 'awaiting-input'
  | 'completed'
  | 'failed';

/**
 * Map stage status to Cloudscape StatusIndicator type.
 */
function getIndicatorType(status: StageStatus): StatusIndicatorProps.Type {
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

/** Threat progress sub-line ("Processing threat X of Y"). */
export interface ThreatProgress {
  current: number;
  total: number;
  completed?: number;
}

/** Per-threat parallel worker row. */
export interface StageWorker {
  id: number;
  status: 'pending' | 'in-progress' | 'completed';
  stage: string;
  detail?: string | null;
}

export interface StageCardProps {
  /** Stage display name. */
  name: string;
  status?: StageStatus;
  /** 0-100 percentage. */
  progress?: number;
  /** Current sub-step description. */
  statusText?: string;
  /** Epoch ms when stage started. */
  startTime?: number | null;
  /** Epoch ms when stage completed. */
  endTime?: number | null;
  threatProgress?: ThreatProgress | null;
  /** Error message if stage failed. */
  errorMessage?: string | null;
  findings?: string[] | null;
  workers?: StageWorker[] | null;
  scannerReview?: ScannerData | null;
  onScannerReviewConfirm?: () => void;
  onScannerReviewEdit?: (edits: ScannerReviewEdits) => void;
  onScannerReviewSkip?: () => void;
  confirmedContext?: ScannerData | null;
}

/**
 * StageCard — renders a single pipeline stage with status, progress,
 * sub-step text, elapsed timer, threat progress, and error display.
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
  onScannerReviewConfirm,
  onScannerReviewEdit,
  onScannerReviewSkip,
  confirmedContext = null,
}: StageCardProps) {
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
            <div><FieldLabel text="Cloud" info={FIELD_HELP.cloud} /><BadgeList items={scannerReview._cloudTokens} /></div>
            <div><FieldLabel text="Stack" info={FIELD_HELP.stack} /><BadgeList items={scannerReview._techTokens} /></div>
            <div><FieldLabel text="Industry" info={FIELD_HELP.industry} /><div>{scannerReview.industry || '—'}</div></div>
            <div><FieldLabel text="Services" info={FIELD_HELP.services} /><BadgeList items={scannerReview.services} /></div>
            <div><FieldLabel text="Auth" info={FIELD_HELP.auth} /><BadgeList items={scannerReview.auth_mechanisms} /></div>
            <div><FieldLabel text="Compliance" info={FIELD_HELP.compliance} /><BadgeList items={scannerReview.compliance_requirements} /></div>
            <div data-testid="scanner-review-cia-priority"><FieldLabel text="CIA priority" info={FIELD_HELP.ciaPriority} /><div>{formatCiaPriority(scannerReview)}</div></div>
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
          {editModalVisible && (
            <ScannerReviewEditModal
              visible={editModalVisible}
              scannerData={scannerReview}
              onSubmit={(edits) => { setEditModalVisible(false); onScannerReviewEdit?.(edits); }}
              onDismiss={() => setEditModalVisible(false)}
            />
          )}
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
                  T{w.id + 1}: {w.stage}{w.detail ? ` — ${w.detail}` : ''}
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

      {/* Confirmed scanner context (read-only) — replaces text findings for Repository Analysis */}
      {isCompleted && confirmedContext && (
        <div style={{ marginTop: '8px' }} data-testid="confirmed-context">
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '8px 24px',
            padding: '10px 12px',
            background: '#f9fafb',
            borderRadius: '6px',
            fontSize: '13px',
          }}>
            <div><FieldLabel text="Cloud" info={FIELD_HELP.cloud} /><BadgeList items={confirmedContext._cloudTokens} /></div>
            <div><FieldLabel text="Stack" info={FIELD_HELP.stack} /><BadgeList items={confirmedContext._techTokens} /></div>
            <div><FieldLabel text="Industry" info={FIELD_HELP.industry} /><div>{confirmedContext.industry || '—'}</div></div>
            <div><FieldLabel text="Services" info={FIELD_HELP.services} /><BadgeList items={confirmedContext.services} /></div>
            <div><FieldLabel text="Auth" info={FIELD_HELP.auth} /><BadgeList items={confirmedContext.auth_mechanisms} /></div>
            <div><FieldLabel text="Compliance" info={FIELD_HELP.compliance} /><BadgeList items={confirmedContext.compliance_requirements} /></div>
            <div data-testid="confirmed-context-cia-priority"><FieldLabel text="CIA priority" info={FIELD_HELP.ciaPriority} /><div>{formatCiaPriority(confirmedContext)}</div></div>
          </div>
        </div>
      )}

      {/* Findings summary when completed (only if no confirmed context) */}
      {isCompleted && !confirmedContext && findings && findings.length > 0 && (
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
