'use client';

import { useState, useMemo, useEffect } from 'react';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Button from '@cloudscape-design/components/button';
import Textarea from '@cloudscape-design/components/textarea';
import Box from '@cloudscape-design/components/box';
import Badge, { type BadgeProps } from '@cloudscape-design/components/badge';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';

type BadgeColor = NonNullable<BadgeProps['color']>;

const PRIORITY_OPTIONS: SelectProps.Option[] = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
];

const PRIORITY_COLOR: Record<string, BadgeColor> = {
  critical: 'red',
  high: 'red',
  medium: 'blue',
  low: 'grey',
};

/**
 * Threat as surfaced to the HITL review panel. This is the review-round shape
 * (carries a `priority` the user can edit) rather than the canonical
 * `@threatforest/types` Threat, which has no priority field.
 */
export interface ReviewThreat {
  id: string;
  title?: string;
  description?: string;
  priority?: string;
}

/** Per-threat local edit. */
interface ThreatEdit {
  priority?: string;
  remove?: boolean;
}

/** Payload emitted to {@link ThreatReviewPanelProps.onApply}. */
export interface ThreatReviewApply {
  edits: Record<string, ThreatEdit>;
  feedback: string;
}

export interface ThreatReviewPanelProps {
  /** Current threats from server. */
  threats?: ReviewThreat[];
  /** Guided questions to show the user. */
  questions?: string[];
  /** Intro message. */
  message?: string;
  onApply: (payload: ThreatReviewApply) => void;
  onProceed: () => void;
  /** True while a response is in-flight. */
  waiting?: boolean;
}

/**
 * ThreatReviewPanel — HITL review of generated threats.
 */
export default function ThreatReviewPanel({
  threats = [],
  questions = [],
  message = '',
  onApply,
  onProceed,
  waiting = false,
}: ThreatReviewPanelProps) {
  // Local edit state: { [threatId]: { priority?: string, remove?: bool } }
  const [edits, setEdits] = useState<Record<string, ThreatEdit>>({});
  const [feedback, setFeedback] = useState('');

  // Reset local state when the threat list changes (new round arrives).
  const threatSignature = useMemo(
    () => threats.map((t) => `${t.id}:${t.priority}`).join('|'),
    [threats],
  );
  useEffect(() => {
    setEdits({});
    setFeedback('');
  }, [threatSignature]);

  function setPriority(threatId: string, newPriority: string) {
    setEdits((prev) => ({
      ...prev,
      [threatId]: { ...(prev[threatId] || {}), priority: newPriority },
    }));
  }

  function toggleRemove(threatId: string) {
    setEdits((prev) => {
      const current = prev[threatId] || {};
      return { ...prev, [threatId]: { ...current, remove: !current.remove } };
    });
  }

  function effectivePriority(threat: ReviewThreat): string {
    const edit = edits[threat.id];
    return (edit && edit.priority) || threat.priority || 'medium';
  }

  const hasEdits = Object.values(edits).some(
    (e) => e && (e.remove || e.priority),
  );
  const hasFeedback = feedback.trim().length > 0;
  const canApply = !waiting && (hasEdits || hasFeedback);

  function handleApply() {
    if (!canApply) return;
    // Strip edits that don't actually change anything (priority same as original)
    const cleaned: Record<string, ThreatEdit> = {};
    for (const [tid, e] of Object.entries(edits)) {
      if (!e) continue;
      const out: ThreatEdit = {};
      const orig = threats.find((t) => t.id === tid);
      if (e.remove) out.remove = true;
      if (
        e.priority &&
        orig &&
        String(orig.priority).toLowerCase() !== String(e.priority).toLowerCase()
      ) {
        out.priority = e.priority;
      }
      if (Object.keys(out).length > 0) cleaned[tid] = out;
    }
    onApply({ edits: cleaned, feedback: feedback.trim() });
  }

  function handleProceed() {
    onProceed();
  }

  return (
    <Container
      header={<Header variant="h3">Threat Review</Header>}
      data-testid="threat-review-panel"
    >
      <SpaceBetween size="m">
        {message && <Box>{message}</Box>}

        {questions && questions.length > 0 && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '8px',
              background: '#f0f4f8',
              borderLeft: '3px solid #0972d3',
            }}
          >
            <Box fontSize="body-s" color="text-status-inactive" margin={{ bottom: 'xxxs' }}>
              Interviewer
            </Box>
            <ol style={{ margin: '4px 0 0 0', paddingLeft: '20px' }}>
              {questions.map((q, qi) => (
                <li key={qi} style={{ marginBottom: '6px', lineHeight: '1.5' }}>
                  {q}
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Threat list */}
        <div>
          <Box variant="h4" margin={{ bottom: 'xs' }}>
            Generated threats ({threats.length})
          </Box>
          <SpaceBetween size="xs">
            {threats.map((t) => {
              const marked = edits[t.id]?.remove;
              const prio = effectivePriority(t);
              return (
                <div
                  key={t.id}
                  style={{
                    padding: '10px 12px',
                    border: '1px solid #d5dbdb',
                    borderRadius: '6px',
                    background: marked ? '#fdf2f2' : '#ffffff',
                    opacity: marked ? 0.6 : 1,
                  }}
                  data-testid={`threat-review-row-${t.id}`}
                >
                  <div
                    style={{
                      display: 'flex',
                      gap: '10px',
                      alignItems: 'flex-start',
                    }}
                  >
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                        <Badge color={PRIORITY_COLOR[prio] || 'grey'}>
                          {prio.toUpperCase()}
                        </Badge>
                        <strong>{t.id}</strong>
                        <span>{t.title || ''}</span>
                      </div>
                      {t.description && (
                        <Box
                          fontSize="body-s"
                          color="text-body-secondary"
                          margin={{ top: 'xxs' }}
                        >
                          {t.description}
                        </Box>
                      )}
                    </div>
                    <div
                      style={{
                        display: 'flex',
                        gap: '6px',
                        flexDirection: 'column',
                        minWidth: '160px',
                      }}
                    >
                      <Select
                        selectedOption={
                          PRIORITY_OPTIONS.find((o) => o.value === prio) ||
                          PRIORITY_OPTIONS[2]!
                        }
                        onChange={({ detail }) =>
                          setPriority(t.id, detail.selectedOption.value as string)
                        }
                        options={PRIORITY_OPTIONS}
                        disabled={waiting || marked}
                        ariaLabel={`Priority for ${t.id}`}
                      />
                      <Button
                        variant={marked ? 'primary' : 'normal'}
                        onClick={() => toggleRemove(t.id)}
                        disabled={waiting}
                        data-testid={`threat-review-remove-${t.id}`}
                      >
                        {marked ? 'Undo remove' : 'Mark false positive'}
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })}
          </SpaceBetween>
        </div>

        {/* Free-text feedback */}
        <FormField
          label="Additional feedback"
          description="Describe any threats you'd like added, or other changes the agent should make. Leave blank if none."
        >
          <Textarea
            value={feedback}
            onChange={({ detail }) => setFeedback(detail.value)}
            placeholder="e.g. Add a threat about session token reuse across tenants."
            rows={3}
            disabled={waiting}
            data-testid="threat-review-feedback"
          />
        </FormField>

        {/* Action buttons */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          {waiting && (
            <Box
              fontSize="body-s"
              color="text-status-inactive"
              data-testid="threat-review-thinking"
            >
              Thinking in progress…
            </Box>
          )}
          {/*
            Button precedence flips with pending state. With unsaved edits or
            feedback, "Apply changes" is the action the user almost certainly
            means; "Ready to proceed" demotes to a secondary "Continue without
            changes" so the prominent green button doesn't silently discard
            their work. Without pending edits, proceeding is the obvious
            next step and reclaims the primary slot.
          */}
          <Button
            variant={canApply ? 'primary' : 'normal'}
            onClick={handleApply}
            disabled={!canApply}
            loading={waiting}
            data-testid="threat-review-apply"
          >
            Apply changes
          </Button>
          <Button
            variant={canApply ? 'normal' : 'primary'}
            onClick={handleProceed}
            disabled={waiting}
            data-testid="threat-review-proceed"
          >
            {canApply ? 'Continue without changes' : 'Continue'}
          </Button>
        </div>
      </SpaceBetween>
    </Container>
  );
}
