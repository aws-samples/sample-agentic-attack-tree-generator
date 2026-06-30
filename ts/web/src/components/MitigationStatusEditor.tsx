'use client';

import { useState, useRef, useEffect } from 'react';
import Box from '@cloudscape-design/components/box';
import Badge, { type BadgeProps } from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import Textarea from '@cloudscape-design/components/textarea';
import FormField from '@cloudscape-design/components/form-field';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Modal from '@cloudscape-design/components/modal';
import Header from '@cloudscape-design/components/header';
import type { MitigationOverride, MitigationStatusT } from '@threatforest/types';
import { setMitigationOverride, clearMitigationOverride } from '@/api/client';
import { STATUS_OPTIONS, statusInfo } from '@/utils/mitigation-status';

/**
 * MitigationStatusEditor — modal-based editor for the user-disposition layer (M3 v1).
 *
 * Renders one of two compact states inside a mitigations-table cell:
 *  - "no status" → a small "Set status" button that opens the modal
 *  - "status set" → the colour-coded badge + comment + edit/clear actions
 *
 * The editor opens in a Cloudscape Modal because the form (Select + Textarea +
 * three actions) can't fit reliably in a 240px column slot — an in-cell form
 * pushes the row height and collides with neighbouring columns. Modal renders
 * in a portal so it's free of the table's layout constraints.
 *
 * Save is disabled until the comment is non-empty — backend enforces the same
 * rule, so this is just to skip a doomed round trip.
 */
export interface MitigationStatusEditorProps {
  /**
   * The canonical mitigation_text key the backend uses to look up the override.
   */
  mitigationKey: string;
  appId: string;
  versionId: string;
  /** Current override status, or null. */
  status: string | null;
  /** Current override comment. */
  comment: string;
  /**
   * Called with the saved override after a successful save; parent updates
   * local state.
   */
  onSaved?: (override: MitigationOverride) => void;
  /** Called after a successful clear. */
  onCleared?: () => void;
}

export default function MitigationStatusEditor({
  mitigationKey,
  appId,
  versionId,
  status,
  comment,
  onSaved,
  onCleared,
}: MitigationStatusEditorProps) {
  const [open, setOpen] = useState(false);
  const [draftStatus, setDraftStatus] = useState(status || '');
  const [draftComment, setDraftComment] = useState(comment || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const textareaWrapperRef = useRef<HTMLDivElement>(null);

  // Re-sync drafts whenever the form opens so re-edits don't show stale text.
  useEffect(() => {
    if (open) {
      setDraftStatus(status || '');
      setDraftComment(comment || '');
      setError('');
    }
  }, [open, status, comment]);

  // Autofocus the textarea on open. Wrapped in a tiny RAF so Cloudscape's
  // own focus management doesn't fight ours.
  useEffect(() => {
    if (!open) return;
    const id = requestAnimationFrame(() => {
      const el = textareaWrapperRef.current?.querySelector('textarea');
      if (el) el.focus();
    });
    return () => cancelAnimationFrame(id);
  }, [open]);

  async function handleSave() {
    const trimmed = draftComment.trim();
    if (!draftStatus) {
      // The user cleared the dropdown without removing the comment — treat
      // as an explicit clear so we don't leave dangling state.
      return handleClear();
    }
    if (!trimmed) {
      setError('Add a comment so reviewers know why this status was set.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const result = await setMitigationOverride(appId, versionId, mitigationKey, {
        status: draftStatus as MitigationStatusT,
        comment: trimmed,
      });
      onSaved?.(result.override);
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save status');
    } finally {
      setBusy(false);
    }
  }

  async function handleClear() {
    setBusy(true);
    setError('');
    try {
      await clearMitigationOverride(appId, versionId, mitigationKey);
      onCleared?.();
      setOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear status');
    } finally {
      setBusy(false);
    }
  }

  const info = statusInfo(status);
  const selectedOption: SelectProps.Option =
    STATUS_OPTIONS.find((o) => o.value === draftStatus) || STATUS_OPTIONS[0]!;

  return (
    <div style={{ minWidth: 140 }}>
      {/* ─── Display state — compact, fits in the table cell ───────── */}
      {info ? (
        <SpaceBetween size="xxs">
          <Badge color={info.color as BadgeProps['color']}>{info.label}</Badge>
          {comment && (
            <Box variant="small" color="text-body-secondary">
              {comment}
            </Box>
          )}
          <Button
            iconName="edit"
            variant="inline-link"
            onClick={() => setOpen(true)}
            ariaLabel="Edit status"
          >
            Edit
          </Button>
        </SpaceBetween>
      ) : (
        <Button iconName="add-plus" variant="inline-link" onClick={() => setOpen(true)}>
          Set status
        </Button>
      )}

      {/* ─── Edit modal — portalled, immune to row-width constraints ── */}
      <Modal
        visible={open}
        onDismiss={() => !busy && setOpen(false)}
        header={<Header variant="h3">Set mitigation status</Header>}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              {status && (
                <Button onClick={handleClear} disabled={busy} iconName="close">
                  Clear
                </Button>
              )}
              <Button onClick={() => setOpen(false)} disabled={busy}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleSave}
                disabled={busy || !draftStatus || !draftComment.trim()}
                loading={busy}
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="small" color="text-body-secondary">
            {mitigationKey}
          </Box>
          <FormField label="Status">
            <Select
              selectedOption={selectedOption}
              options={[...STATUS_OPTIONS]}
              onChange={({ detail }) => setDraftStatus(detail.selectedOption.value || '')}
              disabled={busy}
              expandToViewport
            />
          </FormField>
          <FormField
            label="Comment"
            description="Required — a short rationale that future reviewers and re-runs can rely on."
            errorText={error || undefined}
          >
            <div ref={textareaWrapperRef}>
              <Textarea
                value={draftComment}
                onChange={({ detail }) => setDraftComment(detail.value)}
                placeholder="e.g. Org-wide SCP enforces this — see SEC-1042"
                rows={4}
                disabled={busy}
              />
            </div>
          </FormField>
        </SpaceBetween>
      </Modal>
    </div>
  );
}
