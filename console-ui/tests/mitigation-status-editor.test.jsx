import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent, cleanup, within } from '@testing-library/react';

/**
 * The repo's vitest setup doesn't load @testing-library/jest-dom, so the
 * idiomatic ``toBeDisabled`` / ``toBeInTheDocument`` matchers aren't
 * available. These helpers express the same intent against plain DOM.
 */
const isInDocument = (el) => !!el && document.body.contains(el);
const isDisabled = (el) =>
  !!el && (el.disabled === true || el.getAttribute('aria-disabled') === 'true' || el.getAttribute('disabled') !== null);

vi.mock('../src/api-client', () => ({
  setMitigationOverride: vi.fn(),
  clearMitigationOverride: vi.fn(),
}));

import MitigationStatusEditor from '../src/components/MitigationStatusEditor.jsx';
import { setMitigationOverride, clearMitigationOverride } from '../src/api-client';

const COMMON_PROPS = {
  mitigationKey: 'Use SCP',
  appId: 'demo',
  versionId: '20260101_120000',
};

describe('MitigationStatusEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it('renders the "Set status" CTA when no override is recorded', () => {
    render(<MitigationStatusEditor {...COMMON_PROPS} status={null} comment="" />);
    expect(isInDocument(screen.getByRole('button', { name: /set status/i }))).toBe(true);
  });

  it('shows the badge + comment + edit affordance when a status is recorded', () => {
    render(
      <MitigationStatusEditor
        {...COMMON_PROPS}
        status="already_implemented"
        comment="Org-wide SCP — see SEC-1042"
      />
    );
    // The Select + Textarea inside the (closed) Modal also bake the status
    // label and the comment into the DOM, so we assert presence not uniqueness.
    expect(screen.getAllByText('Already implemented').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Org-wide SCP — see SEC-1042').length).toBeGreaterThan(0);
    expect(isInDocument(screen.getByRole('button', { name: /edit/i }))).toBe(true);
  });

  it('opens the form on "Set status" click and shows status + comment fields', async () => {
    render(<MitigationStatusEditor {...COMMON_PROPS} status={null} comment="" />);
    fireEvent.click(screen.getByRole('button', { name: /set status/i }));

    await waitFor(() => {
      expect(isInDocument(screen.getByText(/^Status$/))).toBe(true);
      expect(isInDocument(screen.getByText(/^Comment$/))).toBe(true);
    });
  });

  it('disables Save until the comment is non-empty', async () => {
    render(<MitigationStatusEditor {...COMMON_PROPS} status={null} comment="" />);
    fireEvent.click(screen.getByRole('button', { name: /set status/i }));

    const saveBtn = await screen.findByRole('button', { name: /save/i });
    expect(isDisabled(saveBtn)).toBe(true);
  });

  it('calls setMitigationOverride and onSaved with the new override on Save', async () => {
    const onSaved = vi.fn();
    setMitigationOverride.mockResolvedValueOnce({
      override: {
        status: 'in_progress',
        comment: 'starting next sprint',
        updated_at: '2026-05-13T10:00:00+00:00',
      },
    });

    render(
      <MitigationStatusEditor
        {...COMMON_PROPS}
        status="in_progress"
        comment="starting next sprint"
        onSaved={onSaved}
      />
    );
    // Open form via the existing edit button
    fireEvent.click(screen.getByRole('button', { name: /edit/i }));

    // Save with the (already-populated) draft values
    const saveBtn = await screen.findByRole('button', { name: /save/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(setMitigationOverride).toHaveBeenCalledWith(
        'demo',
        '20260101_120000',
        'Use SCP',
        { status: 'in_progress', comment: 'starting next sprint' },
      );
      expect(onSaved).toHaveBeenCalledWith({
        status: 'in_progress',
        comment: 'starting next sprint',
        updated_at: '2026-05-13T10:00:00+00:00',
      });
    });
  });

  it('Clear button calls clearMitigationOverride and onCleared', async () => {
    const onCleared = vi.fn();
    clearMitigationOverride.mockResolvedValueOnce({ success: true });

    render(
      <MitigationStatusEditor
        {...COMMON_PROPS}
        status="wont_do"
        comment="duplicate of TS003"
        onCleared={onCleared}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: /edit/i }));

    const clearBtn = await screen.findByRole('button', { name: /^clear$/i });
    fireEvent.click(clearBtn);

    await waitFor(() => {
      expect(clearMitigationOverride).toHaveBeenCalledWith(
        'demo',
        '20260101_120000',
        'Use SCP',
      );
      expect(onCleared).toHaveBeenCalled();
    });
  });
});
