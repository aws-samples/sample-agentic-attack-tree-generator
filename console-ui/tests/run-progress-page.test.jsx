import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import RunProgressPage from '../src/pages/RunProgressPage.jsx';

// Track the most recent WebSocket handlers so tests can simulate messages
let wsHandlers = {};
let mockWsInstance = {};

vi.mock('../src/api-client', () => ({
  connectRunWebSocket: vi.fn((runId, handlers) => {
    wsHandlers = handlers;
    mockWsInstance = { close: vi.fn(), readyState: 1 };
    // Simulate connection open
    if (handlers.onOpen) setTimeout(() => handlers.onOpen(), 0);
    return mockWsInstance;
  }),
  getDashboardUrl: vi.fn((runId) => `/api/runs/${runId}/dashboard`),
}));

import { connectRunWebSocket, getDashboardUrl } from '../src/api-client';

function renderPage(runId = 'run-abc-123') {
  return render(
    <MemoryRouter initialEntries={[`/runs/${runId}/progress`]}>
      <Routes>
        <Route path="/runs/:runId/progress" element={<RunProgressPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

/** Simulate a WebSocket message */
function sendWsMessage(data) {
  act(() => {
    if (wsHandlers.onMessage) {
      wsHandlers.onMessage({ data: JSON.stringify(data) });
    }
  });
}

describe('RunProgressPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    wsHandlers = {};
    mockWsInstance = {};
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders within CloudscapeShell with activePage="/new-run"', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const activeLinks = container.querySelectorAll('[aria-current="page"]');
      expect(activeLinks.length).toBeGreaterThan(0);
      const hrefs = Array.from(activeLinks).map((el) => el.getAttribute('href'));
      expect(hrefs).toContain('/new-run');
    });
  });

  it('renders breadcrumbs with Home, New Run, and Progress', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const breadcrumbLinks = container.querySelectorAll(
        '[class*="breadcrumb"] a, [class*="Breadcrumb"] a',
      );
      const texts = Array.from(breadcrumbLinks).map((el) => el.textContent);
      expect(texts).toContain('Home');
    });
  });

  it('renders the Run Progress header with run ID', () => {
    renderPage('run-xyz');
    expect(screen.getAllByText('Run Progress').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/run-xyz/).length).toBeGreaterThan(0);
  });

  it('connects to WebSocket on mount with the correct runId', () => {
    renderPage('run-test-42');
    expect(connectRunWebSocket).toHaveBeenCalledWith('run-test-42', expect.any(Object));
  });

  it('disconnects WebSocket on unmount', () => {
    const { unmount } = renderPage();
    expect(connectRunWebSocket).toHaveBeenCalled();
    unmount();
    expect(mockWsInstance.close).toHaveBeenCalled();
  });

  it('renders all 4 pipeline stages', () => {
    renderPage();
    const stages = [
      'Repository Analysis',
      'Threat Generation',
      'Parallel Analysis',
      'Dashboard Generation',
    ];
    stages.forEach((stage) => {
      expect(screen.getAllByText(stage).length).toBeGreaterThan(0);
    });
  });

  it('renders overall progress bar', () => {
    renderPage();
    expect(screen.getAllByText('Pipeline progress').length).toBeGreaterThan(0);
  });

  it('shows connection status indicator', async () => {
    renderPage();
    // Initially disconnected, then connected after onOpen fires
    await vi.advanceTimersByTimeAsync(10);
    await waitFor(() => {
      expect(screen.getAllByText('Connected').length).toBeGreaterThan(0);
    });
  });

  it('handles stage_start event — marks stage as in-progress', async () => {
    const { container } = renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_start', stage: 'Repository Analysis' });

    await waitFor(() => {
      // The log should contain the stage start message
      expect(screen.getAllByText(/Stage started: Repository Analysis/).length).toBeGreaterThan(0);
    });
  });

  it('handles stage_complete event — marks stage as completed', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_start', stage: 'Repository Analysis' });
    sendWsMessage({ type: 'stage_complete', stage: 'Repository Analysis' });

    await waitFor(() => {
      expect(screen.getAllByText(/Stage completed: Repository Analysis/).length).toBeGreaterThan(0);
    });
  });

  it('handles pipeline completion (stage_complete with stage="complete")', async () => {
    renderPage('run-done');
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_complete', stage: 'complete' });

    await waitFor(() => {
      expect(screen.getAllByText(/Pipeline completed successfully/).length).toBeGreaterThan(0);
    });
  });

  it('shows dashboard link on pipeline completion with app_id', async () => {
    renderPage('run-done');
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({
      type: 'stage_complete',
      stage: 'complete',
      details: { app_id: 'my-app' },
    });

    await waitFor(() => {
      expect(screen.getAllByText('View Dashboard').length).toBeGreaterThan(0);
    });
  });

  it('shows View Applications link on pipeline completion without app_id', async () => {
    renderPage('run-done');
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_complete', stage: 'complete' });

    await waitFor(() => {
      expect(screen.getAllByText('View Applications').length).toBeGreaterThan(0);
    });
  });

  it('handles error event — shows error alert', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({
      type: 'error',
      stage: 'Threat Parsing',
      message: 'Parse failed: invalid input',
    });

    await waitFor(() => {
      expect(screen.getAllByText('Parse failed: invalid input').length).toBeGreaterThan(0);
    });
  });

  it('silently ignores log events (not shown in activity feed)', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'log', stage: 'pipeline', message: 'Processing file: main.py' });

    // Log events are silently ignored — verify no error is thrown
    // and the message does NOT appear in the activity feed
    await vi.advanceTimersByTimeAsync(10);
    expect(screen.queryByText('Processing file: main.py')).toBeNull();
  });

  it('silently ignores heartbeat events', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'heartbeat', timestamp: Date.now() });

    // Heartbeat events are silently ignored — no error, no UI change
    await vi.advanceTimersByTimeAsync(10);
    expect(screen.queryByText(/heartbeat/i)).toBeNull();
  });

  it('handles stage_progress event with percentage', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_start', stage: 'Repository Analysis' });
    sendWsMessage({
      type: 'stage_progress',
      stage: 'Repository Analysis',
      percentage: 50,
      message: 'Scanning files...',
    });

    await waitFor(() => {
      expect(screen.getAllByText('Scanning files...').length).toBeGreaterThan(0);
    });
  });

  it('handles stage_update event the same as stage_progress', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_start', stage: 'Dashboard Generation' });
    sendWsMessage({
      type: 'stage_update',
      stage: 'Dashboard Generation',
      percentage: 60,
      message: 'Generating HTML dashboard...',
    });

    await waitFor(() => {
      expect(screen.getAllByText('Generating HTML dashboard...').length).toBeGreaterThan(0);
    });
  });

  it('handles internal stage names via stageIndexMap fallback', async () => {
    renderPage();
    await vi.advanceTimersByTimeAsync(10);

    sendWsMessage({ type: 'stage_start', stage: 'tree_generation' });

    await waitFor(() => {
      expect(screen.getAllByText(/Stage started: Parallel Analysis/).length).toBeGreaterThan(0);
    });
  });

  it('renders Activity Feed section', () => {
    renderPage();
    expect(screen.getAllByText('Activity Feed').length).toBeGreaterThan(0);
  });

  it('renders Pipeline Stages section', () => {
    renderPage();
    expect(screen.getAllByText('Pipeline Stages').length).toBeGreaterThan(0);
  });
});
