import { expect, test } from '@playwright/test';
import { APPLICATION_ID, RUN_ID, VERSION_ID, installBaseApi, json } from './support/mock-api.mjs';

const baseTime = Date.parse('2026-09-16T09:00:00.000Z');
function log(id, seconds, overrides = {}) {
  return {
    id, run_id: RUN_ID, trace_id: 'trace', span_id: id, parent_span_id: null,
    category: 'agent', stage: 'scanner', agent_id: 'scanner', agent_name: 'Scanner', invocation_id: 'scanner-1',
    status: 'completed', title: 'Agent response', summary: 'Review payment processing, source evidence, and trust boundaries.',
    started_at: new Date(baseTime + seconds * 1000).toISOString(),
    completed_at: new Date(baseTime + seconds * 1000).toISOString(), duration_ms: 1000,
    details: { operation_id: id, sequence: seconds }, content: [], ...overrides,
  };
}
const longResponse = JSON.stringify({
  application: 'Payments Service',
  business_context: { purpose: 'Card payments and settlements', priority: 'Integrity', compliance: ['PCI DSS'] },
  evidence: Array.from({ length: 6 }, (_, index) => ({
    file: `src/payments/handler-${index + 1}.ts`, line: 25 + index, finding: `Verified tenant boundary ${index + 1}`,
  })),
  conclusion: 'Review the settlement authorization boundary.',
}, null, 2);
const logs = [
  log('agent-request', 0, { status: 'running', title: 'Agent request', completed_at: null,
    content: [{ kind: 'request', role: 'user', text: 'Analyze payment processing. Verify business context and cite the source for each trust boundary.', truncated: false }] }),
  log('model-request', 1, { category: 'model', status: 'running', title: 'Model request', completed_at: null,
    details: { model_id: 'Configured analysis model', operation_id: 'model-1' },
    content: [{ kind: 'request', role: 'user', text: 'Identify the trust boundaries in the payments repository.', truncated: false }] }),
  log('tool-input', 2, { category: 'tool', status: 'running', title: 'Tool use', completed_at: null,
    content: [{ kind: 'tool_input', text: JSON.stringify({ path: 'src/payments/handler.ts', offset: 20, limit: 15 }, null, 2), truncated: false }] }),
  log('tool-result', 3, { category: 'tool', title: 'Tool result',
    content: [{ kind: 'tool_result', text: JSON.stringify({ file: 'src/payments/handler.ts', line: 25, excerpt: 'return findByTenant(tenantId, paymentId);' }, null, 2), truncated: false }] }),
  log('model-response', 8, { category: 'model', title: 'Model response', duration_ms: 7000,
    details: { model_id: 'Configured analysis model', input_tokens: 4221, output_tokens: 505, operation_id: 'model-1' },
    content: [
      { kind: 'reasoning', text: 'Settlement integrity is the business priority. The tenant-scoped lookup establishes the boundary between customers.', truncated: false },
      { kind: 'response', text: longResponse, truncated: false },
    ] }),
  log('agent-response', 9, { content: [{ kind: 'response', text: 'Repository analysis completed. Evidence is linked to source lines.', truncated: false }] }),
  log('threat-response', 15, { stage: 'threat', agent_id: 'threat', agent_name: 'Threat generator', invocation_id: 'threat-1',
    content: [{ kind: 'response', text: 'THR-1: Unauthorized modification of settlement records.', truncated: false }] }),
  log('mitigation-response', 25, { stage: 'parallel_pipeline', agent_id: 'mitigation-t1', agent_name: 'Mitigation · THR-1', invocation_id: 'mitigation-1',
    content: [{ kind: 'response', text: 'Enforce tenant-scoped settlement authorization and add a negative access test.', truncated: false }] }),
];
const envelope = (entries, next = null) => ({
  run_id: RUN_ID, entries, next_token: next, source: 'agentcore_cloudwatch', window_end: new Date().toISOString(),
});
async function installObservabilityApi(page, handler) {
  await installBaseApi(page, async (context) => {
    if (handler && await handler(context) !== false) return;
    if (context.url.pathname === `/api/runs/${RUN_ID}/logs`) return json(context.route, envelope(logs));
    return false;
  });
}
async function liveApi(page, handler, status = 'running') {
  await page.addInitScript(() => {
    class MockWebSocket extends EventTarget {
      static OPEN = 1;
      readyState = 1;
      constructor() {
        super();
        window.__runSocket = this;
        setTimeout(() => this.dispatchEvent(new Event('open')), 0);
      }
      send() {}
      close() {}
    }
    window.WebSocket = MockWebSocket;
  });
  await installObservabilityApi(page, async (context) => {
    const { route, request, url } = context;
    if (handler && await handler(context) !== false) return;
    if (url.pathname === `/api/runs/${RUN_ID}/replay-ticket`) return json(route, { ticket: 'ticket.test.signature', expires_at: '2026-09-16T12:00:00.000Z' });
    if (url.pathname === `/api/runs/${RUN_ID}/interactions`) return json(route, { interactions: [] });
    if (url.pathname === `/api/runs/${RUN_ID}` && request.method() === 'GET') return json(route, {
      run_id: RUN_ID, status, config: { app_id: APPLICATION_ID, project_path: '', threat_source: 'auto', skip_nodes: [] },
      started_at: new Date(baseTime).toISOString(), completed_at: null, error: null, output_dir: null, paused_at_stage: null, paused_at: null,
    });
    return false;
  });
}
const historyPath = `/applications/${APPLICATION_ID}/versions/${VERSION_ID}/logs`;

test('application overview links latest and prior threat models to execution logs', async ({ page }) => {
  await installObservabilityApi(page);
  await page.goto(`/applications/${APPLICATION_ID}`);
  await expect(page.getByRole('heading', { name: 'Latest threat model' })).toBeVisible();
  const logLinks = page.getByRole('button', { name: 'Logs', exact: true });
  await expect(logLinks).toHaveCount(2);
  await logLinks.first().click();
  await expect(page).toHaveURL(new RegExp(`${historyPath}/?$`));
  await expect(page.getByRole('heading', { name: 'Execution logs', exact: true })).toBeVisible();
});

test('historical logs use phase/task navigation and expandable request, response and reasoning content', async ({ page }) => {
  await installObservabilityApi(page);
  await page.goto(historyPath);
  const scanner = page.getByRole('button', { name: /^Scanner Completed/ });
  await expect(scanner).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByRole('heading', { name: 'Task logs (6)' })).toBeVisible();
  await expect(page.locator('[data-entry-id="agent-request"] [data-log-kind="request"]')).toContainText('Verify business context');
  const response = page.locator('[data-entry-id="model-response"]');
  await expect(response.locator('[data-log-kind="reasoning"]')).toContainText('Settlement integrity');
  await response.getByRole('button', { name: /Show more/ }).click();
  await expect(response.locator('[data-log-kind="response"]')).toContainText('Verified tenant boundary 6');
  await expect(response.getByRole('button', { name: 'Show less' })).toBeVisible();
  await page.getByLabel('Filter log content').selectOption('reasoning');
  await expect(page.getByRole('heading', { name: 'Task logs (1)' })).toBeVisible();
  await page.screenshot({ path: '/tmp/threatforest-observability-history.png', fullPage: true });
  await page.getByRole('button', { name: /^Mitigation · THR-1 Completed/ }).click();
  await expect(page.getByRole('heading', { name: 'Mitigation · THR-1', exact: true })).toBeVisible();
  await expect(page.getByTestId('activity-feed')).toContainText('negative access test');
  await page.getByLabel('Search task logs').fill('unmatched search');
  await expect(page.getByText('No task logs match this filter.')).toBeVisible();
});

test('history drains empty intermediate pages and shows retrieval errors with refresh recovery', async ({ page }) => {
  let fail = true;
  const cursors = [];
  let end;
  await installObservabilityApi(page, async ({ route, url }) => {
    if (url.pathname !== `/api/runs/${RUN_ID}/logs`) return false;
    if (fail) return json(route, { detail: 'Log retrieval temporarily unavailable.' }, 503);
    const cursor = url.searchParams.get('next_token');
    cursors.push(cursor);
    if (!cursor) {
      end = new Date().toISOString();
      return json(route, { ...envelope(logs.slice(0, 2), 'empty-page'), window_end: end });
    }
    expect(url.searchParams.get('until')).toBe(end);
    return json(route, cursor === 'empty-page' ? envelope([], 'final-page') : envelope(logs.slice(2)));
  });
  await page.goto(historyPath);
  await expect(page.getByText('Log retrieval temporarily unavailable.', { exact: true })).toBeVisible();
  fail = false;
  await page.getByRole('button', { name: 'Refresh logs', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Task logs (6)' })).toBeVisible();
  expect(cursors).toEqual([null, 'empty-page', 'final-page']);
  await expect(page.getByText('Log retrieval temporarily unavailable.', { exact: true })).toHaveCount(0);
});

test('live activity drains pages, updates duplicate IDs, and displays the same content and phase filters', async ({ page }) => {
  let pass = 0;
  const requests = [];
  await liveApi(page, async ({ route, url }) => {
    if (url.pathname !== `/api/runs/${RUN_ID}/logs`) return false;
    requests.push(url.searchParams.get('next_token'));
    if (url.searchParams.get('next_token')) return json(route, envelope(logs.slice(2)));
    pass++;
    return json(route, pass === 1 ? envelope(logs.slice(0, 2), 'remaining') : envelope([
      ...logs, { ...logs[0], status: 'completed', title: 'Agent request received' },
    ]));
  });
  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(8);
  expect(requests.slice(0, 2)).toEqual([null, 'remaining']);
  await page.getByRole('button', { name: 'Refresh logs', exact: true }).click();
  await expect(page.locator('[data-entry-id="agent-request"]')).toContainText('Agent request received');
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(8);
  await page.getByLabel('Filter activity by phase').selectOption('scanner');
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(6);
  await page.getByLabel('Search activity logs').fill('Settlement integrity');
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(1);
  await expect(page.locator('[data-log-kind="reasoning"]')).toContainText('business priority');
  await page.getByRole('heading', { name: 'Activity Feed', exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: '/tmp/threatforest-observability-live.png', fullPage: true });
});

test('reading earlier live logs disables auto-follow and preserves scroll on refresh', async ({ page }) => {
  await liveApi(page);
  await page.goto(`/runs/${RUN_ID}/progress`);
  const feed = page.getByTestId('activity-feed');
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(8);
  await expect(page.getByLabel('Follow latest')).toBeChecked();
  await feed.evaluate((element) => { element.scrollTop = 0; element.dispatchEvent(new Event('scroll', { bubbles: true })); });
  await expect(page.getByLabel('Follow latest')).not.toBeChecked();
  await page.getByRole('button', { name: 'Refresh logs', exact: true }).click();
  await expect.poll(() => feed.evaluate((element) => element.scrollTop)).toBe(0);
  await page.getByLabel('Follow latest').check();
  await expect.poll(() => feed.evaluate((element) => element.scrollHeight - element.scrollTop - element.clientHeight)).toBeLessThan(2);
});

test('live logs show absent reasoning explicitly and remain usable on a narrow screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await liveApi(page, async ({ route, url }) => {
    if (url.pathname !== `/api/runs/${RUN_ID}/logs`) return false;
    return json(route, envelope([log('plain-model', 1, { category: 'model', title: 'Model response',
      content: [{ kind: 'response', text: 'Recorded output only.', truncated: true }] })]));
  });
  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByText('No reasoning content was recorded for this response.')).toBeVisible();
  await expect(page.getByText(/recorded content is truncated/)).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('automatic live polling receives later responses and stops after terminal log delivery settles', async ({ page }) => {
  await page.clock.install();
  let requests = 0;
  await liveApi(page, async ({ route, url }) => {
    if (url.pathname !== `/api/runs/${RUN_ID}/logs`) return false;
    requests++;
    return json(route, envelope(requests === 1 ? logs.slice(0, 1) : logs));
  });
  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(1);
  await page.clock.fastForward(6000);
  await expect(page.getByTestId('execution-log-entry')).toHaveCount(8);
  await page.evaluate(() => window.__runSocket.dispatchEvent(new MessageEvent('message', {
    data: JSON.stringify({ type: 'run_complete', details: { status: 'complete' } }),
  })));
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveCount(0);
  await page.clock.fastForward(75_000);
  await expect.poll(() => requests).toBeGreaterThanOrEqual(3);
  // Wait for the final fetch to complete before checking that no timer remains.
  await expect(page.getByText('Execution logs could not be refreshed')).toHaveCount(0);
  const settled = requests;
  await page.clock.fastForward(60_000);
  expect(requests).toBe(settled);
});

test('a deleted application does not hide Stop, and HTTP confirms stop without a stream event', async ({ page }) => {
  await page.clock.install();
  let requested = false;
  let confirmed = false;
  await liveApi(page, async ({ route, request, url }) => {
    if (url.pathname === `/api/applications/by-id/${APPLICATION_ID}`) {
      return json(route, { detail: 'Unknown application' }, 404);
    }
    if (url.pathname === `/api/runs/${RUN_ID}/stop`) {
      requested = true;
      return json(route, { status: 'stop_requested' });
    }
    if (url.pathname === `/api/runs/${RUN_ID}` && request.method() === 'GET') {
      return json(route, {
        run_id: RUN_ID, status: confirmed ? 'stopped' : 'running',
        config: { app_id: APPLICATION_ID }, started_at: new Date(baseTime).toISOString(),
      });
    }
    return false;
  });
  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByText(/application is no longer available/)).toBeVisible();
  await expect(page.getByText(/This run is no longer active in the server/)).toHaveCount(0);
  await page.getByRole('button', { name: 'Stop', exact: true }).click();
  expect(requested).toBe(true);
  await expect(page.getByText('Stop requested. Waiting for the run to confirm it has stopped.')).toBeVisible();
  await expect(page.getByText('Scan stopped. Start a new run to analyze this project again.')).toHaveCount(0);
  confirmed = true;
  await page.clock.fastForward(3000);
  await expect(page.getByText('Scan stopped. Start a new run to analyze this project again.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stop', exact: true })).toHaveCount(0);
});

test('an unconfirmed Stop becomes retryable instead of disabling controls indefinitely', async ({ page }) => {
  await page.clock.install();
  await liveApi(page, async ({ route, url }) => {
    if (url.pathname === `/api/runs/${RUN_ID}/stop`) return json(route, { status: 'stop_requested' });
    return false;
  });
  await page.goto(`/runs/${RUN_ID}/progress`);
  await page.getByRole('button', { name: 'Stop', exact: true }).click();
  await expect(page.getByText('Stop requested. Waiting for the run to confirm it has stopped.')).toBeVisible();
  await page.clock.fastForward(121_000);
  await expect(page.getByText(/confirmation is taking longer than expected/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeEnabled();
  await expect(page.getByText('Scan stopped. Start a new run to analyze this project again.')).toHaveCount(0);
});

for (const phase of ['scanner_review', 'interviewer', 'threat_review']) {
  test(`Stop remains available during ${phase} and closes the review when confirmed`, async ({ page }) => {
    await liveApi(page);
    await page.goto(`/runs/${RUN_ID}/progress`);
    await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeVisible();
    await page.evaluate(phase => window.__runSocket.dispatchEvent(new MessageEvent('message', {
      data: JSON.stringify({
        type: 'awaiting_input', stage: phase,
        details: { phase, scanner_data: {}, threats: [], questions: ['What matters most?'] },
      }),
    })), phase);
    await expect(page.getByRole('button', { name: 'Pause', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeEnabled();
    await page.evaluate(() => window.__runSocket.dispatchEvent(new MessageEvent('message', {
      data: JSON.stringify({ type: 'scan_stopped' }),
    })));
    await expect(page.getByText('Scan stopped. Start a new run to analyze this project again.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Stop', exact: true })).toHaveCount(0);
  });
}

test('historical review replay does not reopen answered gates or report missing pending input', async ({ page }) => {
  await liveApi(page);
  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toBeVisible();
  await page.evaluate(() => {
    const send = data => window.__runSocket.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(data) }));
    send({ type: 'awaiting_input', stage: 'scanner_review', details: { phase: 'scanner_review', scanner_data: {} } });
    send({ type: 'stage_complete', stage: 'scanner_review' });
    send({ type: 'awaiting_input', stage: 'threat_review', details: { phase: 'threat_review', interaction_id: 'answered' } });
    send({ type: 'stage_complete', stage: 'threat_review' });
    send({ type: 'stage_start', stage: 'parallel_pipeline' });
  });
  await expect(page.getByRole('button', { name: 'Pause', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stop', exact: true })).toBeEnabled();
  await expect(page.getByText(/Failed to load pending review/)).toHaveCount(0);
});
