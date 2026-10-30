import { expect, test } from '@playwright/test';
import { APPLICATION_ID, RUN_ID, installBaseApi, json } from './support/mock-api.mjs';

test('progress client requests a replay ticket and includes it in the WebSocket URL', async ({
  page,
}) => {
  await page.addInitScript(() => {
    class CapturingWebSocket extends EventTarget {
      constructor(url) {
        super();
        if (String(url).includes('/ws/runs/')) {
          window.__capturedWebSocketUrl = String(url);
        }
        setTimeout(() => this.dispatchEvent(new Event('open')), 0);
      }
      send(value) {
        window.__capturedWebSocketMessage = String(value);
      }
      close() {}
    }
    window.WebSocket = CapturingWebSocket;
  });
  await installBaseApi(page, async ({ route, request, url }) => {
    if (url.pathname === `/api/runs/${RUN_ID}/replay-ticket`) {
      expect(request.postDataJSON()).toEqual({ after_sequence: -1 });
      return json(route, {
        ticket: 'ticket.playwright.signature',
        expires_at: '2026-08-19T10:05:00.000Z',
      });
    }
    if (url.pathname === `/api/runs/${RUN_ID}`) {
      return json(route, {
        run_id: RUN_ID,
        status: 'running',
        config: {
          project_path: '',
          threat_source: 'auto',
          threat_file_path: null,
          frameworks: null,
          resume_run_dir: null,
          skip_nodes: [],
          app_id: APPLICATION_ID,
        },
        started_at: '2026-08-19T10:00:00.000Z',
        completed_at: null,
        output_dir: null,
        error: null,
        paused_at_stage: null,
        paused_at: null,
      });
    }
    return false;
  });

  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect
    .poll(() => page.evaluate(() => window.__capturedWebSocketUrl || ''))
    .toContain('ticket=ticket.playwright.signature');
  const url = await page.evaluate(() => window.__capturedWebSocketUrl);
  expect(url).toContain(`/ws/runs/${RUN_ID}`);
  await expect
    .poll(() => page.evaluate(() => window.__capturedWebSocketMessage || ''))
    .toBe(JSON.stringify({ action: 'replay', after_sequence: -1 }));
});
