import { expect, test } from '@playwright/test';
import {
  APPLICATION_ID,
  RUN_ID,
  application,
  installBaseApi,
  json,
} from './support/mock-api.mjs';

test('interviewer HITL can be skipped without leaving the progress workflow', async ({
  page,
}) => {
  let submitted = null;
  await page.addInitScript(() => {
    class MockWebSocket extends EventTarget {
      static OPEN = 1;
      readyState = 0;
      constructor(url) {
        super();
        window.__openedWebSocket = String(url);
        setTimeout(() => {
          this.readyState = MockWebSocket.OPEN;
          this.dispatchEvent(new Event('open'));
          setTimeout(() => {
            this.dispatchEvent(
              new MessageEvent('message', {
                data: JSON.stringify({
                  type: 'awaiting_input',
                  stage: 'Context Validation',
                  sequence: 3,
                  event_id: 'event_hitl',
                  server_ts: Date.now(),
                  details: {
                    phase: 'interviewer',
                    message: 'Confirm the service boundary.',
                    questions: ['Is the API internet-facing?'],
                  },
                }),
              }),
            );
          }, 20);
        }, 10);
      }
      send() {}
      close() {
        this.dispatchEvent(new CloseEvent('close', { code: 1000 }));
      }
    }
    window.WebSocket = MockWebSocket;
  });
  await installBaseApi(page, async ({ route, request, url }) => {
    if (url.pathname === `/api/runs/${RUN_ID}/replay-ticket`) {
      return json(route, {
        ticket: 'signed-replay-ticket',
        expires_at: '2026-08-19T10:05:00.000Z',
      });
    }
    if (url.pathname === `/api/runs/${RUN_ID}` && request.method() === 'GET') {
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
    if (url.pathname === `/api/applications/by-id/${APPLICATION_ID}`) {
      return json(route, application);
    }
    if (url.pathname === `/api/runs/${RUN_ID}/respond`) {
      submitted = request.postDataJSON();
      return json(route, { ok: true });
    }
    return false;
  });

  await page.goto(`/runs/${RUN_ID}/progress`);
  await expect(page.getByTestId('interviewer-panel')).toBeVisible();
  await expect(page.getByText('Is the API internet-facing?')).toBeVisible();
  await page.getByTestId('interviewer-skip').click();
  await expect(page.getByTestId('interviewer-panel')).toBeHidden();
  expect(submitted).toEqual({ text: null });
});
