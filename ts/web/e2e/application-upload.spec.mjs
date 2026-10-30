import { expect, test } from '@playwright/test';
import {
  APPLICATION_ID,
  RUN_ID,
  application,
  installBaseApi,
  json,
} from './support/mock-api.mjs';

test('application creation uploads project evidence without asking for a local path', async ({
  page,
}) => {
  const requests = [];
  let createBody;
  await installBaseApi(page, async ({ route, request, url }) => {
    requests.push(`${request.method()} ${url.pathname}`);
    if (url.pathname === '/api/applications' && request.method() === 'POST') {
      createBody = request.postDataJSON();
      return json(route, { ...application, project_path: '' }, 201);
    }
    if (
      url.pathname === `/api/applications/${APPLICATION_ID}/uploads` &&
      request.method() === 'POST'
    ) {
      return json(route, {
        upload_id: 'upload_playwright',
        manifest: uploadManifest('pending'),
        part_size_bytes: 5 * 1024 * 1024,
        part_count: 1,
      });
    }
    if (url.pathname.endsWith('/uploads/upload_playwright/parts')) {
      return json(route, {
        upload_id: 'upload_playwright',
        part_number: 1,
        url: 'https://upload.example.test/part-1',
        expires_at: '2026-09-15T10:15:00.000Z',
        headers: {},
      });
    }
    if (url.pathname.endsWith('/uploads/upload_playwright/complete')) {
      return json(route, {
        upload_id: 'upload_playwright',
        manifest: uploadManifest('uploaded'),
      });
    }
    if (
      url.pathname.endsWith('/uploads/upload_playwright') &&
      request.method() === 'GET'
    ) {
      return json(route, {
        upload_id: 'upload_playwright',
        manifest: uploadManifest('ready'),
      });
    }
    return false;
  });
  installUploadTarget(page);

  await page.goto('/applications/new');
  await expect(page.getByText('Project path', { exact: true })).toHaveCount(0);
  await page.getByPlaceholder('e.g. Payments API').fill('Uploaded Application');
  await page.getByRole('button', { name: 'Next', exact: true }).click();

  await page
    .getByTestId('application-file-upload')
    .locator('input[type="file"]')
    .setInputFiles({
      name: 'architecture.md',
      mimeType: 'text/markdown',
      buffer: Buffer.from('# Architecture\n\nUses Cognito and S3.'),
    });
  await page.getByRole('button', { name: 'Next', exact: true }).click();

  await page
    .getByPlaceholder(/A healthcare intake API/)
    .fill('A hosted application with encrypted project evidence.');
  await page.getByPlaceholder('e.g. SOC2, HIPAA, PCI-DSS').fill('SOC2');
  await page.getByRole('button', { name: 'Add framework' }).click();
  await page.getByText('Choose a sensitivity level', { exact: true }).click();
  await page.getByText(/^Internal\b/).click();
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await page.getByRole('button', { name: 'Create application' }).click();

  await page.waitForURL(new RegExp(`/applications/${APPLICATION_ID}/?$`));
  expect(createBody.project_path).toBe('');
  expect(requests).toContain(`POST /api/applications/${APPLICATION_ID}/uploads`);
  expect(requests).toContain(
    `POST /api/applications/${APPLICATION_ID}/uploads/upload_playwright/complete`,
  );
});

test('project evidence uploads, normalizes, and starts an app-scoped run', async ({
  page,
}) => {
  const requests = [];
  let runBody;
  await installBaseApi(page, async ({ route, request, url }) => {
    requests.push(`${request.method()} ${url.pathname}`);
    if (
      url.pathname === `/api/applications/${APPLICATION_ID}/uploads` &&
      request.method() === 'POST'
    ) {
      return json(route, {
        upload_id: 'upload_playwright',
        manifest: {
          schema_version: 1,
          owner_id: 'user_playwright',
          upload_id: 'upload_playwright',
          application_id: APPLICATION_ID,
          filename: 'architecture.md',
          content_type: 'text/markdown',
          size_bytes: 34,
          status: 'pending',
          parts: [],
          source_artifact: null,
          normalized_artifacts: [],
          created_at: '2026-08-19T10:00:00.000Z',
          updated_at: '2026-08-19T10:00:00.000Z',
          failure_reason: null,
        },
        part_size_bytes: 5 * 1024 * 1024,
        part_count: 1,
      });
    }
    if (url.pathname.endsWith('/uploads/upload_playwright/parts')) {
      return json(route, {
        upload_id: 'upload_playwright',
        part_number: 1,
        url: 'https://upload.example.test/part-1',
        expires_at: '2026-08-19T10:15:00.000Z',
        headers: {},
      });
    }
    if (url.pathname.endsWith('/uploads/upload_playwright/complete')) {
      return json(route, { upload_id: 'upload_playwright', manifest: uploadManifest('uploaded') });
    }
    if (
      url.pathname.endsWith('/uploads/upload_playwright') &&
      request.method() === 'GET'
    ) {
      return json(route, { upload_id: 'upload_playwright', manifest: uploadManifest('ready') });
    }
    if (url.pathname === '/api/runs' && request.method() === 'POST') {
      runBody = request.postDataJSON();
      return json(route, { run_id: RUN_ID }, 202);
    }
    return false;
  });
  installUploadTarget(page);

  await page.goto(`/applications/${APPLICATION_ID}/runs/new`);
  await page.getByRole('checkbox', { name: /original-architecture/ }).uncheck();
  const fileInput = page.locator('input[type="file"]').first();
  await fileInput.setInputFiles({
    name: 'architecture.md',
    mimeType: 'text/markdown',
    buffer: Buffer.from('# Architecture\n\nUses Cognito and S3.'),
  });
  await page.getByTestId('start-run').click();
  await page.waitForURL(new RegExp(`/runs/${RUN_ID}/progress/?$`));

  expect(requests).toContain(
    `POST /api/applications/${APPLICATION_ID}/uploads`,
  );
  expect(requests).toContain(
    `POST /api/applications/${APPLICATION_ID}/uploads/upload_playwright/complete`,
  );
  expect(requests).toContain('POST /api/runs');
  expect(runBody.source_artifact_ids).toEqual(['upload_playwright']);
});

test('an app-scoped run reuses ready application evidence without another upload', async ({
  page,
}) => {
  const requests = [];
  let runBody;
  await installBaseApi(page, async ({ route, request, url }) => {
    requests.push(`${request.method()} ${url.pathname}`);
    if (url.pathname === '/api/runs' && request.method() === 'POST') {
      runBody = request.postDataJSON();
      return json(route, { run_id: RUN_ID }, 202);
    }
    return false;
  });

  await page.goto(`/applications/${APPLICATION_ID}/runs/new`);
  await expect(page.getByTestId('additional-project-context-banner')).toContainText(
    'Select the evidence for this run',
  );
  await expect(
    page.getByText('Additional files and directories (optional)', { exact: true }),
  ).toBeVisible();
  await page.getByTestId('start-run').click();
  await page.waitForURL(new RegExp(`/runs/${RUN_ID}/progress/?$`));

  expect(requests.some((request) => request.includes('/uploads'))).toBe(false);
  expect(runBody.source_artifact_ids).toEqual(['source_existing']);
  expect(runBody.app_id).toBe(APPLICATION_ID);
});

function installUploadTarget(page) {
  page.route('https://upload.example.test/part-1', (route) => {
    if (route.request().method() === 'OPTIONS') {
      return route.fulfill({
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'PUT, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '600',
        },
      });
    }
    return route.fulfill({
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': 'ETag',
        ETag: '"playwright-etag"',
      },
    });
  });
}

function uploadManifest(status) {
  return {
    schema_version: 1,
    owner_id: 'user_playwright',
    upload_id: 'upload_playwright',
    application_id: APPLICATION_ID,
    filename: 'architecture.md',
    content_type: 'text/markdown',
    size_bytes: 34,
    status,
    parts: [
      {
        part_number: 1,
        size_bytes: 34,
        etag: '"playwright-etag"',
        checksum_sha256: 'a'.repeat(64),
      },
    ],
    source_artifact:
      status === 'ready'
        ? {
            artifact_id: 'upload_playwright',
            kind: 'source',
            version: 1,
            content_type: 'text/markdown',
            size_bytes: 34,
            sha256: 'b'.repeat(64),
            created_at: '2026-08-19T10:00:02.000Z',
          }
        : null,
    normalized_artifacts: [],
    created_at: '2026-08-19T10:00:00.000Z',
    updated_at: '2026-08-19T10:00:02.000Z',
    failure_reason: null,
  };
}
