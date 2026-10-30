import { expect, test } from '@playwright/test';
import {
  APPLICATION_ID,
  VERSION_ID,
  installBaseApi,
} from './support/mock-api.mjs';

test('latest threat model exports as a tfreport download', async ({ page }) => {
  let exportPath = null;
  await installBaseApi(page, async ({ route, url }) => {
    if (url.pathname.endsWith('/report')) {
      exportPath = `${url.pathname}${url.search}`;
      return route.fulfill({
        status: 200,
        contentType: 'application/zip',
        headers: {
          'Content-Disposition': 'attachment; filename="payments-latest.tfreport"',
        },
        body: Buffer.from('PK-playwright-report'),
      });
    }
    return false;
  });

  await page.goto(`/applications/${APPLICATION_ID}`);
  await page.getByTestId('export-tfreport-button').click();
  await page.getByText('Latest version only', { exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Export ThreatForest Report' })).toBeVisible();

  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('confirm-tfreport-export').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('payments-latest.tfreport');
  expect(exportPath).toBe(
    `/api/applications/${APPLICATION_ID}/versions/${VERSION_ID}/report?include_scanner_context=true`,
  );
});
