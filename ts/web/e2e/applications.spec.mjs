import { expect, test } from '@playwright/test';
import { installBaseApi } from './support/mock-api.mjs';

test('applications workspace is usable at desktop resolution', async ({ page }) => {
  await installBaseApi(page);
  await page.goto('/');

  await expect(page.getByRole('heading', { name: /Applications/i })).toBeVisible();
  await expect(page.getByText('Payments Service', { exact: true })).toBeVisible();
  await expect(page.getByText('Processes card payments and settlement events.')).toBeVisible();
  await expect(page.getByText('1', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
});
