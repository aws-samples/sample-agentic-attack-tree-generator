import { expect, test } from '@playwright/test';
import { installBaseApi } from './support/mock-api.mjs';

test('applications workspace desktop visual baseline', async ({ page }) => {
  await installBaseApi(page);
  await page.goto('/');
  const applicationLink = page.getByText('Payments Service', { exact: true });
  const signOut = page.getByRole('button', { name: 'Sign out' });
  await expect(applicationLink).toBeVisible();
  await expect(signOut).toBeVisible();

  const screenshot = await page.screenshot({
    fullPage: true,
    animations: 'disabled',
  });
  expect(screenshot.byteLength).toBeGreaterThan(20_000);

  const layout = await page.evaluate(() => ({
    viewportWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
    viewportHeight: document.documentElement.clientHeight,
    scrollHeight: document.documentElement.scrollHeight,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.scrollHeight).toBeGreaterThanOrEqual(layout.viewportHeight);

  const appBox = await applicationLink.boundingBox();
  const signOutBox = await signOut.boundingBox();
  expect(appBox).not.toBeNull();
  expect(signOutBox).not.toBeNull();
  if (appBox === null || signOutBox === null) {
    throw new Error('Visible desktop controls did not produce measurable layout boxes.');
  }
  expect(rectanglesOverlap(appBox, signOutBox)).toBe(false);
});

function rectanglesOverlap(left, right) {
  return !(
    left.x + left.width <= right.x ||
    right.x + right.width <= left.x ||
    left.y + left.height <= right.y ||
    right.y + right.height <= left.y
  );
}
