import { defineConfig, devices } from '@playwright/test';

const live = process.env.TF_PLAYWRIGHT_LIVE === '1';
const minimalArtifacts = process.env.TF_PLAYWRIGHT_MINIMAL_ARTIFACTS === '1';
const localPort = process.env.TF_PLAYWRIGHT_PORT || '3100';
const localBaseURL = `http://127.0.0.1:${localPort}`;
const baseURL =
  process.env.TF_PLAYWRIGHT_BASE_URL ||
  process.env.TF_BASE_URL ||
  localBaseURL;

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  workers: process.env.CI ? 1 : 2,
  retries: process.env.CI ? 2 : 0,
  timeout: 30_000,
  expect: {
    timeout: 8_000,
    toHaveScreenshot: {
      animations: 'disabled',
      caret: 'hide',
      maxDiffPixelRatio: 0.01,
    },
  },
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    viewport: { width: 1440, height: 900 },
    colorScheme: 'light',
    locale: 'en-GB',
    timezoneId: 'Europe/London',
    actionTimeout: 10_000,
    navigationTimeout: 20_000,
    screenshot: 'only-on-failure',
    trace: minimalArtifacts ? 'off' : 'retain-on-failure',
    video: minimalArtifacts ? 'off' : 'retain-on-failure',
  },
  webServer: live
    ? undefined
    : {
        command: 'npm run build && node e2e/support/static-server.mjs',
        url: localBaseURL,
        reuseExistingServer: false,
        timeout: 120_000,
      },
  reporter: process.env.CI
    ? [['line'], ['html', { open: 'never', outputFolder: 'playwright-report' }]]
    : 'list',
  outputDir: 'test-results',
});
