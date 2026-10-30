import { chmod, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from '@playwright/test';
import '../test/support/env.mjs';

const STORAGE_KEY = 'threatforest.oauth.tokens.v1';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function shellValue(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

async function login(browser, baseUrl, username, password, label) {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    console.log(`Authenticating test user ${label} through Cognito PKCE`);
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
    const authorizationUrl = new URL(page.url());
    if (
      !['/oauth2/authorize', '/login'].includes(authorizationUrl.pathname) ||
      authorizationUrl.searchParams.get('code_challenge_method') !== 'S256'
    ) {
      throw new Error(`Expected Cognito PKCE authorization, received ${page.url()}`);
    }

    const usernameInput = page
      .locator(
        'input[name="username"], input[type="email"], input[autocomplete="username"]',
      )
      .first();
    const passwordInput = page
      .locator('input[name="password"], input[type="password"]')
      .first();
    await usernameInput.waitFor({ state: 'visible', timeout: 30_000 });
    await passwordInput.waitFor({ state: 'visible', timeout: 30_000 });
    await usernameInput.fill(username);
    await passwordInput.click();
    await passwordInput.pressSequentially(password, { delay: 5 });
    if ((await passwordInput.inputValue()) !== password) {
      throw new Error('Cognito password field did not retain the supplied value');
    }

    const submit = page.locator('button[type="submit"], input[type="submit"]').first();
    await submit.click();
    try {
      await page.waitForURL(
        (url) =>
          url.origin === new URL(baseUrl).origin && url.pathname === '/',
        { timeout: 60_000 },
      );
    } catch {
      const alerts = await page.locator('[role="alert"]').allInnerTexts();
      const bodyText = await page.locator('body').innerText();
      const diagnosticLines = bodyText
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => /error|incorrect|invalid|password|try again/i.test(line))
        .slice(0, 5);
      throw new Error(
        `Cognito login did not return to ThreatForest; current URL is ` +
          `${page.url()}` +
          `${alerts.length > 0 ? `; alerts: ${alerts.join(' | ')}` : ''}` +
          `${diagnosticLines.length > 0 ? `; page: ${diagnosticLines.join(' | ')}` : ''}`,
      );
    }
    await page.waitForFunction(
      (key) => window.sessionStorage.getItem(key) !== null,
      STORAGE_KEY,
      { timeout: 60_000 },
    );
    const stored = await page.evaluate((key) => {
      const raw = window.sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    }, STORAGE_KEY);
    if (!stored?.accessToken) {
      throw new Error('Cognito callback did not store an access token');
    }
    return stored.accessToken;
  } finally {
    await context.close();
  }
}

const baseUrl = required('TF_BASE_URL').replace(/\/+$/, '');
const outputPath = resolve(
  process.env.TF_TOKEN_ENV_FILE?.trim() ||
    '/tmp/threatforest-deployed-test-tokens.env',
);
const users = [
  {
    label: 'A',
    username: required('TF_TEST_USER_A_USERNAME'),
    password: required('TF_TEST_USER_A_PASSWORD'),
  },
  {
    label: 'B',
    username: required('TF_TEST_USER_B_USERNAME'),
    password: required('TF_TEST_USER_B_PASSWORD'),
  },
];

const browser = await chromium.launch({ headless: true });
try {
  const tokens = {};
  for (const user of users) {
    tokens[user.label] = await login(
      browser,
      baseUrl,
      user.username,
      user.password,
      user.label,
    );
  }
  const content =
    '# Generated short-lived Cognito access tokens. Delete after testing.\n' +
    users
      .map(
        (user) =>
          `TF_TEST_USER_${user.label}_ACCESS_TOKEN=` +
          `${shellValue(tokens[user.label])}`,
      )
      .join('\n') +
    '\n';
  await writeFile(outputPath, content, { encoding: 'utf8', mode: 0o600 });
  await chmod(outputPath, 0o600);
  console.log(`Wrote short-lived test tokens to ${outputPath}`);
} finally {
  await browser.close();
}
