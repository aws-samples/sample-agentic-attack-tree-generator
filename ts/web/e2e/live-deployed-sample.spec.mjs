import { expect, test } from '@playwright/test';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';

const enabled = process.env.TF_PLAYWRIGHT_LIVE_SAMPLE === '1';
const baseUrl = process.env.TF_PLAYWRIGHT_BASE_URL?.replace(/\/+$/, '');
const username = process.env.TF_BROWSER_E2E_USERNAME;
const password = process.env.TF_BROWSER_E2E_PASSWORD;
const artifactBucket = process.env.TF_ARTIFACT_BUCKET;
const region = process.env.TF_REGION || 'eu-west-2';
const sampleDirectory = process.env.TF_BROWSER_E2E_SAMPLE_DIR || '';
const artifactDirectory =
  process.env.TF_BROWSER_E2E_ARTIFACT_DIR ||
  '/tmp/threatforest-live-browser-e2e';
const resumeResultPath = process.env.TF_BROWSER_E2E_RESUME_RESULT;

const sourceFiles = [
  resolve(sampleDirectory, 'overview.md'),
  resolve(sampleDirectory, 'healthcare-analytics-environment.pdf'),
  resolve(sampleDirectory, 'healthcare-analytics-environment.jpg'),
];
const threatFile = resolve(
  sampleDirectory,
  'Healthcare_Analytics_Platform_HCLS_Example_generated_threat_statements.md',
);

function required(value, name) {
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

async function isVisible(locator) {
  return locator.isVisible().catch(() => false);
}

function safeUrl(value) {
  const url = new URL(value);
  url.search = '';
  url.hash = '';
  return url.toString();
}

function sanitizeMessage(value) {
  return value.replace(/https:\/\/[^\s"'<>]+/g, (candidate) => {
    try {
      return safeUrl(candidate);
    } catch {
      return '<invalid-url>';
    }
  });
}

function isExpectedCognitoLoginAbort(request) {
  const url = new URL(request.url());
  return (
    request.method() === 'POST' &&
    url.hostname.endsWith('.amazoncognito.com') &&
    url.pathname === '/login' &&
    request.failure()?.errorText === 'net::ERR_ABORTED'
  );
}

function isExpectedArtifactUploadAbort(request) {
  if (
    !artifactBucket ||
    request.method() !== 'PUT' ||
    request.failure()?.errorText !== 'net::ERR_ABORTED'
  ) {
    return false;
  }
  const url = new URL(request.url());
  return (
    url.hostname === `${artifactBucket}.s3.${region}.amazonaws.com` &&
    url.pathname.includes('/uploads/')
  );
}

async function loginThroughCognito(page) {
  await page.goto(required(baseUrl, 'TF_PLAYWRIGHT_BASE_URL'), {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });

  const authorizationUrl = new URL(page.url());
  expect(['/oauth2/authorize', '/login']).toContain(authorizationUrl.pathname);
  expect(authorizationUrl.searchParams.get('response_type')).toBe('code');
  expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');

  const usernameInput = page
    .locator(
      'input[name="username"], input[type="email"], input[autocomplete="username"]',
    )
    .first();
  const passwordInput = page
    .locator('input[name="password"], input[type="password"]')
    .first();
  await usernameInput.waitFor({ state: 'visible', timeout: 30_000 });
  await usernameInput.fill(required(username, 'TF_BROWSER_E2E_USERNAME'));
  await passwordInput.fill(required(password, 'TF_BROWSER_E2E_PASSWORD'));
  await page.locator('button[type="submit"], input[type="submit"]').first().click();
  await page.waitForURL(
    (url) => url.origin === new URL(baseUrl).origin && url.pathname === '/',
    { timeout: 60_000 },
  );
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible({
    timeout: 30_000,
  });
}

async function createApplication(page, name) {
  await page.getByTestId('create-application').click();
  await page.waitForURL(/\/applications\/new\/?$/);

  await page.getByPlaceholder('e.g. Payments API').fill(name);
  await page.getByRole('button', { name: 'Next', exact: true }).click();

  const projectInput = page
    .getByTestId('application-file-upload')
    .locator('input[type="file"]');
  await projectInput.setInputFiles(sourceFiles);
  for (const path of sourceFiles) {
    await expect(page.getByText(basename(path), { exact: true })).toBeVisible();
  }
  await page.getByRole('button', { name: 'Next', exact: true }).click();

  await page
    .getByPlaceholder(/A healthcare intake API/)
    .fill(
      'Healthcare analytics platform processing PHI through an AWS data lake, ' +
        'analytics, machine learning, reporting, and clinical integration services.',
    );
  await page
    .getByPlaceholder('e.g. SOC2, HIPAA, PCI-DSS')
    .fill('HIPAA');
  await page.getByRole('button', { name: 'Add framework', exact: true }).click();
  await page.getByText('Choose a sensitivity level', { exact: true }).click();
  await page.getByText(/^PHI\b/).click();
  await page.getByRole('button', { name: 'Next', exact: true }).click();

  await expect(
    page.getByRole('heading', { name: 'Review & create', level: 2 }),
  ).toBeVisible();
  await expect(page.getByText(name, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Create application', exact: true }).click();
  await page.waitForURL(/\/applications\/app_[a-z0-9]+\/?$/, {
    timeout: 60_000,
  });
  return new URL(page.url()).pathname.split('/').filter(Boolean).at(-1);
}

async function selectRunInputs(page) {
  await page.getByTestId('start-new-threat-model').click();
  await page.waitForURL(/\/applications\/app_[a-z0-9]+\/runs\/new\/?$/);
  await expect(page.getByRole('heading', { name: 'New threat model' })).toBeVisible();

  await page
    .getByText('Provide existing threat statements file', { exact: true })
    .click();
  const threatInput = page
    .getByTestId('threat-file-upload')
    .locator('input[type="file"]');
  await threatInput.setInputFiles(threatFile);
  await expect(page.getByText(basename(threatFile), { exact: true })).toBeVisible();

  const frameworkCheckboxes = page.getByRole('checkbox');
  await expect(frameworkCheckboxes).toHaveCount(3);
  for (let index = 0; index < 3; index += 1) {
    await expect(frameworkCheckboxes.nth(index)).toBeChecked();
  }
}

async function waitForRunCompletion(page, evidence) {
  const deadline = Date.now() + 2 * 60 * 60_000;
  let interviewerRound = 0;

  while (Date.now() < deadline) {
    const success = page.getByText('View Dashboard', { exact: true });
    if (await isVisible(success)) return;

    const failureAlert = page
      .locator('[role="alert"]')
      .filter({ hasText: /run failed|failed without reporting|agent run.*failed/i })
      .first();
    if (await isVisible(failureAlert)) {
      throw new Error(`Run failed in the UI: ${await failureAlert.innerText()}`);
    }

    const scannerReview = page.getByTestId('scanner-review-inline');
    if (
      evidence.hitl.scannerReview === 0 &&
      (await isVisible(scannerReview))
    ) {
      await page.screenshot({
        path: join(artifactDirectory, '04-scanner-review.png'),
        fullPage: true,
      });
      await page.getByTestId('scanner-review-confirm').click();
      evidence.hitl.scannerReview += 1;
      await expect(scannerReview).toBeHidden({ timeout: 60_000 });
      continue;
    }

    const interviewer = page.getByTestId('interviewer-panel');
    const interviewerInput = interviewer.getByRole('textbox', {
      name: 'Type your response...',
    });
    const interviewerSubmit = interviewer.getByRole('button', {
      name: 'Submit',
      exact: true,
    });
    if (
      (await isVisible(interviewer)) &&
      (await interviewerInput.isEnabled().catch(() => false))
    ) {
      interviewerRound += 1;
      await page.screenshot({
        path: join(
          artifactDirectory,
          `05-interviewer-round-${interviewerRound}.png`,
        ),
        fullPage: true,
      });
      const response =
        interviewerRound === 1
          ? 'The platform processes PHI across S3 raw, curated, and analytics ' +
            'zones. Lake Formation and IAM enforce least privilege. Data arrives ' +
            'through VPN or Direct Connect and AWS Transfer Family. SageMaker, ' +
            'Redshift, Glue, and QuickSight consume the data. Prioritize ' +
            'confidentiality, then integrity, then availability, and retain HIPAA ' +
            'evidence and tenant boundaries throughout the analysis.'
          : 'No additional corrections. Continue with the confirmed healthcare, ' +
            'PHI, HIPAA, identity, network, and data-lake context.';
      await interviewerInput.fill(response);
      await expect(interviewerSubmit).toBeEnabled();
      await interviewerSubmit.click();
      evidence.hitl.interviewer += 1;
      await page.waitForTimeout(2_000);
      continue;
    }

    const threatReview = page.getByTestId('threat-review-panel');
    if (
      evidence.hitl.threatReview === 0 &&
      (await isVisible(threatReview))
    ) {
      const threatRows = threatReview.locator('[data-testid^="threat-review-row-"]');
      const count = await threatRows.count();
      expect(count).toBeGreaterThan(0);
      evidence.reviewedThreatCount = count;
      await page.screenshot({
        path: join(artifactDirectory, '06-threat-review.png'),
        fullPage: true,
      });
      await page.getByTestId('threat-review-proceed').click();
      evidence.hitl.threatReview += 1;
      await expect(threatReview).toBeHidden({ timeout: 60_000 });
      continue;
    }

    await page.waitForTimeout(2_000);
  }

  throw new Error('Timed out waiting for the browser-driven run to complete.');
}

test(
  'live browser completes an HCLS sample through Cognito, HITL, dashboard, and export',
  async ({ page }) => {
    test.skip(!enabled, 'Set TF_PLAYWRIGHT_LIVE_SAMPLE=1 and the browser E2E credentials.');
    required(sampleDirectory, 'TF_BROWSER_E2E_SAMPLE_DIR');
    test.setTimeout(2 * 60 * 60_000 + 20 * 60_000);
    await mkdir(artifactDirectory, { recursive: true });
    for (const path of [...sourceFiles, threatFile]) {
      const metadata = await stat(path);
      expect(metadata.size).toBeGreaterThan(0);
    }

    const previousEvidence = resumeResultPath
      ? JSON.parse(await readFile(resumeResultPath, 'utf8'))
      : null;
    const evidence = previousEvidence
      ? {
          ...previousEvidence,
          baseUrl,
          resumedAt: new Date().toISOString(),
          previousFailure: previousEvidence.failure,
          pageErrors: [],
          consoleErrors: [],
          expectedRequestAborts: previousEvidence.expectedRequestAborts || [],
          failedRequests: [],
          httpErrors: [],
          completedAt: null,
          failure: null,
        }
      : {
          startedAt: new Date().toISOString(),
          baseUrl,
          sampleDirectory,
          sourceFiles: sourceFiles.map((path) => basename(path)),
          threatFile: basename(threatFile),
          applicationId: null,
          runId: null,
          dashboardUrl: null,
          dashboardThreatCount: null,
          dashboardAttackTreeCount: null,
          renderedThreatRows: null,
          renderedAttackTreeNodes: null,
          reportFilename: null,
          reportBytes: null,
          runRequest: null,
          reviewedThreatCount: null,
          hitl: {
            scannerReview: 0,
            interviewer: 0,
            threatReview: 0,
          },
          pageErrors: [],
          consoleErrors: [],
          expectedRequestAborts: [],
          failedRequests: [],
          httpErrors: [],
          completedAt: null,
          failure: null,
        };

    page.on('pageerror', (error) => evidence.pageErrors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') {
        evidence.consoleErrors.push(sanitizeMessage(message.text()));
      }
    });
    page.on('requestfailed', (request) => {
      if (isExpectedCognitoLoginAbort(request)) return;
      if (isExpectedArtifactUploadAbort(request)) {
        evidence.expectedRequestAborts.push({
          method: request.method(),
          url: safeUrl(request.url()),
          error: request.failure()?.errorText || 'unknown',
        });
        return;
      }
      evidence.failedRequests.push({
        method: request.method(),
        url: safeUrl(request.url()),
        error: request.failure()?.errorText || 'unknown',
      });
    });
    page.on('response', (response) => {
      if (response.status() < 400) return;
      evidence.httpErrors.push({
        method: response.request().method(),
        url: safeUrl(response.url()),
        status: response.status(),
      });
    });
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.pathname === '/api/runs' && request.method() === 'POST') {
        evidence.runRequest = request.postDataJSON();
      }
    });

    try {
      await loginThroughCognito(page);
      if (resumeResultPath) {
        expect(evidence.applicationId).toMatch(/^app_[a-z0-9]+$/);
        expect(evidence.runId).toMatch(/^run_[a-z0-9]+$/);
        await page.goto(
          `${required(baseUrl, 'TF_PLAYWRIGHT_BASE_URL')}/runs/${evidence.runId}/progress`,
          { waitUntil: 'domcontentloaded', timeout: 60_000 },
        );
        await waitForRunCompletion(page, evidence);
      } else {
        await page.screenshot({
          path: join(artifactDirectory, '01-authenticated-home.png'),
          fullPage: true,
        });

        const applicationName = `HCLS Browser E2E ${Date.now()}`;
        evidence.applicationId = await createApplication(page, applicationName);
        expect(evidence.applicationId).toMatch(/^app_[a-z0-9]+$/);
        await page.screenshot({
          path: join(artifactDirectory, '02-application-created.png'),
          fullPage: true,
        });

        await selectRunInputs(page);
        await page.screenshot({
          path: join(artifactDirectory, '03-run-inputs.png'),
          fullPage: true,
        });
        await page.getByTestId('start-run').click();
        const startOutcome = await Promise.race([
          page
            .waitForURL(/\/runs\/run_[a-z0-9]+\/progress\/?$/, {
              timeout: 30 * 60_000,
            })
            .then(() => ({ kind: 'progress' })),
          page
            .locator('[role="alert"]')
            .filter({ hasText: /\S/ })
            .last()
            .waitFor({ state: 'visible', timeout: 30 * 60_000 })
            .then(async () => ({
              kind: 'error',
              message: await page
                .locator('[role="alert"]')
                .filter({ hasText: /\S/ })
                .last()
                .innerText(),
            })),
        ]);
        if (startOutcome.kind === 'error') {
          throw new Error(`Run submission failed in the UI: ${startOutcome.message}`);
        }
        evidence.runId = new URL(page.url()).pathname
          .split('/')
          .filter(Boolean)
          .at(-2);
        expect(evidence.runId).toMatch(/^run_[a-z0-9]+$/);
        expect(evidence.runRequest?.threat_source).toBe('file');
        expect(evidence.runRequest?.frameworks?.sort()).toEqual([
          'atlas',
          'attack',
          'wiz',
        ]);
        expect(evidence.runRequest?.source_artifact_ids).toBeUndefined();
        expect(evidence.runRequest?.threat_artifact_id).toBeTruthy();

        await waitForRunCompletion(page, evidence);
      }
      expect(evidence.hitl.scannerReview).toBe(1);
      expect(evidence.hitl.interviewer).toBeGreaterThanOrEqual(1);
      expect(evidence.hitl.threatReview).toBe(1);
      await page.screenshot({
        path: join(artifactDirectory, '07-run-complete.png'),
        fullPage: true,
      });

      const dashboardDataPromise = page.waitForResponse(
        (response) =>
          response.request().method() === 'GET' &&
          /\/api\/applications\/app_[a-z0-9]+\/versions\/[^/]+\/data$/.test(
            new URL(response.url()).pathname,
          ) &&
          response.status() === 200,
        { timeout: 5 * 60_000 },
      );
      await page.getByText('View Dashboard', { exact: true }).click();
      const dashboardDataResponse = await dashboardDataPromise;
      const dashboardData = await dashboardDataResponse.json();
      expect(Array.isArray(dashboardData.threats)).toBe(true);
      expect(Array.isArray(dashboardData.attack_trees)).toBe(true);
      evidence.dashboardThreatCount = dashboardData.threats.length;
      evidence.dashboardAttackTreeCount = dashboardData.attack_trees.length;
      expect(evidence.dashboardThreatCount).toBeGreaterThan(0);
      expect(evidence.dashboardAttackTreeCount).toBeGreaterThan(0);
      await expect(page.getByRole('heading', { name: 'Threat Model Summary' })).toBeVisible({
        timeout: 5 * 60_000,
      });
      await expect(page.getByText('Total threats', { exact: true })).toBeVisible();
      await expect(page.getByText('Attack trees', { exact: true })).toBeVisible();
      await expect(
        page.getByText('TTP mappings', { exact: true }).first(),
      ).toBeVisible();
      await expect(page.getByText('Mitigation coverage', { exact: true })).toBeVisible();
      evidence.dashboardUrl = page.url();
      await page.screenshot({
        path: join(artifactDirectory, '08-dashboard.png'),
        fullPage: true,
      });

      await page.getByRole('tab', { name: 'Threats', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: /Threat Statements/ }),
      ).toBeVisible();
      const attackTreeLinks = page.getByRole('button', {
        name: 'See attack tree',
        exact: true,
      });
      await expect(attackTreeLinks.first()).toBeVisible({
        timeout: 5 * 60_000,
      });
      evidence.renderedThreatRows = await attackTreeLinks.count();
      expect(evidence.renderedThreatRows).toBeGreaterThan(0);
      expect(evidence.renderedThreatRows).toBe(
        evidence.dashboardAttackTreeCount,
      );
      await expect(
        page
          .getByRole('tabpanel', { name: 'Threats' })
          .getByText(dashboardData.attack_trees[0].threat_id, {
            exact: true,
          }),
      ).toBeVisible();
      await page.screenshot({
        path: join(artifactDirectory, '09-threat-list.png'),
        fullPage: true,
      });

      await attackTreeLinks.first().click();
      await page.waitForURL(/\/threats\/0\/?$/);
      await expect(
        page.getByRole('heading', { name: 'Attack Tree', exact: true }),
      ).toBeVisible({ timeout: 5 * 60_000 });
      const attackTreeNodes = page.locator('.react-flow__node');
      await expect(attackTreeNodes.first()).toBeVisible({
        timeout: 5 * 60_000,
      });
      evidence.renderedAttackTreeNodes = await attackTreeNodes.count();
      expect(evidence.renderedAttackTreeNodes).toBeGreaterThan(0);
      await page.screenshot({
        path: join(artifactDirectory, '10-attack-tree.png'),
        fullPage: true,
      });

      await page.goto(
        `${required(baseUrl, 'TF_PLAYWRIGHT_BASE_URL')}/applications/${evidence.applicationId}`,
        { waitUntil: 'domcontentloaded' },
      );
      await page.getByTestId('export-tfreport-button').click();
      await page.getByText('Latest version only', { exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Export ThreatForest Report' }),
      ).toBeVisible();
      const downloadPromise = page.waitForEvent('download', {
        timeout: 5 * 60_000,
      });
      await page.getByTestId('confirm-tfreport-export').click();
      const download = await downloadPromise;
      const reportPath = join(
        artifactDirectory,
        download.suggestedFilename(),
      );
      await download.saveAs(reportPath);
      const report = await readFile(reportPath);
      expect(report.subarray(0, 2).toString('ascii')).toBe('PK');
      evidence.reportFilename = download.suggestedFilename();
      evidence.reportBytes = report.byteLength;
      expect(evidence.reportBytes).toBeGreaterThan(0);

      evidence.completedAt = new Date().toISOString();
      expect(evidence.pageErrors).toEqual([]);
      expect(evidence.consoleErrors).toEqual([]);
      expect(evidence.failedRequests).toEqual([]);
      expect(evidence.httpErrors).toEqual([]);
    } catch (error) {
      evidence.failure = error instanceof Error ? error.stack || error.message : String(error);
      await page
        .screenshot({
          path: join(artifactDirectory, 'failure.png'),
          fullPage: true,
        })
        .catch(() => {});
      throw error;
    } finally {
      await writeFile(
        join(artifactDirectory, 'result.json'),
        `${JSON.stringify(evidence, null, 2)}\n`,
        { encoding: 'utf8', mode: 0o600 },
      );
    }
  },
);
