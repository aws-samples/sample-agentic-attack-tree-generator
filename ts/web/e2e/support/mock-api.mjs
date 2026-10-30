export const APPLICATION_ID = 'app_playwright';
export const RUN_ID = 'run_playwright';
export const VERSION_ID = 'version_playwright';

export const application = {
  id: APPLICATION_ID,
  name: 'Payments Service',
  slug: 'payments-service',
  project_path: '/hosted/payments-service',
  business_context: {
    description: 'Processes card payments and settlement events.',
    regulatory_frameworks: ['PCI DSS'],
    data_sensitivity: 'regulated_financial',
    cia_priority: ['confidentiality', 'integrity', 'availability'],
  },
  created_at: '2026-08-18T10:00:00.000Z',
  updated_at: '2026-08-18T12:00:00.000Z',
  run_dir_name: 'payments-service',
};

export const applicationSummary = {
  id: APPLICATION_ID,
  name: application.name,
  description: application.business_context.description,
  version_count: 1,
  last_run_date: '2026-08-18T12:00:00.000Z',
  business_context: application.business_context,
  imported: false,
  imported_from: null,
};

export const version = {
  id: VERSION_ID,
  run_date: '2026-08-18T12:00:00.000Z',
  status: 'completed',
  threat_count: 4,
  high_severity_count: 1,
  categories: ['Spoofing', 'Information Disclosure'],
  display_name: 'Threat model 18 Aug 2026',
  run_id: RUN_ID,
};

export async function installBrowserSession(page) {
  await page.addInitScript(() => {
    window.sessionStorage.setItem(
      'threatforest.oauth.tokens.v1',
      JSON.stringify({
        accessToken: 'playwright-access-token',
        idToken: null,
        refreshToken: 'playwright-refresh-token',
        expiresAt: Date.now() + 3_600_000,
        tokenType: 'Bearer',
      }),
    );
  });
}

export function json(route, body, status = 200, headers = {}) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    headers,
    body: JSON.stringify(body),
  });
}

export async function installBaseApi(page, handler, options = {}) {
  if (options.session !== false) {
    await installBrowserSession(page);
  }
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (handler) {
      const handled = await handler({ route, request, url });
      if (handled !== false) return;
    }
    if (url.pathname === '/api/applications') {
      return json(route, { applications: [applicationSummary] });
    }
    if (url.pathname === '/api/runs' && request.method() === 'GET') {
      return json(route, { runs: [] });
    }
    if (url.pathname === '/api/paused-runs') {
      return json(route, { paused_runs: [] });
    }
    if (url.pathname === `/api/applications/by-id/${APPLICATION_ID}`) {
      return json(route, application);
    }
    if (url.pathname === `/api/applications/${APPLICATION_ID}/sources`) {
      return json(route, { sources: [{
        artifact_id: 'source_existing', filename: 'original-architecture.md',
        created_at: '2026-08-19T10:00:00.000Z',
      }] });
    }
    if (url.pathname === `/api/applications/${APPLICATION_ID}/versions`) {
      return json(route, { versions: [version] });
    }
    if (url.pathname === '/api/config') {
      return json(route, {
        model_provider: 'AWS Bedrock',
        model_id: 'eu.anthropic.claude-sonnet-4-20250514-v1:0',
        embeddings_model: 'all-MiniLM-L6-v2',
        default_browse_path: '',
        aws_profile: null,
      });
    }
    if (url.pathname === '/api/config/frameworks') {
      return json(route, {
        frameworks: {
          attack: { name: 'MITRE ATT&CK', description: 'Enterprise attack techniques.' },
          atlas: { name: 'MITRE ATLAS', description: 'AI system techniques.' },
          wiz: { name: 'Wiz', description: 'Cloud threat techniques.' },
        },
      });
    }
    return json(route, { detail: `Unhandled mock route ${request.method()} ${url.pathname}` }, 501);
  });
}
