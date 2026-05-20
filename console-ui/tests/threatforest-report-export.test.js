import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadThreatforestReport } from '../src/utils/export-service.js';

describe('downloadThreatforestReport', () => {
  let createObjectUrlSpy;
  let revokeObjectUrlSpy;
  let appendChildSpy;
  let removeChildSpy;
  let clickSpy;

  beforeEach(() => {
    // jsdom doesn't implement URL.createObjectURL — stub the property
    // directly rather than spying on a missing one.
    globalThis.URL.createObjectURL = vi.fn().mockReturnValue('blob:mock');
    globalThis.URL.revokeObjectURL = vi.fn();
    createObjectUrlSpy = globalThis.URL.createObjectURL;
    revokeObjectUrlSpy = globalThis.URL.revokeObjectURL;

    clickSpy = vi.fn();
    vi.spyOn(document, 'createElement').mockReturnValue({
      href: '',
      download: '',
      style: {},
      click: clickSpy,
    });
    appendChildSpy = vi.spyOn(document.body, 'appendChild').mockImplementation(() => {});
    removeChildSpy = vi.spyOn(document.body, 'removeChild').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function mockFetchOk({ filename = 'demo.tfreport' } = {}) {
    const headers = new Headers({
      'content-disposition': `attachment; filename="${filename}"`,
    });
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers,
      blob: async () => new Blob(['fake-zip-bytes']),
    });
  }

  it('calls the per-version endpoint with include_scanner_context=true', async () => {
    mockFetchOk();
    await downloadThreatforestReport({
      appId: 'app_abc',
      versionId: '20260101_120000',
      includeScannerContext: true,
    });

    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const url = globalThis.fetch.mock.calls[0][0];
    expect(url).toContain('/api/applications/app_abc/versions/20260101_120000/report');
    expect(url).toContain('include_scanner_context=true');
    expect(clickSpy).toHaveBeenCalled();
  });

  it('calls the full-app endpoint when versionId is omitted', async () => {
    mockFetchOk();
    await downloadThreatforestReport({
      appId: 'app_abc',
      includeScannerContext: false,
    });

    const url = globalThis.fetch.mock.calls[0][0];
    expect(url).toMatch(/\/api\/applications\/app_abc\/report\?/);
    expect(url).not.toContain('/versions/');
    expect(url).toContain('include_scanner_context=false');
  });

  it('uses the server-supplied filename from Content-Disposition', async () => {
    mockFetchOk({ filename: 'sales-portal-full.tfreport' });
    const link = { href: '', download: '', style: {}, click: clickSpy };
    document.createElement.mockReturnValue(link);

    await downloadThreatforestReport({
      appId: 'app_abc',
      includeScannerContext: true,
    });
    expect(link.download).toBe('sales-portal-full.tfreport');
  });

  it('throws with the FastAPI detail string on error responses', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      headers: new Headers(),
      json: async () => ({ detail: 'No completed versions for application' }),
    });

    await expect(
      downloadThreatforestReport({
        appId: 'unknown',
        includeScannerContext: true,
      })
    ).rejects.toThrow(/No completed versions/);
  });

  it('falls back to a generic error when no JSON body is present', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      headers: new Headers(),
      json: async () => { throw new Error('not json'); },
    });

    await expect(
      downloadThreatforestReport({
        appId: 'x',
        includeScannerContext: true,
      })
    ).rejects.toThrow(/HTTP 500/);
  });

  it('rejects without appId', async () => {
    await expect(
      downloadThreatforestReport({ includeScannerContext: true })
    ).rejects.toThrow(/appId is required/);
  });
});
