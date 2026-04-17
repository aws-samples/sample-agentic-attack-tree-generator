import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createApplication,
  getApplication,
  updateApplication,
  deleteApplicationRecord,
} from '../src/api-client.js';

/**
 * Tests for the v2 persistent-application CRUD wrappers.
 *
 * These hit ``/api/applications/by-id/*`` to avoid colliding with the
 * legacy folder-identifier endpoints (``/applications/{appId}/versions``).
 * The fetch spy lets us assert on the URL, method, and body shape the
 * client sends.
 */

function mockResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  };
}

let fetchSpy;

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('createApplication', () => {
  it('POSTs snake_case body to /api/applications', async () => {
    const created = {
      id: 'app_abc',
      name: 'Demo',
      slug: 'demo',
      project_path: '/tmp/demo',
    };
    fetchSpy.mockResolvedValueOnce(mockResponse(created, 201));

    const result = await createApplication({
      name: 'Demo',
      projectPath: '/tmp/demo',
      businessContext: {
        description: 'A demo app',
        regulatory_frameworks: ['SOC2'],
        data_sensitivity: 'pii',
        main_cia_risk: 'confidentiality',
      },
    });

    expect(result).toEqual(created);
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe('/api/applications');
    expect(options.method).toBe('POST');

    const body = JSON.parse(options.body);
    expect(body).toEqual({
      name: 'Demo',
      project_path: '/tmp/demo',
      business_context: {
        description: 'A demo app',
        regulatory_frameworks: ['SOC2'],
        data_sensitivity: 'pii',
        main_cia_risk: 'confidentiality',
      },
    });
  });

  it('surfaces 409 detail messages as ApiError.message', async () => {
    fetchSpy.mockResolvedValueOnce(
      mockResponse({ detail: "An application named 'Demo' already exists." }, 409)
    );

    await expect(
      createApplication({
        name: 'Demo',
        projectPath: '/tmp/demo',
        businessContext: { description: 'x', regulatory_frameworks: [], data_sensitivity: 'pii', main_cia_risk: 'integrity' },
      })
    ).rejects.toMatchObject({
      status: 409,
      message: expect.stringContaining('already exists'),
    });
  });
});

describe('getApplication', () => {
  it('GETs /api/applications/by-id/{id} with encoding', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ id: 'app_abc', name: 'Demo' }));
    await getApplication('app_abc');
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/applications/by-id/app_abc');
  });
});

describe('updateApplication', () => {
  it('PATCHes only the fields provided (name only)', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ id: 'app_abc', name: 'Renamed' }));
    await updateApplication('app_abc', { name: 'Renamed' });

    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe('/api/applications/by-id/app_abc');
    expect(options.method).toBe('PATCH');
    expect(JSON.parse(options.body)).toEqual({ name: 'Renamed' });
  });

  it('PATCHes business_context when provided', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ id: 'app_abc' }));
    const bc = {
      description: 'new',
      regulatory_frameworks: ['HIPAA'],
      data_sensitivity: 'phi',
      main_cia_risk: 'confidentiality',
    };
    await updateApplication('app_abc', { businessContext: bc });

    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(body).toEqual({ business_context: bc });
  });

  it('can send both fields in one PATCH', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ id: 'app_abc' }));
    await updateApplication('app_abc', {
      name: 'New',
      businessContext: { description: 'x', regulatory_frameworks: [], data_sensitivity: 'pii', main_cia_risk: 'integrity' },
    });
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(Object.keys(body).sort()).toEqual(['business_context', 'name']);
  });
});

describe('deleteApplicationRecord', () => {
  it('DELETEs /api/applications/by-id/{id}', async () => {
    fetchSpy.mockResolvedValueOnce(mockResponse({ success: true }));
    await deleteApplicationRecord('app_abc');
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe('/api/applications/by-id/app_abc');
    expect(options.method).toBe('DELETE');
  });
});
