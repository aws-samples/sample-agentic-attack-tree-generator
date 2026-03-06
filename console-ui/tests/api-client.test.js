import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  ApiError,
  getApplications,
  getApplicationVersions,
  deleteApplication,
  getConfig,
  getProviders,
  testConnection,
  saveConfig,
  createRun,
  getDashboardUrl,
  connectRunWebSocket,
} from '../src/api-client.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a mock Response that resolves to the given JSON body. */
function mockResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  };
}

/** Build a mock Response whose .json() rejects (non-JSON body). */
function mockNonJsonResponse(status) {
  return {
    ok: false,
    status,
    json: () => Promise.reject(new Error('not json')),
  };
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

let fetchSpy;

beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, 'fetch');
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// ApiError
// ---------------------------------------------------------------------------

describe('ApiError', () => {
  it('extends Error with status and message', () => {
    const err = new ApiError(404, 'Not found');
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ApiError');
    expect(err.status).toBe(404);
    expect(err.message).toBe('Not found');
  });
});

// ---------------------------------------------------------------------------
// REST functions — success paths
// ---------------------------------------------------------------------------

describe('getApplications', () => {
  it('calls GET /api/applications and returns data', async () => {
    const data = { applications: [{ id: '1', name: 'App1' }] };
    fetchSpy.mockResolvedValue(mockResponse(data));

    const result = await getApplications();
    expect(result).toEqual(data);
    expect(fetchSpy).toHaveBeenCalledWith('/api/applications', undefined);
  });
});

describe('getApplicationVersions', () => {
  it('calls GET /api/applications/{id}/versions', async () => {
    const data = { versions: [{ version_id: 'v1' }] };
    fetchSpy.mockResolvedValue(mockResponse(data));

    const result = await getApplicationVersions('app-42');
    expect(result).toEqual(data);
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/applications/app-42/versions',
      undefined,
    );
  });

  it('encodes special characters in appId', async () => {
    fetchSpy.mockResolvedValue(mockResponse({ versions: [] }));
    await getApplicationVersions('app/special&chars');
    expect(fetchSpy.mock.calls[0][0]).toBe(
      `/api/applications/${encodeURIComponent('app/special&chars')}/versions`,
    );
  });
});

describe('deleteApplication', () => {
  it('calls DELETE /api/applications/{id}', async () => {
    fetchSpy.mockResolvedValue(mockResponse({}));
    await deleteApplication('app-1');
    expect(fetchSpy).toHaveBeenCalledWith('/api/applications/app-1', {
      method: 'DELETE',
    });
  });
});

describe('getConfig', () => {
  it('calls GET /api/config', async () => {
    const cfg = { model_provider: 'bedrock', model_id: 'claude' };
    fetchSpy.mockResolvedValue(mockResponse(cfg));

    const result = await getConfig();
    expect(result).toEqual(cfg);
  });
});

describe('getProviders', () => {
  it('calls GET /api/config/providers', async () => {
    const data = { providers: ['bedrock', 'openai'] };
    fetchSpy.mockResolvedValue(mockResponse(data));

    const result = await getProviders();
    expect(result).toEqual(data);
  });
});

describe('testConnection', () => {
  it('sends POST /api/config/test with JSON body', async () => {
    const config = { model_provider: 'bedrock' };
    fetchSpy.mockResolvedValue(mockResponse({ success: true, message: 'ok' }));

    const result = await testConnection(config);
    expect(result).toEqual({ success: true, message: 'ok' });
    expect(fetchSpy).toHaveBeenCalledWith('/api/config/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  });
});

describe('saveConfig', () => {
  it('sends POST /api/config/save with JSON body', async () => {
    const config = { model_provider: 'openai' };
    fetchSpy.mockResolvedValue(mockResponse({ success: true, message: 'saved' }));

    const result = await saveConfig(config);
    expect(result).toEqual({ success: true, message: 'saved' });
  });
});

describe('createRun', () => {
  it('sends POST /api/runs with JSON body', async () => {
    const params = { project_path: '/tmp/proj', threat_source: 'auto' };
    fetchSpy.mockResolvedValue(mockResponse({ run_id: 'run-99' }));

    const result = await createRun(params);
    expect(result).toEqual({ run_id: 'run-99' });
    expect(fetchSpy).toHaveBeenCalledWith('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
  });
});

describe('getDashboardUrl', () => {
  it('returns the correct URL string', () => {
    expect(getDashboardUrl('run-1')).toBe('/api/runs/run-1/dashboard');
  });

  it('encodes special characters', () => {
    expect(getDashboardUrl('run/special')).toBe(
      `/api/runs/${encodeURIComponent('run/special')}/dashboard`,
    );
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe('error handling', () => {
  it('throws ApiError with detail from JSON body', async () => {
    fetchSpy.mockResolvedValue(
      mockResponse({ detail: 'App not found' }, 404),
    );

    await expect(getApplications()).rejects.toThrow(ApiError);
    await expect(getApplications()).rejects.toMatchObject({
      status: 404,
      message: 'App not found',
    });
  });

  it('throws ApiError with message from JSON body', async () => {
    fetchSpy.mockResolvedValue(
      mockResponse({ message: 'Server error' }, 500),
    );

    await expect(getConfig()).rejects.toMatchObject({
      status: 500,
      message: 'Server error',
    });
  });

  it('falls back to default message when body is not JSON', async () => {
    fetchSpy.mockResolvedValue(mockNonJsonResponse(502));

    await expect(getProviders()).rejects.toMatchObject({
      status: 502,
      message: 'Request failed with status 502',
    });
  });
});

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

describe('connectRunWebSocket', () => {
  let MockWebSocket;
  let lastInstance;

  beforeEach(() => {
    MockWebSocket = vi.fn(function (url) {
      this.url = url;
      this.readyState = 1; // OPEN
      this.addEventListener = vi.fn();
      this.close = vi.fn();
      lastInstance = this;
    });
    // Expose class-level constants used by the implementation
    MockWebSocket.OPEN = 1;
    MockWebSocket.CONNECTING = 0;
    vi.stubGlobal('WebSocket', MockWebSocket);
    // Provide location for protocol/host detection
    vi.stubGlobal('location', { protocol: 'http:', host: 'localhost:3000' });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    lastInstance = null;
  });

  it('creates a WebSocket with the correct URL', () => {
    connectRunWebSocket('run-7', {});
    expect(MockWebSocket).toHaveBeenCalledWith(
      'ws://localhost:3000/ws/runs/run-7',
    );
  });

  it('attaches open handler that wraps user callback and resets retries', () => {
    const onOpen = vi.fn();
    connectRunWebSocket('run-1', { onOpen });

    // The internal open handler is registered, not the user's directly
    expect(lastInstance.addEventListener).toHaveBeenCalledWith(
      'open',
      expect.any(Function),
    );
  });

  it('attaches message, error, and close handlers', () => {
    const onMessage = vi.fn();
    const onError = vi.fn();
    const onClose = vi.fn();

    connectRunWebSocket('run-1', { onMessage, onError, onClose });

    const eventNames = lastInstance.addEventListener.mock.calls.map((c) => c[0]);
    expect(eventNames).toContain('open');
    expect(eventNames).toContain('message');
    expect(eventNames).toContain('error');
    expect(eventNames).toContain('close');
  });

  it('returns a controller with a close() method', () => {
    const controller = connectRunWebSocket('run-3', {});
    expect(controller).toHaveProperty('close');
    expect(typeof controller.close).toBe('function');
  });

  it('close() calls WebSocket.close(1000) and prevents reconnects', () => {
    const controller = connectRunWebSocket('run-5', {});
    controller.close();
    expect(lastInstance.close).toHaveBeenCalledWith(1000);
  });

  it('uses wss: for https: pages', () => {
    vi.stubGlobal('location', { protocol: 'https:', host: 'example.com' });
    connectRunWebSocket('run-4', {});
    expect(MockWebSocket).toHaveBeenCalledWith(
      'wss://example.com/ws/runs/run-4',
    );
  });

  it('reconnects on unexpected close with exponential backoff', () => {
    vi.useFakeTimers();
    const onClose = vi.fn();
    connectRunWebSocket('run-6', { onClose }, { maxRetries: 2, baseDelay: 100 });

    // Simulate unexpected close (code !== 1000 and !== 4004)
    const closeHandler = lastInstance.addEventListener.mock.calls.find(
      (c) => c[0] === 'close',
    )[1];
    closeHandler({ code: 1006 });

    // onClose should NOT be called yet (reconnect pending)
    expect(onClose).not.toHaveBeenCalled();

    // Advance time to trigger first reconnect (100ms)
    vi.advanceTimersByTime(100);
    expect(MockWebSocket).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });

  it('calls onClose after maxRetries exhausted', () => {
    vi.useFakeTimers();
    const onClose = vi.fn();
    connectRunWebSocket('run-7', { onClose }, { maxRetries: 1, baseDelay: 50 });

    // First unexpected close — triggers reconnect
    let closeHandler = lastInstance.addEventListener.mock.calls.find(
      (c) => c[0] === 'close',
    )[1];
    closeHandler({ code: 1006 });
    vi.advanceTimersByTime(50);
    expect(MockWebSocket).toHaveBeenCalledTimes(2);

    // Second unexpected close — retries exhausted, should call onClose
    closeHandler = lastInstance.addEventListener.mock.calls.find(
      (c) => c[0] === 'close',
    )[1];
    closeHandler({ code: 1006 });
    expect(onClose).toHaveBeenCalledWith({ code: 1006 });

    vi.useRealTimers();
  });

  it('does not reconnect on normal close (code 1000)', () => {
    vi.useFakeTimers();
    const onClose = vi.fn();
    connectRunWebSocket('run-8', { onClose }, { maxRetries: 3, baseDelay: 50 });

    const closeHandler = lastInstance.addEventListener.mock.calls.find(
      (c) => c[0] === 'close',
    )[1];
    closeHandler({ code: 1000 });

    // Should call onClose immediately, no reconnect
    expect(onClose).toHaveBeenCalledWith({ code: 1000 });
    vi.advanceTimersByTime(200);
    expect(MockWebSocket).toHaveBeenCalledTimes(1); // no new connections

    vi.useRealTimers();
  });

  it('does not reconnect on unknown run (code 4004)', () => {
    vi.useFakeTimers();
    const onClose = vi.fn();
    connectRunWebSocket('run-9', { onClose }, { maxRetries: 3, baseDelay: 50 });

    const closeHandler = lastInstance.addEventListener.mock.calls.find(
      (c) => c[0] === 'close',
    )[1];
    closeHandler({ code: 4004 });

    expect(onClose).toHaveBeenCalledWith({ code: 4004 });
    vi.advanceTimersByTime(200);
    expect(MockWebSocket).toHaveBeenCalledTimes(1);

    vi.useRealTimers();
  });
});
