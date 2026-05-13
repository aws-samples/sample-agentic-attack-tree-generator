/**
 * Centralized API client for ThreatForest Console UI.
 *
 * All REST and WebSocket communication with the backend flows through
 * this module, replacing inline fetch() calls across pages.
 */

/**
 * Structured error thrown by API functions on non-OK HTTP responses.
 */
export class ApiError extends Error {
  /**
   * @param {number} status  HTTP status code
   * @param {string} message Human-readable error description
   */
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.message = message;
  }
}

/**
 * Internal helper — sends a request and returns parsed JSON.
 * Throws ApiError when the response is not OK.
 */
async function request(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = await response.json();
      message = body.detail || body.message || message;
    } catch {
      // body wasn't JSON — keep the default message
    }
    throw new ApiError(response.status, message);
  }
  return response.json();
}

// ---------------------------------------------------------------------------
// REST API functions
// ---------------------------------------------------------------------------

/** GET /api/applications → { applications: App[] } */
export async function getApplications() {
  return request('/api/applications');
}

/** GET /api/applications/{appId}/versions → { versions: Version[] } */
export async function getApplicationVersions(appId) {
  return request(`/api/applications/${encodeURIComponent(appId)}/versions`);
}

/** DELETE /api/applications/{appId} → void */
export async function deleteApplication(appId) {
  await request(`/api/applications/${encodeURIComponent(appId)}`, {
    method: 'DELETE',
  });
}

/** DELETE /api/applications/{appId}/versions/{versionId} → void */
export async function deleteApplicationVersion(appId, versionId) {
  await request(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}`,
    { method: 'DELETE' },
  );
}

// --- v2 persistent-application CRUD --------------------------------------
// These hit /api/applications/by-id/* to avoid colliding with the legacy
// folder-identifier routes above (/{appId}/versions etc.).

/** POST /api/applications → Application (201) */
export async function createApplication({ name, projectPath, businessContext }) {
  return request('/api/applications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      project_path: projectPath,
      business_context: businessContext,
    }),
  });
}

/** GET /api/applications/by-id/{appId} → Application */
export async function getApplication(appId) {
  return request(`/api/applications/by-id/${encodeURIComponent(appId)}`);
}

/** PATCH /api/applications/by-id/{appId} → Application */
export async function updateApplication(appId, { name, businessContext, projectPath } = {}) {
  const body = {};
  if (name !== undefined) body.name = name;
  if (businessContext !== undefined) body.business_context = businessContext;
  if (projectPath !== undefined) body.project_path = projectPath;
  return request(`/api/applications/by-id/${encodeURIComponent(appId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** DELETE /api/applications/by-id/{appId} → void */
export async function deleteApplicationRecord(appId) {
  await request(`/api/applications/by-id/${encodeURIComponent(appId)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Mitigation overrides (M3 v1)
// Status + comment dispositions a user records against individual mitigations
// in a given version. Storage is server-side, edits are surfaced live in the
// merged /data response (override_status / override_comment / override_updated_at).
// ---------------------------------------------------------------------------

/** GET → { overrides: { [mitigationKey]: { status, comment, updated_at } } } */
export async function getMitigationOverrides(appId, versionId) {
  return request(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides`
  );
}

/** PUT → { override: { status, comment, updated_at } } */
export async function setMitigationOverride(appId, versionId, mitigationKey, { status, comment }) {
  return request(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides/${encodeURIComponent(mitigationKey)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, comment }),
    }
  );
}

/** DELETE → { success: true } */
export async function clearMitigationOverride(appId, versionId, mitigationKey) {
  return request(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides/${encodeURIComponent(mitigationKey)}`,
    { method: 'DELETE' }
  );
}

/** GET /api/config → Config object */
export async function getConfig() {
  return request('/api/config');
}

/** GET /api/config/providers → { providers: string[] } */
export async function getProviders() {
  return request('/api/config/providers');
}

/** GET /api/config/frameworks → { frameworks: { key: { name, description } } } */
export async function getFrameworks() {
  return request('/api/config/frameworks');
}

/** POST /api/config/test → { success, message } */
export async function testConnection(config) {
  return request('/api/config/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** POST /api/config/save → { success, message } */
export async function saveConfig(config) {
  return request('/api/config/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** GET /api/config/langfuse → LangfuseConfig */
export async function getLangfuseConfig() {
  return request('/api/config/langfuse');
}

/** POST /api/config/langfuse → { success, message } */
export async function saveLangfuseConfig(config) {
  return request('/api/config/langfuse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** POST /api/config/langfuse/test → { success, message } */
export async function testLangfuseConnection(config) {
  return request('/api/config/langfuse/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** GET /api/filesystem/browse?path=... → DirectoryListing */
export async function browseFilesystem(path) {
  return request(`/api/filesystem/browse?path=${encodeURIComponent(path)}`);
}

/** POST /api/filesystem/pick-directory → { path: string | null } */
export async function pickDirectory() {
  return request('/api/filesystem/pick-directory', { method: 'POST' });
}

/** GET /api/runs?status=... → { runs: RunState[] } */
export async function getActiveRuns() {
  return request('/api/runs?status=pending,running');
}

/** POST /api/runs → { run_id } */
export async function createRun(params) {
  return request('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

/** GET /api/runs/{runId} → RunState */
export async function getRun(runId) {
  return request(`/api/runs/${encodeURIComponent(runId)}`);
}

/** POST /api/runs/{runId}/pause → { status } */
export async function pauseRun(runId) {
  return request(`/api/runs/${encodeURIComponent(runId)}/pause`, { method: 'POST' });
}

/** POST /api/runs/{runId}/stop → { status } */
export async function stopRun(runId) {
  return request(`/api/runs/${encodeURIComponent(runId)}/stop`, { method: 'POST' });
}

/** POST /api/runs/{runId}/resume → { new_run_id } */
export async function resumeRun(runId) {
  return request(`/api/runs/${encodeURIComponent(runId)}/resume`, { method: 'POST' });
}

/** GET /api/paused-runs → { paused_runs: PausedRun[] } */
export async function getPausedRuns() {
  return request('/api/paused-runs');
}

/** DELETE /api/paused-runs/{appId} → void */
export async function deletePausedRun(appId) {
  return request(`/api/paused-runs/${encodeURIComponent(appId)}`, { method: 'DELETE' });
}

/** POST /api/runs (resume from pause_state) → { run_id } */
export async function createResumeRun(params) {
  return request('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

/** POST /api/runs/{runId}/respond → { ok } */
export async function submitRunResponse(runId, text) {
  return request(`/api/runs/${encodeURIComponent(runId)}/respond`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/**
 * Open a WebSocket connection for real-time run progress with automatic
 * reconnection on unexpected disconnects.
 *
 * Returns a controller object with a `close()` method to cleanly tear down
 * the connection and stop reconnection attempts.
 *
 * @param {string} runId
 * @param {{ onOpen?, onMessage?, onError?, onClose? }} handlers
 * @param {{ maxRetries?: number, baseDelay?: number }} options
 * @returns {{ close: () => void }}
 */
export function connectRunWebSocket(runId, handlers = {}, options = {}) {
  const { maxRetries = 5, baseDelay = 1000 } = options;
  let retries = 0;
  let ws = null;
  let intentionalClose = false;
  let reconnectTimer = null;

  function connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws/runs/${encodeURIComponent(runId)}`;
    ws = new WebSocket(url);

    ws.addEventListener('open', (e) => {
      retries = 0; // Reset backoff on successful connection
      if (handlers.onOpen) handlers.onOpen(e);
    });

    if (handlers.onMessage) ws.addEventListener('message', handlers.onMessage);
    if (handlers.onError) ws.addEventListener('error', handlers.onError);

    ws.addEventListener('close', (e) => {
      // Don't reconnect on intentional close or terminal server codes
      // 1000 = normal close (pipeline finished), 4004 = unknown run_id
      if (intentionalClose || e.code === 1000 || e.code === 4004) {
        if (handlers.onClose) handlers.onClose(e);
        return;
      }

      // Attempt reconnection with exponential backoff
      if (retries < maxRetries) {
        const delay = Math.min(baseDelay * Math.pow(2, retries), 30000);
        retries++;
        reconnectTimer = setTimeout(connect, delay);
      } else {
        // Exhausted retries — notify caller
        if (handlers.onClose) handlers.onClose(e);
      }
    });
  }

  connect();

  // Return a controller instead of the raw WebSocket so callers
  // always go through `close()` which prevents reconnect loops.
  return {
    /** Cleanly close the WebSocket and cancel any pending reconnect. */
    close() {
      intentionalClose = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close(1000);
      }
    },
  };
}
