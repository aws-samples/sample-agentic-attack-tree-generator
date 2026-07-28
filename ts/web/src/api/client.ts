/**
 * Centralized API client for the ThreatForest Console UI (TS port of
 * console-ui/src/api-client.js).
 *
 * All REST and WebSocket communication with the backend flows through this
 * module. Response types come from `@threatforest/types`, the shared Zod-backed
 * contract package, so the UI and the TS server agree on payload shapes.
 *
 * The endpoints, methods, paths, and JSON request bodies are a 1:1 port of the
 * legacy client — the frozen HTTP/WS contract is preserved exactly.
 */

import type {
  Application,
  ApplicationSummary,
  ConfigResponse,
  ConfigSaveRequest,
  ConfigTestRequest,
  ConfigTestResponse,
  DirectoryListing,
  LangfuseConfigResponse,
  LangfuseConfigSaveRequest,
  MitigationOverride,
  MitigationStatusT,
  ProvidersResponse,
  BedrockModelsResponse,
  ResumeResponse,
  RunConfig,
  RunResponse,
  RunState,
  VersionSummary,
} from '@threatforest/types';

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/**
 * Structured error thrown by API functions on non-OK HTTP responses.
 */
export class ApiError extends Error {
  override readonly name = 'ApiError';
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Internal request helper
// ---------------------------------------------------------------------------

/**
 * Sends a request and returns parsed JSON, throwing {@link ApiError} when the
 * response is not OK. The error message prefers the server's `detail` /
 * `message` field when the body is JSON.
 */
async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: string; message?: string };
      message = body.detail || body.message || message;
    } catch {
      // body wasn't JSON — keep the default message
    }
    throw new ApiError(response.status, message);
  }
  return (await response.json()) as T;
}

// ---------------------------------------------------------------------------
// Response envelope shapes (small wrappers the contract returns around the
// shared @threatforest/types models).
// ---------------------------------------------------------------------------

export interface ApplicationsResponse {
  applications: ApplicationSummary[];
}

export interface ApplicationVersionsResponse {
  versions: VersionSummary[];
}

export interface ImportsInfoResponse {
  imports_dir: string;
  processed: string[];
  failed: string[];
}

export interface TfReportUploadResult {
  result: {
    status: string;
    folder_name: string;
    versions_added: number;
    [key: string]: unknown;
  };
}

export interface FrameworksResponse {
  frameworks: Record<string, { name: string; description: string }>;
}

export interface MitigationOverridesResponse {
  overrides: Record<string, MitigationOverride>;
}

export interface SetMitigationOverrideResponse {
  override: MitigationOverride;
}

export interface ClearMitigationOverrideResponse {
  success: boolean;
}

export interface PickDirectoryResponse {
  path: string | null;
}

export interface ActiveRunsResponse {
  runs: RunState[];
}

export interface PauseStopResponse {
  status: string;
}

export interface PausedRun {
  app_id: string;
  app_name: string;
  paused_at: string;
  paused_at_stage: string | null;
  run_id: string | null;
  [key: string]: unknown;
}

export interface PausedRunsResponse {
  paused_runs: PausedRun[];
}

export interface RunRespondResponse {
  ok: boolean;
}

// ---------------------------------------------------------------------------
// REST API functions
// ---------------------------------------------------------------------------

/** GET /api/applications → { applications: App[] } */
export async function getApplications(): Promise<ApplicationsResponse> {
  return request<ApplicationsResponse>('/api/applications');
}

// --- Report imports -------------------------------------------------------

/** GET /api/imports/info → { imports_dir, processed[], failed[] } */
export async function getImportsInfo(): Promise<ImportsInfoResponse> {
  return request<ImportsInfoResponse>('/api/imports/info');
}

/**
 * POST /api/imports/tfreport — multipart upload of a .tfreport bundle.
 * Returns `{ result: { status, folder_name, versions_added, ... } }`.
 *
 * We intentionally bypass `request()` here because multipart uploads need the
 * browser to set the Content-Type with the auto-generated boundary.
 */
export async function uploadTfReport(file: File | Blob): Promise<TfReportUploadResult> {
  const form = new FormData();
  form.append('file', file);
  const response = await fetch('/api/imports/tfreport', {
    method: 'POST',
    body: form,
  });
  if (!response.ok) {
    let detail = '';
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body?.detail || '';
    } catch {
      // Ignore non-JSON error bodies.
    }
    throw new Error(detail || `Upload failed (HTTP ${response.status}).`);
  }
  return (await response.json()) as TfReportUploadResult;
}

/** GET /api/applications/{appId}/versions → { versions: Version[] } */
export async function getApplicationVersions(
  appId: string,
): Promise<ApplicationVersionsResponse> {
  return request<ApplicationVersionsResponse>(
    `/api/applications/${encodeURIComponent(appId)}/versions`,
  );
}

/** DELETE /api/applications/{appId} → void */
export async function deleteApplication(appId: string): Promise<void> {
  await request<unknown>(`/api/applications/${encodeURIComponent(appId)}`, {
    method: 'DELETE',
  });
}

/** DELETE /api/applications/{appId}/versions/{versionId} → void */
export async function deleteApplicationVersion(
  appId: string,
  versionId: string,
): Promise<void> {
  await request<unknown>(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}`,
    { method: 'DELETE' },
  );
}

// --- v2 persistent-application CRUD --------------------------------------
// These hit /api/applications/by-id/* to avoid colliding with the legacy
// folder-identifier routes above (/{appId}/versions etc.).

/** POST /api/applications → Application (201) */
export async function createApplication(params: {
  name: string;
  projectPath: string;
  businessContext: Application['business_context'];
}): Promise<Application> {
  return request<Application>('/api/applications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: params.name,
      project_path: params.projectPath,
      business_context: params.businessContext,
    }),
  });
}

/** GET /api/applications/by-id/{appId} → Application */
export async function getApplication(appId: string): Promise<Application> {
  return request<Application>(
    `/api/applications/by-id/${encodeURIComponent(appId)}`,
  );
}

/** PATCH /api/applications/by-id/{appId} → Application */
export async function updateApplication(
  appId: string,
  patch: {
    name?: string;
    businessContext?: Application['business_context'];
    projectPath?: string;
  } = {},
): Promise<Application> {
  const body: Record<string, unknown> = {};
  if (patch.name !== undefined) body['name'] = patch.name;
  if (patch.businessContext !== undefined) body['business_context'] = patch.businessContext;
  if (patch.projectPath !== undefined) body['project_path'] = patch.projectPath;
  return request<Application>(
    `/api/applications/by-id/${encodeURIComponent(appId)}`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
}

/** DELETE /api/applications/by-id/{appId} → void */
export async function deleteApplicationRecord(appId: string): Promise<void> {
  await request<unknown>(
    `/api/applications/by-id/${encodeURIComponent(appId)}`,
    { method: 'DELETE' },
  );
}

// ---------------------------------------------------------------------------
// Mitigation overrides (M3 v1)
// Status + comment dispositions a user records against individual mitigations
// in a given version. Storage is server-side; edits are surfaced live in the
// merged /data response (override_status / override_comment / override_updated_at).
// ---------------------------------------------------------------------------

/** GET → { overrides: { [mitigationKey]: { status, comment, updated_at } } } */
export async function getMitigationOverrides(
  appId: string,
  versionId: string,
): Promise<MitigationOverridesResponse> {
  return request<MitigationOverridesResponse>(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides`,
  );
}

/** PUT → { override: { status, comment, updated_at } } */
export async function setMitigationOverride(
  appId: string,
  versionId: string,
  mitigationKey: string,
  payload: { status: MitigationStatusT; comment: string },
): Promise<SetMitigationOverrideResponse> {
  return request<SetMitigationOverrideResponse>(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides/${encodeURIComponent(mitigationKey)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: payload.status, comment: payload.comment }),
    },
  );
}

/** DELETE → { success: true } */
export async function clearMitigationOverride(
  appId: string,
  versionId: string,
  mitigationKey: string,
): Promise<ClearMitigationOverrideResponse> {
  return request<ClearMitigationOverrideResponse>(
    `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/mitigation-overrides/${encodeURIComponent(mitigationKey)}`,
    { method: 'DELETE' },
  );
}

// --- Config ---------------------------------------------------------------

/** GET /api/config → Config object */
export async function getConfig(): Promise<ConfigResponse> {
  return request<ConfigResponse>('/api/config');
}

/** GET /api/config/providers → { providers: string[] } */
export async function getProviders(): Promise<ProvidersResponse> {
  return request<ProvidersResponse>('/api/config/providers');
}

/** GET /api/config/frameworks → { frameworks: { key: { name, description } } } */
export async function getFrameworks(): Promise<FrameworksResponse> {
  return request<FrameworksResponse>('/api/config/frameworks');
}

/**
 * GET /api/config/bedrock/models → the live Bedrock catalogue.
 *
 * Never rejects for an expected failure (no credentials, missing IAM, offline):
 * the server answers with `source: 'fallback'` plus a warning instead, so the
 * Configure page always has something to show.
 */
export async function getBedrockModels(opts: {
  region?: string;
  refresh?: boolean;
} = {}): Promise<BedrockModelsResponse> {
  const params = new URLSearchParams();
  if (opts.region) params.set('region', opts.region);
  if (opts.refresh) params.set('refresh', 'true');
  const qs = params.toString();
  return request<BedrockModelsResponse>(`/api/config/bedrock/models${qs ? `?${qs}` : ''}`);
}

/** POST /api/config/test → { success, message } */
export async function testConnection(
  config: ConfigTestRequest,
): Promise<ConfigTestResponse> {
  return request<ConfigTestResponse>('/api/config/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** POST /api/config/save → { success, message } */
export async function saveConfig(
  config: ConfigSaveRequest,
): Promise<ConfigTestResponse> {
  return request<ConfigTestResponse>('/api/config/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** GET /api/config/langfuse → LangfuseConfig */
export async function getLangfuseConfig(): Promise<LangfuseConfigResponse> {
  return request<LangfuseConfigResponse>('/api/config/langfuse');
}

/** POST /api/config/langfuse → { success, message } */
export async function saveLangfuseConfig(
  config: LangfuseConfigSaveRequest,
): Promise<ConfigTestResponse> {
  return request<ConfigTestResponse>('/api/config/langfuse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

/** POST /api/config/langfuse/test → { success, message } */
export async function testLangfuseConnection(
  config: LangfuseConfigSaveRequest,
): Promise<ConfigTestResponse> {
  return request<ConfigTestResponse>('/api/config/langfuse/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
}

// --- Filesystem -----------------------------------------------------------

/** GET /api/filesystem/browse?path=... → DirectoryListing */
export async function browseFilesystem(path: string): Promise<DirectoryListing> {
  return request<DirectoryListing>(
    `/api/filesystem/browse?path=${encodeURIComponent(path)}`,
  );
}

/** POST /api/filesystem/pick-directory → { path: string | null } */
export async function pickDirectory(): Promise<PickDirectoryResponse> {
  return request<PickDirectoryResponse>('/api/filesystem/pick-directory', {
    method: 'POST',
  });
}

// --- Runs -----------------------------------------------------------------

/** GET /api/runs?status=... → { runs: RunState[] } */
export async function getActiveRuns(): Promise<ActiveRunsResponse> {
  return request<ActiveRunsResponse>('/api/runs?status=pending,running');
}

/** POST /api/runs → { run_id } */
export async function createRun(params: RunConfig): Promise<RunResponse> {
  return request<RunResponse>('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

/** GET /api/runs/{runId} → RunState */
export async function getRun(runId: string): Promise<RunState> {
  return request<RunState>(`/api/runs/${encodeURIComponent(runId)}`);
}

/** POST /api/runs/{runId}/pause → { status } */
export async function pauseRun(runId: string): Promise<PauseStopResponse> {
  return request<PauseStopResponse>(
    `/api/runs/${encodeURIComponent(runId)}/pause`,
    { method: 'POST' },
  );
}

/** POST /api/runs/{runId}/stop → { status } */
export async function stopRun(runId: string): Promise<PauseStopResponse> {
  return request<PauseStopResponse>(
    `/api/runs/${encodeURIComponent(runId)}/stop`,
    { method: 'POST' },
  );
}

/** POST /api/runs/{runId}/resume → { new_run_id } */
export async function resumeRun(runId: string): Promise<ResumeResponse> {
  return request<ResumeResponse>(
    `/api/runs/${encodeURIComponent(runId)}/resume`,
    { method: 'POST' },
  );
}

/** GET /api/paused-runs → { paused_runs: PausedRun[] } */
export async function getPausedRuns(): Promise<PausedRunsResponse> {
  return request<PausedRunsResponse>('/api/paused-runs');
}

/** DELETE /api/paused-runs/{appId} → void */
export async function deletePausedRun(appId: string): Promise<unknown> {
  return request<unknown>(`/api/paused-runs/${encodeURIComponent(appId)}`, {
    method: 'DELETE',
  });
}

/** POST /api/runs (resume from pause_state) → { run_id } */
export async function createResumeRun(params: RunConfig): Promise<RunResponse> {
  return request<RunResponse>('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

/** POST /api/runs/{runId}/respond → { ok } */
export async function submitRunResponse(
  runId: string,
  text: string,
): Promise<RunRespondResponse> {
  return request<RunRespondResponse>(
    `/api/runs/${encodeURIComponent(runId)}/respond`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    },
  );
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/** Event handlers for {@link connectRunWebSocket}. */
export interface RunWebSocketHandlers {
  onOpen?: (event: Event) => void;
  onMessage?: (event: MessageEvent) => void;
  onError?: (event: Event) => void;
  onClose?: (event: CloseEvent) => void;
}

/** Reconnection tuning for {@link connectRunWebSocket}. */
export interface RunWebSocketOptions {
  maxRetries?: number;
  baseDelay?: number;
}

/** Controller returned by {@link connectRunWebSocket}. */
export interface RunWebSocketController {
  /** Cleanly close the WebSocket and cancel any pending reconnect. */
  close: () => void;
}

/**
 * Open a WebSocket connection for real-time run progress with automatic
 * reconnection on unexpected disconnects.
 *
 * Returns a controller object with a `close()` method to cleanly tear down the
 * connection and stop reconnection attempts. Terminal close codes (1000 normal,
 * 4004 unknown run_id) and intentional `close()` skip reconnection.
 */
export function connectRunWebSocket(
  runId: string,
  handlers: RunWebSocketHandlers = {},
  options: RunWebSocketOptions = {},
): RunWebSocketController {
  const { maxRetries = 5, baseDelay = 1000 } = options;
  let retries = 0;
  let ws: WebSocket | null = null;
  let intentionalClose = false;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  function connect(): void {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${protocol}//${window.location.host}/ws/runs/${encodeURIComponent(runId)}`;
    ws = new WebSocket(url);

    ws.addEventListener('open', (e) => {
      retries = 0; // Reset backoff on successful connection
      handlers.onOpen?.(e);
    });

    if (handlers.onMessage) {
      ws.addEventListener('message', handlers.onMessage);
    }
    if (handlers.onError) {
      ws.addEventListener('error', handlers.onError);
    }

    ws.addEventListener('close', (e) => {
      // Don't reconnect on intentional close or terminal server codes.
      // 1000 = normal close (pipeline finished), 4004 = unknown run_id.
      if (intentionalClose || e.code === 1000 || e.code === 4004) {
        handlers.onClose?.(e);
        return;
      }

      // Attempt reconnection with exponential backoff.
      if (retries < maxRetries) {
        const delay = Math.min(baseDelay * Math.pow(2, retries), 30000);
        retries++;
        reconnectTimer = setTimeout(connect, delay);
      } else {
        // Exhausted retries — notify caller.
        handlers.onClose?.(e);
      }
    });
  }

  connect();

  // Return a controller instead of the raw WebSocket so callers always go
  // through `close()`, which prevents reconnect loops.
  return {
    close() {
      intentionalClose = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (
        ws &&
        (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)
      ) {
        ws.close(1000);
      }
    },
  };
}
