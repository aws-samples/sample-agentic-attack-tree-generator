/**
 * @threatforest/server — public surface.
 *
 * The Express app factory + WS attach, the run lifecycle (RunManager,
 * ScanControl, ProgressEvent), the orchestrator executor, and the route-level
 * singleton accessors the CLI (WS-5) and tests (WS-7) swap in.
 */
export { createApp, type CreateAppOptions } from './app.js';
export { attachProgressWebSocket } from './ws.js';

export {
  RunManager,
  ScanControl,
  type ProgressEvent,
  type OrchestratorExecutor,
} from './run-manager.js';
export { createOrchestratorExecutor, type ExecutorOptions } from './executor.js';

export { getRunManager, setRunManager, WS_HEARTBEAT_INTERVAL } from './routes/runs.js';
export { getRegistry, setRegistry } from './routes/applications.js';
export { getBrowser, setBrowser } from './routes/filesystem.js';
export { setConfig } from './routes/config.js';

export { ApplicationRegistry, getRunsRoot, slugify } from './registry.js';
export {
  ApplicationRepository,
  getRepository,
  resolveProjectPathForApp,
  ApplicationError,
  ApplicationNotFoundError,
  ApplicationNameConflictError,
  ApplicationPathConflictError,
} from './applications.js';
export { FilesystemBrowser } from './filesystem.js';
export { buildReportBundle, ReportBundleError } from './report-bundle.js';
export {
  processPendingImports,
  ensureImportsDir,
  type ImportResult,
} from './report-import.js';
