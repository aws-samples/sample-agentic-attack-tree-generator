/**
 * Application repository layer backed by `.threatforest/applications.json`.
 * Port of `src/server/applications.py`.
 *
 * Applications are first-class persistent entities in the v2 UX model. Each
 * record has a stable ID, a user-chosen name, a fixed on-disk run directory,
 * and a required business-context block.
 *
 * Storage format: a single JSON object keyed by `app_id` sitting alongside the
 * `runs/` directory. Filesystem-first — no database.
 *
 * Uniqueness rules:
 *   - `name`         — case-insensitive unique across all applications.
 *   - `project_path` — one application per folder (409 on collision).
 *
 * `app_id` is a short ULID-style token (time-ordered, URL safe) independent of
 * name and path so renaming never invalidates URLs.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import {
  ApplicationSchema,
  type Application,
  type ApplicationCreateRequest,
  type ApplicationUpdateRequest,
  type BusinessContext,
} from '@threatforest/types';
import { getRunsRoot, slugify } from './registry.js';

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/** Base class for application-repository errors. */
export class ApplicationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApplicationError';
  }
}

/** Raised when an `app_id` does not resolve to a stored application. */
export class ApplicationNotFoundError extends ApplicationError {
  constructor(message: string) {
    super(message);
    this.name = 'ApplicationNotFoundError';
  }
}

/** Raised when a proposed name collides with an existing application. */
export class ApplicationNameConflictError extends ApplicationError {
  constructor(message: string) {
    super(message);
    this.name = 'ApplicationNameConflictError';
  }
}

/** Raised when a proposed `project_path` already belongs to another app. */
export class ApplicationPathConflictError extends ApplicationError {
  constructor(message: string) {
    super(message);
    this.name = 'ApplicationPathConflictError';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Location of the applications store, alongside `runs/`. */
function getStorePath(): string {
  return join(dirname(getRunsRoot()), 'applications.json');
}

/**
 * Generate a short, time-ordered, URL-safe application ID.
 * Format: `app_<8 hex chars time><6 hex chars random>`.
 */
function generateAppId(): string {
  const ts = Math.floor(Date.now() / 1000);
  const tsHex = (ts >>> 0).toString(16).padStart(8, '0');
  return `app_${tsHex}${randomBytes(3).toString('hex')}`;
}

/** Expand a leading `~` to the user's home directory. */
function expandUser(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return p;
}

/** Absolute, resolved string form of a project path. */
function normalisePath(projectPath: string): string {
  return resolve(expandUser(projectPath));
}

/** Case-insensitive, whitespace-collapsed form used for uniqueness checks. */
function normaliseName(name: string): string {
  return name.trim().toLowerCase().replace(/\s+/g, ' ');
}

/** Pick an on-disk folder name derived from `name`, avoiding collisions. */
function deriveRunDirName(name: string, existing: Set<string>): string {
  const base = slugify(name) || 'app';
  let candidate = base;
  let suffix = 2;
  while (existing.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  return candidate;
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/**
 * Repository for the applications store. Mutations are serialized through an
 * async mutex and persisted atomically (write-to-tmp + rename), mirroring the
 * Python repository's lock + atomic-write semantics in a single-process,
 * cooperatively-scheduled Node runtime.
 */
export class ApplicationRepository {
  private readonly storePath: string;

  /** Serializes mutating sections — the await-chain analogue of the Python lock. */
  private chain: Promise<void> = Promise.resolve();

  constructor(storePath?: string) {
    this.storePath = storePath ?? getStorePath();
  }

  // ------------------------------------------------------------------
  // Internal helpers
  // ------------------------------------------------------------------

  /** Return the raw store as a record keyed by `app_id`. */
  private load(): Record<string, Record<string, unknown>> {
    let exists = false;
    try {
      exists = statSync(this.storePath).isFile();
    } catch {
      exists = false;
    }
    if (!exists) return {};
    try {
      const data = JSON.parse(readFileSync(this.storePath, 'utf-8'));
      if (typeof data !== 'object' || data === null || Array.isArray(data)) return {};
      return data as Record<string, Record<string, unknown>>;
    } catch {
      return {};
    }
  }

  /** Atomically write the store (keys sorted, 2-space indent). */
  private save(data: Record<string, Record<string, unknown>>): void {
    mkdirSync(dirname(this.storePath), { recursive: true });
    const sorted = sortKeysDeep(data);
    const tmp = `${this.storePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(sorted, null, 2), 'utf-8');
    renameSync(tmp, this.storePath);
  }

  /** Run a mutation under the serializing chain (analogue of `with lock`). */
  private async withLock<T>(fn: () => T): Promise<T> {
    const run = this.chain.then(fn);
    // Keep the chain alive even if `fn` throws, so later mutations still run.
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private toModel(record: Record<string, unknown>): Application {
    return ApplicationSchema.parse(record);
  }

  private toRecord(app: Application): Record<string, unknown> {
    return { ...app };
  }

  // ------------------------------------------------------------------
  // Public read API
  // ------------------------------------------------------------------

  /** Return all stored applications, ordered by `created_at` ascending. */
  listApplications(): Application[] {
    const data = this.load();
    const apps = Object.values(data).map((rec) => this.toModel(rec));
    apps.sort((a, b) => (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0));
    return apps;
  }

  /** Return the application for `appId` or throw `ApplicationNotFoundError`. */
  getApplication(appId: string): Application {
    const data = this.load();
    const record = data[appId];
    if (record === undefined) {
      throw new ApplicationNotFoundError(`Unknown application: ${appId}`);
    }
    return this.toModel(record);
  }

  /** Return an application with a matching (case-insensitive) name, or null. */
  findByName(name: string): Application | null {
    const target = normaliseName(name);
    for (const app of this.listApplications()) {
      if (normaliseName(app.name) === target) return app;
    }
    return null;
  }

  /** Return an application whose `project_path` matches, or null. */
  findByProjectPath(projectPath: string): Application | null {
    const target = normalisePath(projectPath);
    for (const app of this.listApplications()) {
      if (normalisePath(app.project_path) === target) return app;
    }
    return null;
  }

  /** Return an application whose on-disk `run_dir_name` matches, or null. */
  findByRunDirName(runDirName: string): Application | null {
    for (const app of this.listApplications()) {
      if (app.run_dir_name === runDirName) return app;
    }
    return null;
  }

  // ------------------------------------------------------------------
  // Public write API
  // ------------------------------------------------------------------

  /**
   * Create a new application, enforcing name + path uniqueness.
   *
   * @throws ApplicationNameConflictError if `name` collides (case-insensitive).
   * @throws ApplicationPathConflictError if `project_path` is already registered.
   */
  async createApplication(request: ApplicationCreateRequest): Promise<Application> {
    return this.withLock(() => {
      const data = this.load();
      const existing = Object.values(data).map((rec) => this.toModel(rec));

      const nameKey = normaliseName(request.name);
      for (const app of existing) {
        if (normaliseName(app.name) === nameKey) {
          throw new ApplicationNameConflictError(
            `An application named '${request.name}' already exists.`,
          );
        }
      }

      const pathKey = normalisePath(request.project_path);
      for (const app of existing) {
        if (normalisePath(app.project_path) === pathKey) {
          throw new ApplicationPathConflictError(
            `An application is already registered for project path ` +
              `'${pathKey}': '${app.name}'.`,
          );
        }
      }

      const now = new Date().toISOString();
      const runDirNames = new Set(existing.map((a) => a.run_dir_name));
      const runDirName = deriveRunDirName(request.name, runDirNames);

      const app: Application = {
        id: generateAppId(),
        name: request.name.trim(),
        slug: slugify(request.name),
        project_path: pathKey,
        business_context: request.business_context,
        created_at: now,
        updated_at: now,
        run_dir_name: runDirName,
      };
      data[app.id] = this.toRecord(app);
      this.save(data);
      return app;
    });
  }

  /**
   * Apply partial updates to an application.
   *
   * `name`, `business_context`, and `project_path` are user-editable. The
   * route layer enforces the "project_path only editable before first run"
   * rule. A rename regenerates `slug` but leaves `run_dir_name` untouched so
   * existing run artefacts stay where they are.
   *
   * @throws ApplicationNotFoundError if the app does not exist.
   * @throws ApplicationNameConflictError if the new name collides.
   * @throws ApplicationPathConflictError if the new path is already registered.
   */
  async updateApplication(
    appId: string,
    request: ApplicationUpdateRequest,
  ): Promise<Application> {
    return this.withLock(() => {
      const data = this.load();
      const record = data[appId];
      if (record === undefined) {
        throw new ApplicationNotFoundError(`Unknown application: ${appId}`);
      }

      const current = this.toModel(record);

      let newName = current.name;
      let newSlug = current.slug;
      if (request.name !== null && request.name.trim() !== current.name) {
        const proposed = request.name.trim();
        const proposedKey = normaliseName(proposed);
        for (const [otherId, otherRec] of Object.entries(data)) {
          if (otherId === appId) continue;
          const other = this.toModel(otherRec);
          if (normaliseName(other.name) === proposedKey) {
            throw new ApplicationNameConflictError(
              `An application named '${proposed}' already exists.`,
            );
          }
        }
        newName = proposed;
        newSlug = slugify(proposed);
      }

      const newContext: BusinessContext =
        request.business_context !== null ? request.business_context : current.business_context;

      let newProjectPath = current.project_path;
      if (request.project_path !== null) {
        const proposedPath = normalisePath(request.project_path);
        if (proposedPath !== normalisePath(current.project_path)) {
          for (const [otherId, otherRec] of Object.entries(data)) {
            if (otherId === appId) continue;
            const other = this.toModel(otherRec);
            if (normalisePath(other.project_path) === proposedPath) {
              throw new ApplicationPathConflictError(
                `An application is already registered for project path ` +
                  `'${proposedPath}': '${other.name}'.`,
              );
            }
          }
          newProjectPath = proposedPath;
        }
      }

      const updated: Application = {
        id: current.id,
        name: newName,
        slug: newSlug,
        project_path: newProjectPath,
        business_context: newContext,
        created_at: current.created_at,
        updated_at: new Date().toISOString(),
        run_dir_name: current.run_dir_name,
      };
      data[appId] = this.toRecord(updated);
      this.save(data);
      return updated;
    });
  }

  /**
   * Remove the application record. Does not touch run artefacts on disk.
   *
   * @throws ApplicationNotFoundError if the app does not exist.
   */
  async deleteApplication(appId: string): Promise<void> {
    return this.withLock(() => {
      const data = this.load();
      if (!(appId in data)) {
        throw new ApplicationNotFoundError(`Unknown application: ${appId}`);
      }
      delete data[appId];
      this.save(data);
    });
  }
}

/** Recursively sort object keys so JSON output is deterministic (sort_keys=True). */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Module-level singleton — matches RunManager / Config access pattern.
// ---------------------------------------------------------------------------

let _repository: ApplicationRepository | null = null;

/** Return the process-wide `ApplicationRepository` singleton. */
export function getRepository(): ApplicationRepository {
  if (_repository === null) {
    _repository = new ApplicationRepository();
  }
  return _repository;
}

/**
 * Resolve the absolute `project_path` for an application by its opaque
 * `app_id`, or `null` if the app is unknown. Used by `executor.ts` to seed a
 * run with the correct repository path independent of the request's
 * `project_path` (which v2 callers omit in favour of the app reference).
 */
export function resolveProjectPathForApp(appId: string): string | null {
  try {
    return getRepository().getApplication(appId).project_path;
  } catch {
    return null;
  }
}
