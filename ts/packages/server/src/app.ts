/**
 * ThreatForest Express application — TS port of `src/server/app.py`.
 *
 * Builds the `/api` REST surface (runs, applications, config, filesystem,
 * imports), permissive CORS (matches the Python `allow_origins=["*"]`), a health
 * probe, and a static-file + SPA-fallback handler for the built UI. The
 * orchestrator executor is wired into a fresh RunManager at construction.
 *
 * The WebSocket progress endpoint is NOT mounted here — it attaches to the HTTP
 * server in `main.ts` (see `attachProgressWebSocket`).
 */
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import { existsSync, readFileSync, statSync, readdirSync } from 'node:fs';
import { join, normalize, relative, sep } from 'node:path';
import { RunManager } from './run-manager.js';
import { createOrchestratorExecutor } from './executor.js';
import { runsRouter, setRunManager } from './routes/runs.js';
import { applicationsRouter } from './routes/applications.js';
import { configRouter } from './routes/config.js';
import { filesystemRouter } from './routes/filesystem.js';
import { importsRouter } from './routes/imports.js';
import { getRunsRoot } from './registry.js';
import { ensureImportsDir } from './report-import.js';

export interface CreateAppOptions {
  /** Directory of the built UI to serve (with SPA fallback). Omit to skip. */
  uiDir?: string;
  /** Root under which per-run directories are created (default: cwd/.threatforest/runs). */
  runsRoot?: string;
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
  '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8',
};

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function guessContentType(path: string): string {
  const dot = path.lastIndexOf('.');
  const ext = dot >= 0 ? path.slice(dot).toLowerCase() : '';
  return MIME[ext] ?? 'application/octet-stream';
}

/**
 * Create the configured Express app. Wires a RunManager backed by the
 * orchestrator executor, configures the registry's imports directory, and
 * (optionally) serves the built UI with an SPA fallback.
 */
export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();

  // Permissive CORS — matches the Python `allow_origins=["*"]` for development.
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  // JSON body parsing for the REST routes. (Multipart uploads on the imports
  // route carry a non-JSON content-type, so this passes them through untouched.)
  app.use(express.json({ limit: '25mb' }));

  // Health probe.
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok' });
  });

  // API routers — mounted under /api.
  app.use('/api', applicationsRouter);
  app.use('/api', configRouter);
  app.use('/api', filesystemRouter);
  app.use('/api', importsRouter);
  app.use('/api', runsRouter);

  // Wire the orchestrator executor into a fresh RunManager.
  const executor = createOrchestratorExecutor(
    options.runsRoot ? { runsRoot: options.runsRoot } : {},
  );
  setRunManager(new RunManager(executor));

  // Ensure the imports drop-folder exists (seeds its README on first run).
  ensureImportsDir(join(getRunsRoot(), '..', 'imports'));

  // Static UI + SPA fallback (only when a built UI dir is provided/found).
  const uiDir = resolveUiDir(options.uiDir);
  if (uiDir !== null) {
    const indexPath = join(uiDir, 'index.html');
    const indexHtml = isFile(indexPath) ? readFileSync(indexPath, 'utf-8') : null;

    // Next.js `output: 'export'` pre-renders each dynamic route once, under a
    // `__shell__` sentinel segment (e.g.
    // out/applications/__shell__/versions/__shell__/index.html). Discover those
    // shells so a real dynamic URL (…/app_123/versions/20260617_041530) can be
    // served the matching route's HTML — which mounts the correct client route
    // component that then reads the real params from the URL. Without this the
    // server fell back to the HOME shell for every dynamic deep-link, so the
    // client always booted at "/" instead of the requested page.
    const dynamicShells = discoverShellRoutes(uiDir);

    app.get('/{*splat}', (req: Request, res: Response) => {
      // `req.path` is NOT percent-decoded by Express, but Next's exported assets
      // for dynamic routes live under literal-bracket dirs on disk
      // (app/applications/[appId]/versions/[versionId]/page-*.js) while the
      // browser requests them URL-encoded (…/%5BappId%5D/…/%5BversionId%5D/…).
      // Decode so the file lookup finds them; fall back to the raw path if the
      // encoding is malformed. Path-traversal is still guarded by normalize() +
      // the startsWith(uiDir) check below.
      let decodedPath = req.path;
      try {
        decodedPath = decodeURIComponent(req.path);
      } catch {
        /* malformed %-encoding — keep the raw path */
      }
      const fullPath = decodedPath.replace(/^\/+/, '');
      // API/WS routes are handled above; never let them fall into the SPA.
      if (fullPath.startsWith('api/') || fullPath.startsWith('ws/')) {
        res.status(404).json({ detail: 'Not found' });
        return;
      }

      // Serve a real static file when one exists (path-traversal guarded).
      if (fullPath) {
        const candidate = normalize(join(uiDir, fullPath));
        if (candidate.startsWith(uiDir) && isFile(candidate)) {
          res.setHeader('Content-Type', guessContentType(candidate));
          res.send(readFileSync(candidate));
          return;
        }
        // Per-route `<route>/index.html` (e.g. out/applications/index.html).
        const routeIndex = normalize(join(uiDir, fullPath, 'index.html'));
        if (routeIndex.startsWith(uiDir) && isFile(routeIndex)) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.send(readFileSync(routeIndex));
          return;
        }
        // Match a dynamic route against the `__shell__` pre-renders.
        const shellFile = matchShellRoute(dynamicShells, fullPath);
        if (shellFile !== null) {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.send(readFileSync(shellFile));
          return;
        }
      }

      // Last resort: the root shell so the client router can still boot.
      if (indexHtml !== null) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(indexHtml);
        return;
      }
      res.status(404).json({ detail: 'Not found' });
    });
  }

  return app;
}

/** A discovered dynamic-route shell: its segment pattern + the HTML file to serve. */
interface ShellRoute {
  /** Path segments; `null` marks a `__shell__` (dynamic) wildcard segment. */
  segments: (string | null)[];
  file: string;
}

/**
 * Find every `…/__shell__/…/index.html` the Next export produced and turn each
 * into a segment matcher. These back dynamic routes (`/applications/:id/...`)
 * that have no real pre-rendered HTML.
 */
function discoverShellRoutes(uiDir: string): ShellRoute[] {
  const out: ShellRoute[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name === 'index.html' && full.includes(`${sep}__shell__${sep}`)) {
        const rel = relative(uiDir, dir); // e.g. applications/__shell__/versions/__shell__
        const segments = rel.split(sep).map((s) => (s === '__shell__' ? null : s));
        out.push({ segments, file: full });
      }
    }
  };
  try {
    walk(uiDir);
  } catch {
    /* no UI dir — leave empty */
  }
  // Longer (more specific) patterns first so e.g. …/versions/:vid wins over …/:appId.
  return out.sort((a, b) => b.segments.length - a.segments.length);
}

/** Match a request path against the discovered shell patterns; return its HTML file or null. */
function matchShellRoute(shells: ShellRoute[], reqPath: string): string | null {
  const reqSegs = reqPath.split('/').filter(Boolean);
  for (const shell of shells) {
    if (shell.segments.length !== reqSegs.length) continue;
    const matches = shell.segments.every((seg, i) => seg === null || seg === reqSegs[i]);
    if (matches) return shell.file;
  }
  return null;
}

/** Resolve the built-UI dir. The Next.js app static-exports to `web/out`. */
function resolveUiDir(explicit?: string): string | null {
  const candidates = [
    explicit,
    process.env.TF_UI_DIR,
    // Next.js `output: 'export'` emits here (run `next build` in ts/web).
    join(process.cwd(), 'ts', 'web', 'out'),
    join(process.cwd(), 'web', 'out'),
    join(process.cwd(), 'out'),
  ].filter((c): c is string => Boolean(c));
  for (const dir of candidates) {
    if (existsSync(join(dir, 'index.html'))) return normalize(dir);
  }
  return null;
}
