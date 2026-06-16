/**
 * ThreatForest report import routes — TS port of `src/server/routes/imports.py`.
 * Mounted under `/api`.
 *
 *   GET  /imports/info        absolute imports dir + processed/failed history
 *   POST /imports/tfreport    upload a `.tfreport` and run the importer inline
 *
 * The drop-folder workflow still works passively (bundles dropped into
 * `.threatforest/imports/` are picked up on the next applications-list refresh);
 * this route just gives the UI an HTTP path so users don't need the abs path.
 *
 * Multipart parsing: the server has no `multer`/`busboy` dependency, so this
 * implements a minimal single-field multipart/form-data extractor against the
 * raw request body (sufficient for the one `file` field the UI sends).
 */
import { Router, type Request, type Response } from 'express';
import {
  existsSync,
  openSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeSync,
  closeSync,
} from 'node:fs';
import { basename, join, dirname } from 'node:path';
import { getRegistry } from './applications.js';
import {
  ensureImportsDir,
  processPendingImports,
  type ImportResult,
} from '../report-import.js';

export const importsRouter: Router = Router();

// Conservative ceiling — a healthy bundle is well under 50MB.
const MAX_BUNDLE_BYTES = 200 * 1024 * 1024;

/** Imports drop-folder, anchored to the active registry's runsRoot parent. */
function importsDir(): string {
  return join(dirname(getRegistry().runsRoot), 'imports');
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}
function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function resultPayload(result: ImportResult): Record<string, unknown> {
  return {
    bundle: result.bundle,
    status: result.status,
    folder_name: result.folder_name,
    versions_added: [...result.versions_added],
    versions_skipped: [...result.versions_skipped],
    error: result.error,
  };
}

/** GET /imports/info — absolute imports dir + processed/failed file lists. */
importsRouter.get('/imports/info', (_req: Request, res: Response) => {
  const dir = importsDir();
  ensureImportsDir(dir);

  const listSub = (sub: string): Array<{ name: string; size: number }> => {
    const path = join(dir, sub);
    if (!isDir(path)) return [];
    const out: Array<{ name: string; size: number }> = [];
    for (const name of readdirSync(path).sort()) {
      const entry = join(path, name);
      if (isFile(entry)) out.push({ name, size: statSync(entry).size });
    }
    return out;
  };

  res.json({
    imports_dir: dir,
    processed: listSub('processed'),
    failed: listSub('failed'),
  });
});

/** POST /imports/tfreport — upload a `.tfreport` bundle and import it inline. */
importsRouter.post(
  '/imports/tfreport',
  collectRawBody(MAX_BUNDLE_BYTES + 1024 * 1024),
  (req: Request, res: Response) => {
    const contentType = req.headers['content-type'] ?? '';
    const file = parseSingleFileUpload(req.rawBody, contentType);

    if (file === null || !file.filename) {
      res.status(400).json({ detail: 'Filename must end with .tfreport.' });
      return;
    }
    if (!file.filename.endsWith('.tfreport')) {
      res.status(400).json({ detail: 'Filename must end with .tfreport.' });
      return;
    }
    // Guard against directory traversal.
    const safeName = basename(file.filename);
    if (safeName !== file.filename || file.filename.includes('/') || file.filename.includes('\\')) {
      res.status(400).json({ detail: 'Filename contains path separators.' });
      return;
    }
    if (file.content.length > MAX_BUNDLE_BYTES) {
      res.status(413).json({ detail: `Bundle exceeds the ${Math.floor(MAX_BUNDLE_BYTES / (1024 * 1024))} MB limit.` });
      return;
    }

    const dir = importsDir();
    ensureImportsDir(dir);

    const target = join(dir, safeName);
    if (existsSync(target)) {
      res.status(409).json({
        detail: `A bundle named '${safeName}' is already pending in the imports directory. Rename your file and try again.`,
      });
      return;
    }

    try {
      const fd = openSync(target, 'w');
      try {
        writeSync(fd, file.content);
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      try {
        if (existsSync(target)) unlinkSync(target);
      } catch {
        /* ignore */
      }
      res.status(500).json({ detail: `Failed to save uploaded file: ${(err as Error).message}` });
      return;
    }

    const results = processPendingImports(dir, getRegistry());
    const own = results.find((r) => r.bundle === safeName);
    if (own === undefined) {
      res.status(500).json({
        detail: 'Upload saved but import did not run. Reload the Applications page to retry.',
      });
      return;
    }

    res.json({ result: resultPayload(own) });
  },
);

// ---------------------------------------------------------------------------
// Raw-body middleware + minimal multipart/form-data parser.
// ---------------------------------------------------------------------------

declare module 'express-serve-static-core' {
  interface Request {
    rawBody: Buffer;
  }
}

/** Collect the raw request body into `req.rawBody` (bounded by `limit`). */
function collectRawBody(limit: number) {
  return (req: Request, res: Response, next: (err?: unknown) => void): void => {
    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on('data', (chunk: Buffer) => {
      if (aborted) return;
      size += chunk.length;
      if (size > limit) {
        aborted = true;
        res.status(413).json({ detail: 'Upload exceeds the size limit.' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (aborted) return;
      req.rawBody = Buffer.concat(chunks);
      next();
    });
    req.on('error', (err) => {
      if (aborted) return;
      aborted = true;
      next(err);
    });
  };
}

interface UploadedFile {
  filename: string;
  content: Buffer;
}

/**
 * Extract the first file part of a multipart/form-data body. Returns null when
 * the body isn't multipart or carries no file part.
 */
function parseSingleFileUpload(body: Buffer | undefined, contentType: string): UploadedFile | null {
  if (!body || body.length === 0) return null;
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  if (!m) return null;
  const boundary = `--${m[1] ?? m[2] ?? ''}`.trim();
  if (boundary === '--') return null;

  const boundaryBuf = Buffer.from(boundary);
  const parts = splitBuffer(body, boundaryBuf);

  for (const part of parts) {
    // Each part begins with CRLF, then headers, then CRLF CRLF, then content.
    const headerEnd = indexOfDouble(part);
    if (headerEnd < 0) continue;
    const headerText = part.subarray(0, headerEnd).toString('utf-8');
    if (!/content-disposition/i.test(headerText)) continue;
    const fnMatch = /filename="([^"]*)"/i.exec(headerText);
    if (!fnMatch) continue; // not a file part

    // Content starts after the CRLF CRLF; trim the trailing CRLF before boundary.
    let content = part.subarray(headerEnd + 4);
    if (content.length >= 2 && content[content.length - 2] === 0x0d && content[content.length - 1] === 0x0a) {
      content = content.subarray(0, content.length - 2);
    }
    return { filename: fnMatch[1] ?? '', content: Buffer.from(content) };
  }
  return null;
}

/** Split a buffer on a delimiter, dropping empty/preamble/closing segments. */
function splitBuffer(buf: Buffer, delim: Buffer): Buffer[] {
  const out: Buffer[] = [];
  let start = 0;
  for (;;) {
    const idx = buf.indexOf(delim, start);
    if (idx < 0) {
      if (start < buf.length) out.push(buf.subarray(start));
      break;
    }
    if (idx > start) out.push(buf.subarray(start, idx));
    start = idx + delim.length;
  }
  // Trim leading CRLF on each part; drop the closing "--" sentinel parts.
  return out
    .map((p) => (p.length >= 2 && p[0] === 0x0d && p[1] === 0x0a ? p.subarray(2) : p))
    .filter((p) => p.length > 0 && !(p.length >= 2 && p[0] === 0x2d && p[1] === 0x2d));
}

/** Index of CRLF CRLF (header/body separator), or -1. */
function indexOfDouble(buf: Buffer): number {
  return buf.indexOf(Buffer.from('\r\n\r\n'));
}
