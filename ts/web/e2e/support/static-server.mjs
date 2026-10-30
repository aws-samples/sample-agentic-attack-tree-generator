import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../out');
const port = Number.parseInt(process.env.TF_PLAYWRIGHT_PORT || '3100', 10);
const host = '127.0.0.1';

const staticRoutes = new Set([
  '/applications',
  '/applications/new',
  '/auth/callback',
  '/configure',
  '/new-run',
  '/paused-runs',
]);

const contentTypes = new Map([
  ['.avif', 'image/avif'],
  ['.css', 'text/css; charset=utf-8'],
  ['.gif', 'image/gif'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ico', 'image/x-icon'],
  ['.jpeg', 'image/jpeg'],
  ['.jpg', 'image/jpeg'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.map', 'application/json; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json'],
  ['.webp', 'image/webp'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
]);

function staticExportPath(pathname) {
  const route = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  if (route === '/') {
    return '/index.html';
  }
  if (staticRoutes.has(route)) {
    return `${route}/index.html`;
  }

  const segments = route.split('/').filter(Boolean);
  if (segments.length === 2 && segments[0] === 'applications') {
    return '/applications/__shell__/index.html';
  }
  if (
    segments.length === 4 &&
    segments[0] === 'applications' &&
    segments[2] === 'runs' &&
    segments[3] === 'new'
  ) {
    return '/applications/__shell__/runs/new/index.html';
  }
  if (
    segments.length === 4 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions'
  ) {
    return '/applications/__shell__/versions/__shell__/index.html';
  }
  if (
    segments.length === 5 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions' &&
    segments[4] === 'logs'
  ) {
    return '/applications/__shell__/versions/__shell__/logs/index.html';
  }
  if (
    segments.length === 6 &&
    segments[0] === 'applications' &&
    segments[2] === 'versions' &&
    segments[4] === 'threats'
  ) {
    return '/applications/__shell__/versions/__shell__/threats/__shell__/index.html';
  }
  if (
    segments.length === 3 &&
    segments[0] === 'runs' &&
    segments[2] === 'progress'
  ) {
    return '/runs/__shell__/progress/index.html';
  }
  return extname(route) ? route : '/index.html';
}

function safeFilePath(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (
    decoded.includes('\0') ||
    decoded.includes('\\') ||
    decoded.split('/').some((segment) => segment === '..')
  ) {
    return null;
  }
  const candidate = resolve(root, `.${decoded}`);
  return candidate.startsWith(`${root}${sep}`) ? candidate : null;
}

const server = createServer(async (request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD' });
    response.end();
    return;
  }

  const requestUrl = new URL(request.url || '/', `http://${host}:${port}`);
  const exportPath = staticExportPath(requestUrl.pathname);
  const filePath = safeFilePath(exportPath);
  if (filePath === null) {
    response.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Invalid path');
    return;
  }

  try {
    const metadata = await stat(filePath);
    if (!metadata.isFile()) {
      throw new Error('not a file');
    }
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Length': String(metadata.size),
      'Content-Type':
        contentTypes.get(extname(filePath).toLowerCase()) ||
        'application/octet-stream',
    });
    if (request.method === 'HEAD') {
      response.end();
      return;
    }
    createReadStream(filePath).pipe(response);
  } catch {
    response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    response.end('Not found');
  }
});

server.listen(port, host, () => {
  process.stdout.write(`ThreatForest static test server listening on http://${host}:${port}\n`);
});
