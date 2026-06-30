// @ts-check

/**
 * Next.js config for the ThreatForest UI.
 *
 * - `output: 'export'` produces a fully static site (the TS server serves the
 *   exported HTML/JS just like the old Vite `dist/`). No Node runtime is
 *   required to serve the UI, matching the legacy SPA deployment model.
 * - `rewrites()` is the dev-server equivalent of the Vite proxy: it forwards
 *   `/api/*` and `/ws/*` to the FastAPI/TS backend on :8000 so `next dev` can
 *   talk to a locally running server. Rewrites are a dev-only convenience —
 *   they are NOT applied to the static export, where the UI and API are served
 *   from the same origin (so same-origin relative URLs resolve correctly).
 *
 * The backend target is overridable via THREATFOREST_API_TARGET for non-default
 * local setups; it defaults to http://localhost:8000 (the Vite proxy default).
 */

const API_TARGET = process.env.THREATFOREST_API_TARGET || 'http://localhost:8000';

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  reactStrictMode: true,
  // Static export emits per-route folders (trailingSlash makes /foo -> /foo/index.html),
  // which is friendlier to plain static file servers.
  trailingSlash: true,
  // `next/image` optimization needs a server; disable it for static export.
  images: {
    unoptimized: true,
  },
  // Dev-only proxy (the Vite-proxy equivalent). Returned only outside a
  // production build so `next build`/`output: export` doesn't warn that
  // rewrites are ignored in a static export — at runtime the UI and API are
  // same-origin (the TS server hosts the exported assets), so no proxy is
  // needed there.
  async rewrites() {
    if (process.env.NODE_ENV === 'production') return [];
    return [
      { source: '/api/:path*', destination: `${API_TARGET}/api/:path*` },
      { source: '/ws/:path*', destination: `${API_TARGET}/ws/:path*` },
    ];
  },
};

export default nextConfig;
