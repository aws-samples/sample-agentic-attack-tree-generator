'use client';

import { useParams, usePathname } from 'next/navigation';

/**
 * Resolve dynamic route params from the LIVE pathname.
 *
 * Under Next's `output: 'export'`, each dynamic route is pre-rendered exactly
 * once against the `generateStaticParams()` placeholder (we use `__shell__`),
 * and the server hands that same shell HTML to every real deep-link. The
 * client then boots with `useParams()` returning the baked-in `__shell__`
 * values — NOT the segments in the URL bar — so data fetches hit
 * `/api/applications/__shell__/...` and 404.
 *
 * `usePathname()`, by contrast, reads the actual current URL, so we recover the
 * real segment values by matching the route `template` against it positionally.
 * Values are URL-decoded. If a segment is missing or still the `__shell__`
 * sentinel we fall back to `useParams()` (covers truly-static mounts of a
 * shared component, e.g. NewRunView at `/new-run`).
 *
 * @param template the route pattern, e.g. `/applications/[appId]/versions/[versionId]`
 */
export function useRealParams<T extends Record<string, string>>(template: string): T {
  const pathname = usePathname() ?? '';
  const fallback = useParams() as Record<string, string | string[] | undefined>;

  const templateSegments = template.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);

  const out: Record<string, string> = {};
  for (let i = 0; i < templateSegments.length; i++) {
    const seg = templateSegments[i]!;
    const match = /^\[(?:\.\.\.)?(.+?)\]$/.exec(seg);
    if (!match) continue;
    const key = match[1]!;
    const fromPath = pathSegments[i];
    if (fromPath !== undefined && fromPath !== '__shell__') {
      try {
        out[key] = decodeURIComponent(fromPath);
      } catch {
        out[key] = fromPath;
      }
    } else {
      const fb = fallback[key];
      out[key] = Array.isArray(fb) ? (fb[0] ?? '') : (fb ?? '');
    }
  }
  return out as T;
}
