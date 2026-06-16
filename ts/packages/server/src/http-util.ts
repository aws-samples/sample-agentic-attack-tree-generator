/**
 * Small HTTP helpers shared by the route modules.
 *
 * Express 5's `req.params` values are typed `string | string[] | undefined`
 * (splat routes can produce arrays). Our route patterns only use single-value
 * params + one splat, so these helpers coerce to the concrete `string` the
 * handlers expect.
 */
import type { Request } from 'express';

/** Return a route param as a single string (joining splat array segments with `/`). */
export function param(req: Request, name: string): string {
  const value = (req.params as Record<string, string | string[] | undefined>)[name];
  if (value === undefined) return '';
  return Array.isArray(value) ? value.join('/') : value;
}
