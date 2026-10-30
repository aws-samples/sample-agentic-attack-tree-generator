const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export type IdempotencyKeyFactory = () => string;

export function createIdempotencyKey(): string {
  const crypto = globalThis.crypto;
  if (typeof crypto?.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  if (typeof crypto?.getRandomValues !== 'function') {
    throw new Error('Secure browser randomness is required for API mutations.');
  }

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

/**
 * Assigns one key to a logical mutation. Calling this again with the returned
 * options preserves that key, which is how authentication retries remain safe.
 */
export function withMutationIdempotency(
  options: RequestInit = {},
  createKey: IdempotencyKeyFactory = createIdempotencyKey,
): RequestInit & { headers: Headers } {
  const headers = new Headers(options.headers);
  const method = (options.method ?? 'GET').toUpperCase();
  if (!SAFE_METHODS.has(method) && !headers.has('Idempotency-Key')) {
    headers.set('Idempotency-Key', createKey());
  }
  return { ...options, headers };
}
