import { describe, expect, it, vi } from 'vitest';
import { withMutationIdempotency } from './idempotency.js';

describe('withMutationIdempotency', () => {
  it('reuses the same key when a logical mutation is prepared for retry', () => {
    const createKey = vi
      .fn<() => string>()
      .mockReturnValueOnce('logical-request-1')
      .mockReturnValueOnce('must-not-be-used');

    const firstAttempt = withMutationIdempotency(
      { method: 'POST', body: '{"name":"app"}' },
      createKey,
    );
    const retry = withMutationIdempotency(firstAttempt, createKey);

    expect(firstAttempt.headers.get('Idempotency-Key')).toBe('logical-request-1');
    expect(retry.headers.get('Idempotency-Key')).toBe('logical-request-1');
    expect(createKey).toHaveBeenCalledTimes(1);
  });

  it('creates distinct keys for distinct mutations and none for reads', () => {
    const createKey = vi
      .fn<() => string>()
      .mockReturnValueOnce('mutation-1')
      .mockReturnValueOnce('mutation-2');

    const first = withMutationIdempotency({ method: 'DELETE' }, createKey);
    const second = withMutationIdempotency({ method: 'PATCH' }, createKey);
    const read = withMutationIdempotency({ method: 'GET' }, createKey);

    expect(first.headers.get('Idempotency-Key')).toBe('mutation-1');
    expect(second.headers.get('Idempotency-Key')).toBe('mutation-2');
    expect(read.headers.has('Idempotency-Key')).toBe(false);
  });
});
