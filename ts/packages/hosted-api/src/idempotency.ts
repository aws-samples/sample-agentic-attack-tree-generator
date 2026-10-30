import { createHash } from 'node:crypto';
import type { ControlPlaneScope, ControlPlaneStore } from '@threatforest/control-plane';
import type { IdempotencyRecord } from '@threatforest/types';
import { conflict, unprocessable } from './errors.js';
import type {
  Clock,
  MutationResponseRecord,
  MutationResponseStore,
} from './contracts.js';

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(',')}}`;
}

export function requestHash(operation: string, request: unknown): string {
  return createHash('sha256')
    .update(canonical({ operation, request }))
    .digest('hex');
}

export interface IdempotencyExecutorOptions {
  store: ControlPlaneStore;
  responses: MutationResponseStore;
  clock: Clock;
  ttlSeconds?: number;
}

export class IdempotencyExecutor {
  readonly #store: ControlPlaneStore;
  readonly #responses: MutationResponseStore;
  readonly #clock: Clock;
  readonly #ttlSeconds: number;

  constructor(options: IdempotencyExecutorOptions) {
    this.#store = options.store;
    this.#responses = options.responses;
    this.#clock = options.clock;
    this.#ttlSeconds = options.ttlSeconds ?? 24 * 60 * 60;
  }

  async execute<T>(
    scope: ControlPlaneScope,
    key: string,
    operation: string,
    request: unknown,
    action: () => Promise<MutationResponseRecord & { value: T }>,
  ): Promise<MutationResponseRecord & { value: T }> {
    if (!/^[\x21-\x7e]{1,512}$/.test(key)) {
      throw unprocessable('Idempotency-Key must contain 1-512 visible ASCII characters.');
    }
    const now = this.#clock.now();
    const createdAt = now.toISOString();
    const hash = requestHash(operation, request);
    const record: IdempotencyRecord = {
      schema_version: 1,
      owner_id: scope.owner_id,
      application_id: scope.application_id,
      key,
      operation,
      request_hash: hash,
      status: 'in_progress',
      response_artifact: null,
      created_at: createdAt,
      expires_at: new Date(now.getTime() + this.#ttlSeconds * 1000).toISOString(),
    };
    const claim = await this.#store.claimIdempotency(record, createdAt);
    if (!claim.acquired) {
      if (claim.record.status !== 'completed') {
        throw conflict(
          `Idempotency key ${key} is ${claim.record.status}.`,
          'idempotency_in_progress',
        );
      }
      const stored = await this.#responses.get(scope, key);
      if (stored === null) {
        throw conflict(
          `The completed response for idempotency key ${key} is unavailable.`,
          'idempotency_response_unavailable',
        );
      }
      return stored as MutationResponseRecord & { value: T };
    }

    try {
      const response = await action();
      await this.#responses.put(scope, key, response);
      await this.#store.completeIdempotency({
        ...scope,
        key,
        request_hash: hash,
        claim_created_at: createdAt,
        response_artifact: null,
      });
      return response;
    } catch (error) {
      try {
        await this.#store.failIdempotency({
          ...scope,
          key,
          request_hash: hash,
          claim_created_at: createdAt,
        });
      } catch {
        // The original operation error is more useful than cleanup failure.
      }
      throw error;
    }
  }
}
