export type DispatchDestination =
  | 'run-command'
  | 'report-import'
  | 'ingestion';

export interface DispatchRelayChange {
  eventName: 'INSERT' | 'MODIFY' | 'REMOVE';
  newItem?: Record<string, unknown>;
  oldItem?: Record<string, unknown>;
}

export interface DispatchRelaySender {
  send(
    destination: DispatchDestination,
    payload: Record<string, unknown>,
  ): Promise<void>;
}

export class DispatchRelay {
  readonly #sender: DispatchRelaySender;

  constructor(sender: DispatchRelaySender) {
    this.#sender = sender;
  }

  async process(change: DispatchRelayChange): Promise<void> {
    const next = change.newItem;
    if (next === undefined) return;
    if (change.eventName === 'INSERT' && next.entity === 'outbox-event') {
      const destination = dispatchDestination(next.destination);
      await this.#sender.send(destination, object(next.payload, 'outbox payload'));
      return;
    }
    if (
      change.eventName === 'MODIFY' &&
      next.entity === 'upload_manifest'
    ) {
      const manifest = object(next.manifest, 'upload manifest');
      const previousManifest =
        change.oldItem === undefined
          ? {}
          : object(change.oldItem.manifest, 'previous upload manifest');
      if (
        manifest.status === 'uploaded' &&
        previousManifest.status !== 'uploaded'
      ) {
        const ownerId = string(manifest.ownerId, 'ownerId');
        const applicationId = string(manifest.applicationId, 'applicationId');
        const uploadId = string(manifest.uploadId, 'uploadId');
        const attempt = nonNegativeInteger(manifest.attempt, 'attempt') + 1;
        await this.#sender.send('ingestion', {
          schemaVersion: 1,
          jobId: `ingest-${uploadId}`,
          idempotencyKey: `upload-${uploadId}`,
          ownerId,
          applicationId,
          uploadId,
          attempt,
          enqueuedAt: string(manifest.updatedAt, 'updatedAt'),
        });
      }
    }
  }
}

function dispatchDestination(value: unknown): DispatchDestination {
  if (
    value === 'run-command' ||
    value === 'report-import' ||
    value === 'ingestion'
  ) {
    return value;
  }
  throw new Error('Outbox destination is unsupported');
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value as number;
}
