import type { RunId } from '@threatforest/types';

export function runLeaseResourceId(runId: RunId): string {
  return `run:${runId}`;
}

export function encodeKeyPart(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

export function sequenceKey(sequence: number): string {
  return sequence.toString().padStart(16, '0');
}
