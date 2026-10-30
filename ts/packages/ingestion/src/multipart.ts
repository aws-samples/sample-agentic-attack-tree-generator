import { timingSafeEqual } from 'node:crypto';
import type { MultipartCompletedPart, UploadPart } from './types.js';

export interface MultipartVerificationOptions {
  readonly declaredSizeBytes: number;
  readonly expectedParts?: readonly UploadPart[];
  readonly minimumPartBytes?: number;
  readonly maximumPartBytes?: number;
  readonly maximumParts?: number;
}

export interface MultipartVerificationResult {
  readonly parts: readonly UploadPart[];
  readonly totalSizeBytes: number;
}

export class MultipartVerificationError extends Error {
  public constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'MultipartVerificationError';
  }
}

const DEFAULT_MINIMUM_PART_BYTES = 5 * 1024 * 1024;
const DEFAULT_MAXIMUM_PART_BYTES = 5 * 1024 * 1024 * 1024;

export function verifyMultipartCompletion(
  completedParts: readonly MultipartCompletedPart[],
  options: MultipartVerificationOptions,
): MultipartVerificationResult {
  const maximumParts = options.maximumParts ?? 10_000;
  if (completedParts.length === 0 || completedParts.length > maximumParts) {
    throw new MultipartVerificationError(
      'INVALID_PART_COUNT',
      `Multipart completion must contain 1-${maximumParts} parts`,
    );
  }
  if (!Number.isSafeInteger(options.declaredSizeBytes) || options.declaredSizeBytes < 1) {
    throw new MultipartVerificationError(
      'INVALID_DECLARED_SIZE',
      'Multipart uploads require a positive declared size',
    );
  }

  const minimumPartBytes = options.minimumPartBytes ?? DEFAULT_MINIMUM_PART_BYTES;
  const maximumPartBytes = options.maximumPartBytes ?? DEFAULT_MAXIMUM_PART_BYTES;
  const expectedByNumber = new Map(
    (options.expectedParts ?? []).map((part) => [part.partNumber, part]),
  );
  const verified: UploadPart[] = [];
  let totalSizeBytes = 0;

  completedParts.forEach((part, index) => {
    const expectedPartNumber = index + 1;
    if (part.partNumber !== expectedPartNumber) {
      throw new MultipartVerificationError(
        'INVALID_PART_ORDER',
        `Expected part ${expectedPartNumber}, received ${part.partNumber}`,
      );
    }
    if (
      !Number.isSafeInteger(part.sizeBytes) ||
      part.sizeBytes < 1 ||
      part.sizeBytes > maximumPartBytes
    ) {
      throw new MultipartVerificationError(
        'INVALID_PART_SIZE',
        `Part ${part.partNumber} has an invalid size`,
      );
    }
    const isLast = index === completedParts.length - 1;
    if (!isLast && part.sizeBytes < minimumPartBytes) {
      throw new MultipartVerificationError(
        'PART_TOO_SMALL',
        `Part ${part.partNumber} is below the minimum multipart size`,
      );
    }
    const checksum = normalizeSha256Checksum(part.checksumSha256);
    const etag = normalizeEtag(part.etag);
    const expected = expectedByNumber.get(part.partNumber);
    if (expected !== undefined) {
      if (
        expected.sizeBytes !== part.sizeBytes ||
        !safeStringEqual(normalizeEtag(expected.etag), etag) ||
        !safeStringEqual(normalizeSha256Checksum(expected.checksumSha256), checksum)
      ) {
        throw new MultipartVerificationError(
          'PART_MISMATCH',
          `Completed part ${part.partNumber} does not match the registered upload part`,
        );
      }
    }
    totalSizeBytes += part.sizeBytes;
    if (!Number.isSafeInteger(totalSizeBytes)) {
      throw new MultipartVerificationError('SIZE_OVERFLOW', 'Multipart size exceeds safe integer range');
    }
    verified.push({
      partNumber: part.partNumber,
      sizeBytes: part.sizeBytes,
      etag,
      checksumSha256: checksum,
    });
  });

  if (expectedByNumber.size > 0 && expectedByNumber.size !== verified.length) {
    throw new MultipartVerificationError(
      'PART_COUNT_MISMATCH',
      'Completed part count does not match registered upload parts',
    );
  }
  if (totalSizeBytes !== options.declaredSizeBytes) {
    throw new MultipartVerificationError(
      'TOTAL_SIZE_MISMATCH',
      `Completed upload size ${totalSizeBytes} does not match declared size ${options.declaredSizeBytes}`,
    );
  }
  return { parts: verified, totalSizeBytes };
}

export function normalizeSha256Checksum(value: string): string {
  const trimmed = value.trim();
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex').toString('base64');
  }
  if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed)) {
    return trimmed;
  }
  throw new MultipartVerificationError(
    'INVALID_CHECKSUM',
    'Part checksum must be SHA-256 encoded as 64 hex characters or base64',
  );
}

function normalizeEtag(value: string): string {
  const trimmed = value.trim();
  const unquoted = trimmed.startsWith('"') && trimmed.endsWith('"') ? trimmed.slice(1, -1) : trimmed;
  if (!/^[A-Za-z0-9+/=_-]{1,256}$/.test(unquoted)) {
    throw new MultipartVerificationError('INVALID_ETAG', 'Part ETag is invalid');
  }
  return unquoted;
}

function safeStringEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}
