import type { UploadId, UserId } from '@threatforest/types';
import { copy } from './runtime.js';
import type {
  MultipartCompletionRecord,
  SignedMultipartPart,
} from './contracts.js';
import type {
  ReportImportDispatcher,
  ReportImportSession,
  ReportImportStore,
} from './report-import-service.js';

function key(ownerId: UserId, importId: UploadId): string {
  return `${ownerId}\0${importId}`;
}

export class InMemoryReportImportStore implements ReportImportStore {
  readonly #sessions = new Map<string, ReportImportSession>();

  async get(
    ownerId: UserId,
    importId: UploadId,
  ): Promise<ReportImportSession | null> {
    const session = this.#sessions.get(key(ownerId, importId));
    return session === undefined ? null : copy(session);
  }

  async put(session: ReportImportSession): Promise<void> {
    this.#sessions.set(key(session.ownerId, session.importId), copy(session));
  }

  async recordSignedPart(
    ownerId: UserId,
    importId: UploadId,
    part: SignedMultipartPart,
    signedAt: string,
  ): Promise<ReportImportSession | null> {
    const itemKey = key(ownerId, importId);
    const existing = this.#sessions.get(itemKey);
    if (
      existing === undefined ||
      existing.completion !== undefined ||
      !['pending', 'uploading'].includes(existing.status)
    ) {
      return null;
    }
    const updated = copy(existing);
    updated.signedParts[String(part.partNumber)] = {
      sizeBytes: part.sizeBytes,
      checksumSha256: part.checksumSha256,
      signedAt,
    };
    updated.status = 'uploading';
    updated.updatedAt = signedAt;
    this.#sessions.set(itemKey, updated);
    return copy(updated);
  }

  async claimCompletion(
    ownerId: UserId,
    importId: UploadId,
    completion: MultipartCompletionRecord,
    claimedAt: string,
  ): Promise<ReportImportSession | null> {
    const itemKey = key(ownerId, importId);
    const existing = this.#sessions.get(itemKey);
    if (existing === undefined) {
      return null;
    }
    if (
      existing.completion !== undefined &&
      existing.completion.claimId !== completion.claimId &&
      existing.completion.claimExpiresAt > claimedAt
    ) {
      return null;
    }
    const claimed = copy(existing);
    claimed.completion = copy(completion);
    claimed.updatedAt = claimedAt;
    this.#sessions.set(itemKey, claimed);
    return copy(claimed);
  }

  async list(ownerId: UserId): Promise<ReportImportSession[]> {
    return [...this.#sessions.values()]
      .filter((session) => session.ownerId === ownerId)
      .map(copy)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }
}

export class RecordingReportImportDispatcher
  implements ReportImportDispatcher
{
  readonly dispatches: Array<{ ownerId: UserId; importId: UploadId }> = [];

  async dispatch(ownerId: UserId, importId: UploadId): Promise<void> {
    this.dispatches.push({ ownerId, importId });
  }
}
