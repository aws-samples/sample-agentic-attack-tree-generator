import { sha256Blob, type JsonRequester } from './multipart-upload';

const DEFAULT_PART_SIZE_BYTES = 16 * 1024 * 1024;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_POLL_TIMEOUT_MS = 15 * 60 * 1_000;

interface ImportSessionResponse {
  import_id: string;
  status: 'pending' | 'uploading' | 'processing' | 'completed' | 'failed' | 'cancelled';
  part_size_bytes?: number;
  part_count?: number;
  result?: TfReportImportResult | null;
  failure_code?: string | null;
}

interface PartSignature {
  import_id: string;
  part_number: number;
  url: string;
  headers: Record<string, string>;
}

export interface TfReportImportResult {
  status: string;
  folder_name: string | null;
  versions_added: string[];
  versions_skipped: string[];
  error: string | null;
  [key: string]: unknown;
}

export interface ReportImportUploadOptions {
  request: JsonRequester;
  fetchPart?: typeof fetch;
  signal?: AbortSignal;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
}

interface CompletedPart {
  part_number: number;
  size_bytes: number;
  etag: string;
  checksum_sha256: string;
}

export async function uploadThreatforestReport(
  file: File,
  options: ReportImportUploadOptions,
): Promise<TfReportImportResult> {
  if (!file.name.endsWith('.tfreport') || file.size < 1) {
    throw new Error('Choose a non-empty .tfreport file.');
  }
  throwIfAborted(options.signal);
  const checksum = await sha256Blob(file);
  const base = '/api/imports/tfreport';
  const created = await options.request<ImportSessionResponse>(
    base,
    jsonRequest(
      {
        filename: file.name,
        content_type: 'application/zip',
        size_bytes: file.size,
        checksum_sha256: checksum,
        part_size_bytes: DEFAULT_PART_SIZE_BYTES,
      },
      options.signal,
    ),
  );
  const partSize = created.part_size_bytes;
  const partCount = created.part_count;
  if (
    typeof partSize !== 'number' ||
    typeof partCount !== 'number' ||
    partSize < 1 ||
    partCount !== Math.ceil(file.size / partSize)
  ) {
    throw new Error('Report import returned an invalid multipart layout.');
  }
  const fetchPart = options.fetchPart ?? fetch;
  const completed: CompletedPart[] = [];
  try {
    for (let number = 1; number <= partCount; number += 1) {
      throwIfAborted(options.signal);
      const start = (number - 1) * partSize;
      const part = file.slice(start, Math.min(start + partSize, file.size));
      const partChecksum = await sha256Blob(part);
      const signature = await options.request<PartSignature>(
        `${base}/${encodeURIComponent(created.import_id)}/parts`,
        jsonRequest(
          {
            part_number: number,
            size_bytes: part.size,
            checksum_sha256: partChecksum,
          },
          options.signal,
        ),
      );
      if (
        signature.import_id !== created.import_id ||
        signature.part_number !== number ||
        !signature.url.startsWith('https://')
      ) {
        throw new Error(`Report part ${number} returned an invalid signature.`);
      }
      const response = await fetchPart(signature.url, {
        method: 'PUT',
        headers: browserHeaders(signature.headers, part.size),
        body: part,
        signal: options.signal,
      });
      if (!response.ok) {
        throw new Error(
          `Report part ${number} failed with status ${response.status}.`,
        );
      }
      const etag = response.headers.get('etag');
      if (!etag) {
        throw new Error('Report upload response did not expose an ETag.');
      }
      completed.push({
        part_number: number,
        size_bytes: part.size,
        etag,
        checksum_sha256: partChecksum,
      });
    }
    let session = await options.request<ImportSessionResponse>(
      `${base}/${encodeURIComponent(created.import_id)}/complete`,
      jsonRequest({ parts: completed }, options.signal),
    );
    const deadline =
      Date.now() + (options.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS);
    const sleep = options.sleep ?? defaultSleep;
    while (session.status === 'processing') {
      if (Date.now() >= deadline) {
        throw new Error('Timed out waiting for report import processing.');
      }
      await sleep(
        options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
        options.signal,
      );
      session = await options.request<ImportSessionResponse>(
        `${base}/${encodeURIComponent(created.import_id)}`,
        { signal: options.signal },
      );
    }
    if (session.status !== 'completed' || session.result == null) {
      throw new Error(
        session.result?.error ||
          session.failure_code ||
          `Report import ended in state ${session.status}.`,
      );
    }
    return session.result;
  } catch (error) {
    await options.request(
      `${base}/${encodeURIComponent(created.import_id)}`,
      { method: 'DELETE' },
    ).catch(() => {});
    throw error;
  }
}

function jsonRequest(value: unknown, signal?: AbortSignal): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(value),
    signal,
  };
}

function browserHeaders(
  signedHeaders: Record<string, string>,
  expectedSize: number,
): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(signedHeaders)) {
    if (name.toLowerCase() === 'content-length') {
      if (value !== String(expectedSize)) {
        throw new Error('Report part signature has an invalid size constraint.');
      }
      continue;
    }
    headers.set(name, value);
  }
  return headers;
}

async function defaultSleep(
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new DOMException('The operation was aborted.', 'AbortError'));
      },
      { once: true },
    );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DOMException('The operation was aborted.', 'AbortError');
  }
}
