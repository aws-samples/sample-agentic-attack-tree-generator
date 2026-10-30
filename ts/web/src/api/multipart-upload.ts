import type { ArtifactRef, UploadManifest } from '@threatforest/types';

const SHA256_BLOCK_BYTES = 64;
const DEFAULT_HASH_CHUNK_BYTES = 4 * 1024 * 1024;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_POLL_TIMEOUT_MS = 10 * 60 * 1_000;

const SHA256_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

type UploadPhase = 'hashing' | 'uploading' | 'processing' | 'complete';

export interface UploadProgress {
  phase: UploadPhase;
  bytesUploaded: number;
  totalBytes: number;
  partNumber?: number;
  partCount?: number;
}

export type JsonRequester = <T>(url: string, options?: RequestInit) => Promise<T>;

export interface MultipartUploadOptions {
  request: JsonRequester;
  fetchPart?: typeof fetch;
  signal?: AbortSignal;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>;
  onProgress?: (progress: UploadProgress) => void;
}

export interface MultipartUploadResult {
  uploadId: string;
  artifact: ArtifactRef;
  manifest: UploadManifest;
}

interface CreateUploadResponse {
  upload_id: string;
  manifest: UploadManifest;
  part_size_bytes: number;
  part_count: number;
}

interface PresignPartResponse {
  upload_id: string;
  part_number: number;
  url: string;
  expires_at: string;
  headers: Record<string, string>;
}

interface UploadManifestResponse {
  upload_id: string;
  manifest: UploadManifest;
}

interface CompletedUploadPart {
  part_number: number;
  size_bytes: number;
  etag: string;
  checksum_sha256: string;
}

class IncrementalSha256 {
  readonly #state = new Uint32Array([
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ]);
  readonly #buffer = new Uint8Array(SHA256_BLOCK_BYTES);
  readonly #words = new Uint32Array(64);
  #bufferLength = 0;
  #bytesHashed = 0;
  #finished = false;

  update(input: Uint8Array): void {
    if (this.#finished) throw new Error('SHA-256 digest has already been finalized.');
    this.#bytesHashed += input.byteLength;
    let offset = 0;

    if (this.#bufferLength > 0) {
      const length = Math.min(SHA256_BLOCK_BYTES - this.#bufferLength, input.byteLength);
      this.#buffer.set(input.subarray(0, length), this.#bufferLength);
      this.#bufferLength += length;
      offset += length;
      if (this.#bufferLength === SHA256_BLOCK_BYTES) {
        this.#transform(this.#buffer);
        this.#bufferLength = 0;
      }
    }

    while (offset + SHA256_BLOCK_BYTES <= input.byteLength) {
      this.#transform(input.subarray(offset, offset + SHA256_BLOCK_BYTES));
      offset += SHA256_BLOCK_BYTES;
    }

    if (offset < input.byteLength) {
      const remainder = input.subarray(offset);
      this.#buffer.set(remainder, 0);
      this.#bufferLength = remainder.byteLength;
    }
  }

  digestHex(): string {
    if (this.#finished) throw new Error('SHA-256 digest has already been finalized.');
    this.#finished = true;

    const finalLength =
      this.#bufferLength < 56 ? SHA256_BLOCK_BYTES : SHA256_BLOCK_BYTES * 2;
    const finalBlock = new Uint8Array(finalLength);
    finalBlock.set(this.#buffer.subarray(0, this.#bufferLength));
    finalBlock[this.#bufferLength] = 0x80;

    const bitLength = this.#bytesHashed * 8;
    const view = new DataView(finalBlock.buffer);
    view.setUint32(finalLength - 8, Math.floor(bitLength / 0x1_0000_0000));
    view.setUint32(finalLength - 4, bitLength >>> 0);
    this.#transform(finalBlock.subarray(0, SHA256_BLOCK_BYTES));
    if (finalLength > SHA256_BLOCK_BYTES) {
      this.#transform(finalBlock.subarray(SHA256_BLOCK_BYTES));
    }

    return Array.from(
      this.#state,
      (value) => value.toString(16).padStart(8, '0'),
    ).join('');
  }

  #transform(block: Uint8Array): void {
    const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
    for (let index = 0; index < 16; index += 1) {
      this.#words[index] = view.getUint32(index * 4);
    }
    for (let index = 16; index < 64; index += 1) {
      const previous15 = this.#words[index - 15]!;
      const previous2 = this.#words[index - 2]!;
      const sigma0 =
        rotateRight(previous15, 7) ^
        rotateRight(previous15, 18) ^
        (previous15 >>> 3);
      const sigma1 =
        rotateRight(previous2, 17) ^
        rotateRight(previous2, 19) ^
        (previous2 >>> 10);
      this.#words[index] =
        (this.#words[index - 16]! +
          sigma0 +
          this.#words[index - 7]! +
          sigma1) >>>
        0;
    }

    let a = this.#state[0]!;
    let b = this.#state[1]!;
    let c = this.#state[2]!;
    let d = this.#state[3]!;
    let e = this.#state[4]!;
    let f = this.#state[5]!;
    let g = this.#state[6]!;
    let h = this.#state[7]!;

    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temporary1 =
        (h + sum1 + choice + SHA256_CONSTANTS[index]! + this.#words[index]!) >>> 0;
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (sum0 + majority) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temporary1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temporary1 + temporary2) >>> 0;
    }

    this.#state[0] = (this.#state[0]! + a) >>> 0;
    this.#state[1] = (this.#state[1]! + b) >>> 0;
    this.#state[2] = (this.#state[2]! + c) >>> 0;
    this.#state[3] = (this.#state[3]! + d) >>> 0;
    this.#state[4] = (this.#state[4]! + e) >>> 0;
    this.#state[5] = (this.#state[5]! + f) >>> 0;
    this.#state[6] = (this.#state[6]! + g) >>> 0;
    this.#state[7] = (this.#state[7]! + h) >>> 0;
  }
}

function rotateRight(value: number, places: number): number {
  return (value >>> places) | (value << (32 - places));
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new DOMException('The operation was aborted.', 'AbortError');
  }
}

async function defaultSleep(milliseconds: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(
          signal.reason instanceof Error
            ? signal.reason
            : new DOMException('The operation was aborted.', 'AbortError'),
        );
      },
      { once: true },
    );
  });
}

export async function sha256Blob(
  blob: Blob,
  chunkSizeBytes = DEFAULT_HASH_CHUNK_BYTES,
): Promise<string> {
  if (!Number.isSafeInteger(chunkSizeBytes) || chunkSizeBytes < 1) {
    throw new Error('SHA-256 chunk size must be a positive integer.');
  }
  const hash = new IncrementalSha256();
  for (let offset = 0; offset < blob.size; offset += chunkSizeBytes) {
    hash.update(
      new Uint8Array(
        await blob.slice(offset, Math.min(offset + chunkSizeBytes, blob.size)).arrayBuffer(),
      ),
    );
  }
  return hash.digestHex();
}

function jsonRequest(body: unknown, signal?: AbortSignal): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  };
}

function browserUploadHeaders(
  signedHeaders: Record<string, string>,
  expectedSize: number,
): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(signedHeaders)) {
    if (name.toLowerCase() === 'content-length') {
      if (value !== String(expectedSize)) {
        throw new Error('The presigned upload has an invalid content-length constraint.');
      }
      // Browsers calculate Content-Length from the Blob and do not allow
      // JavaScript to set this forbidden request header.
      continue;
    }
    headers.set(name, value);
  }
  return headers;
}

function requireSourceArtifact(manifest: UploadManifest): ArtifactRef {
  if (manifest.status !== 'ready') {
    throw new Error(`Upload reached unexpected status ${manifest.status}.`);
  }
  if (manifest.source_artifact === null) {
    throw new Error('Upload completed without a source artifact.');
  }
  return manifest.source_artifact;
}

export async function waitForUploadedManifest(
  appId: string,
  uploadId: string,
  initialManifest: UploadManifest,
  options: MultipartUploadOptions,
): Promise<UploadManifest> {
  const timeout = options.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS;
  const interval = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const sleep = options.sleep ?? defaultSleep;
  const deadline = Date.now() + timeout;
  let manifest = initialManifest;

  while (manifest.status !== 'ready') {
    if (manifest.status === 'failed') {
      throw new Error(manifest.failure_reason || 'Upload processing failed.');
    }
    if (manifest.status === 'cancelled') {
      throw new Error('Upload was cancelled.');
    }
    if (Date.now() >= deadline) {
      throw new Error(`Timed out waiting for upload ${uploadId} to become available.`);
    }
    options.onProgress?.({
      phase: 'processing',
      bytesUploaded: manifest.size_bytes,
      totalBytes: manifest.size_bytes,
    });
    await sleep(interval, options.signal);
    throwIfAborted(options.signal);
    const response = await options.request<UploadManifestResponse>(
      `/api/applications/${encodeURIComponent(appId)}/uploads/${encodeURIComponent(uploadId)}`,
      { signal: options.signal },
    );
    manifest = response.manifest;
  }

  requireSourceArtifact(manifest);
  return manifest;
}

export async function uploadApplicationFile(
  appId: string,
  file: File,
  options: MultipartUploadOptions,
): Promise<MultipartUploadResult> {
  if (file.size < 1) {
    throw new Error(`${file.name} is empty and cannot be uploaded.`);
  }
  throwIfAborted(options.signal);
  options.onProgress?.({
    phase: 'hashing',
    bytesUploaded: 0,
    totalBytes: file.size,
  });
  const fileChecksum = await sha256Blob(file);
  throwIfAborted(options.signal);

  const basePath = `/api/applications/${encodeURIComponent(appId)}/uploads`;
  const created = await options.request<CreateUploadResponse>(
    basePath,
    jsonRequest(
      {
        filename: file.name,
        content_type: file.type || 'application/octet-stream',
        size_bytes: file.size,
        checksum_sha256: fileChecksum,
      },
      options.signal,
    ),
  );
  if (
    !Number.isSafeInteger(created.part_size_bytes) ||
    created.part_size_bytes < 1 ||
    !Number.isSafeInteger(created.part_count) ||
    created.part_count < 1 ||
    Math.ceil(file.size / created.part_size_bytes) !== created.part_count
  ) {
    throw new Error('Upload initialization returned an invalid multipart layout.');
  }

  const fetchPart = options.fetchPart ?? fetch;
  const completedParts: CompletedUploadPart[] = [];
  let bytesUploaded = 0;
  try {
    for (let partNumber = 1; partNumber <= created.part_count; partNumber += 1) {
      throwIfAborted(options.signal);
      const start = (partNumber - 1) * created.part_size_bytes;
      const end = Math.min(start + created.part_size_bytes, file.size);
      const part = file.slice(start, end);
      const checksum = await sha256Blob(part);
      const signature = await options.request<PresignPartResponse>(
        `${basePath}/${encodeURIComponent(created.upload_id)}/parts`,
        jsonRequest(
          {
            part_number: partNumber,
            size_bytes: part.size,
            checksum_sha256: checksum,
          },
          options.signal,
        ),
      );
      if (
        signature.upload_id !== created.upload_id ||
        signature.part_number !== partNumber ||
        !signature.url.startsWith('https://')
      ) {
        throw new Error(`Upload part ${partNumber} returned an invalid signature.`);
      }

      const response = await fetchPart(signature.url, {
        method: 'PUT',
        headers: browserUploadHeaders(signature.headers, part.size),
        body: part,
        signal: options.signal,
      });
      if (!response.ok) {
        throw new Error(`Upload part ${partNumber} failed with status ${response.status}.`);
      }
      const etag = response.headers.get('etag');
      if (!etag) {
        throw new Error(
          'The upload response did not expose an ETag. Check the artifact bucket CORS policy.',
        );
      }
      completedParts.push({
        part_number: partNumber,
        size_bytes: part.size,
        etag,
        checksum_sha256: checksum,
      });
      bytesUploaded += part.size;
      options.onProgress?.({
        phase: 'uploading',
        bytesUploaded,
        totalBytes: file.size,
        partNumber,
        partCount: created.part_count,
      });
    }

    const completed = await options.request<UploadManifestResponse>(
      `${basePath}/${encodeURIComponent(created.upload_id)}/complete`,
      jsonRequest({ parts: completedParts }, options.signal),
    );
    const manifest = await waitForUploadedManifest(
      appId,
      created.upload_id,
      completed.manifest,
      options,
    );
    const artifact = requireSourceArtifact(manifest);
    options.onProgress?.({
      phase: 'complete',
      bytesUploaded: file.size,
      totalBytes: file.size,
    });
    return { uploadId: created.upload_id, artifact, manifest };
  } catch (error) {
    try {
      await options.request<unknown>(`${basePath}/${encodeURIComponent(created.upload_id)}`, {
        method: 'DELETE',
        signal: options.signal?.aborted ? undefined : options.signal,
      });
    } catch {
      // The original upload failure is more useful than a best-effort abort failure.
    }
    throw error;
  }
}
