import { describe, expect, it, vi } from 'vitest';
import type { UploadManifest } from '@threatforest/types';
import {
  sha256Blob,
  uploadApplicationFile,
  waitForUploadedManifest,
  type JsonRequester,
} from './multipart-upload.js';

const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const DEF_SHA256 = 'cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34';
const ABCDEF_SHA256 = 'bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721';

function manifest(status: UploadManifest['status']): UploadManifest {
  return {
    schema_version: 1,
    owner_id: 'user_1',
    upload_id: 'upload_1',
    application_id: 'app_1',
    filename: 'source.txt',
    content_type: 'text/plain',
    size_bytes: 6,
    status,
    parts: [],
    source_artifact:
      status === 'uploaded' || status === 'ready'
        ? {
            artifact_id: 'artifact_1',
            kind: 'source',
            version: 1,
            content_type: 'text/plain',
            size_bytes: 6,
            sha256: ABCDEF_SHA256,
            created_at: '2026-08-19T12:00:00.000Z',
          }
        : null,
    normalized_artifacts: [],
    created_at: '2026-08-19T12:00:00.000Z',
    updated_at: '2026-08-19T12:00:00.000Z',
    failure_reason: null,
  } as unknown as UploadManifest;
}

describe('sha256Blob', () => {
  it('hashes incrementally across chunk boundaries', async () => {
    await expect(sha256Blob(new Blob(['abc']), 1)).resolves.toBe(ABC_SHA256);
    await expect(sha256Blob(new Blob(['abcdef']), 2)).resolves.toBe(ABCDEF_SHA256);
    await expect(sha256Blob(new Blob(['a'.repeat(1_000)]), 67)).resolves.toBe(
      '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3',
    );
  });
});

describe('uploadApplicationFile', () => {
  it('uploads every signed part and completes with checksums and ETags', async () => {
    const apiCalls: Array<{ url: string; body?: unknown; method: string }> = [];
    const request: JsonRequester = async <T>(url: string, options?: RequestInit) => {
      const method = options?.method ?? 'GET';
      const body =
        typeof options?.body === 'string'
          ? (JSON.parse(options.body) as unknown)
          : undefined;
      apiCalls.push({ url, body, method });

      if (url.endsWith('/uploads')) {
        return {
          upload_id: 'upload_1',
          manifest: manifest('pending'),
          part_size_bytes: 3,
          part_count: 2,
        } as T;
      }
      if (url.endsWith('/parts')) {
        const partNumber = (body as { part_number: number }).part_number;
        const checksum = (body as { checksum_sha256: string }).checksum_sha256;
        return {
          upload_id: 'upload_1',
          part_number: partNumber,
          url: `https://uploads.example/part-${partNumber}`,
          expires_at: '2026-08-19T12:15:00.000Z',
          headers: {
            'content-length': '3',
            'x-amz-checksum-sha256':
              checksum === ABC_SHA256
                ? 'ungWv48Bz+pBQUQUDJT4Xw6dFArB8QJHn4bAyhrS3qc='
                : 'y4N5rCCYqhZQKeOTilHaC87PwAj9Z5X0AReGR/lsWzQ=',
          },
        } as T;
      }
      if (url.endsWith('/complete')) {
        return { upload_id: 'upload_1', manifest: manifest('uploaded') } as T;
      }
      if (url.endsWith('/uploads/upload_1') && method === 'GET') {
        return { upload_id: 'upload_1', manifest: manifest('ready') } as T;
      }
      throw new Error(`Unexpected request: ${method} ${url}`);
    };

    const uploadedBodies: string[] = [];
    const fetchPart = vi.fn<typeof fetch>(async (_input, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.has('content-length')).toBe(false);
      expect(headers.has('x-amz-checksum-sha256')).toBe(true);
      uploadedBodies.push(await (init?.body as Blob).text());
      return new Response(null, {
        status: 200,
        headers: { etag: `"etag-${uploadedBodies.length}"` },
      });
    });

    const result = await uploadApplicationFile(
      'app_1',
      new File(['abcdef'], 'source.txt', { type: 'text/plain' }),
      { request, fetchPart },
    );

    expect(result.artifact.artifact_id).toBe('artifact_1');
    expect(uploadedBodies).toEqual(['abc', 'def']);
    expect(fetchPart).toHaveBeenCalledTimes(2);
    expect(apiCalls[0]?.body).toMatchObject({
      filename: 'source.txt',
      size_bytes: 6,
      checksum_sha256: ABCDEF_SHA256,
    });
    expect(apiCalls[1]?.body).toMatchObject({
      part_number: 1,
      checksum_sha256: ABC_SHA256,
    });
    expect(apiCalls[2]?.body).toMatchObject({
      part_number: 2,
      checksum_sha256: DEF_SHA256,
    });
    expect(apiCalls[3]?.body).toEqual({
      parts: [
        {
          part_number: 1,
          size_bytes: 3,
          etag: '"etag-1"',
          checksum_sha256: ABC_SHA256,
        },
        {
          part_number: 2,
          size_bytes: 3,
          etag: '"etag-2"',
          checksum_sha256: DEF_SHA256,
        },
      ],
    });
    expect(apiCalls[4]).toMatchObject({ method: 'GET' });
  });
});

describe('waitForUploadedManifest', () => {
  it('polls processing uploads until the source artifact is ready', async () => {
    const requestCalls = vi.fn();
    const request: JsonRequester = async <T>(
      url: string,
      options?: RequestInit,
    ): Promise<T> => {
      requestCalls(url, options);
      return { upload_id: 'upload_1', manifest: manifest('ready') } as T;
    };
    const sleep = vi.fn(async () => {});

    const result = await waitForUploadedManifest(
      'app_1',
      'upload_1',
      manifest('uploaded'),
      { request, sleep, pollIntervalMs: 1 },
    );

    expect(result.status).toBe('ready');
    expect(requestCalls).toHaveBeenCalledTimes(1);
    expect(sleep).toHaveBeenCalledWith(1, undefined);
  });
});
