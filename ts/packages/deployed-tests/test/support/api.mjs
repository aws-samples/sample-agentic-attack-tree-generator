import { createHash, randomUUID } from 'node:crypto';
import { normalizedBaseUrl } from './env.mjs';

function apiUrl(path) {
  return new URL(path, `${normalizedBaseUrl()}/`).toString();
}

export async function apiRequest(path, token, options = {}) {
  const headers = new Headers(options.headers);
  headers.set('authorization', `Bearer ${token}`);
  headers.set('cookie', 'tf_session=1');
  if (options.json !== undefined) {
    headers.set('content-type', 'application/json');
    options = { ...options, body: JSON.stringify(options.json) };
  }
  if (
    options.method !== undefined &&
    options.method !== 'GET' &&
    options.method !== 'HEAD' &&
    !headers.has('idempotency-key')
  ) {
    headers.set('idempotency-key', `deployed-test:${randomUUID()}`);
  }

  const response = await fetch(apiUrl(path), {
    ...options,
    headers,
    redirect: 'manual',
  });
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  return { response, body };
}

export async function expectApi(path, token, options = {}) {
  const result = await apiRequest(path, token, options);
  if (!result.response.ok) {
    throw new Error(
      `${options.method || 'GET'} ${path} failed with ${result.response.status}: ${
        typeof result.body === 'string' ? result.body : JSON.stringify(result.body)
      }`,
    );
  }
  return result;
}

export async function createApplication(token, namePrefix = 'Deployed Test') {
  const suffix = randomUUID().slice(0, 8);
  const { body } = await expectApi('/api/applications', token, {
    method: 'POST',
    json: {
      name: `${namePrefix} ${suffix}`,
      project_path: `/hosted/deployed-tests/${suffix}`,
      business_context: {
        description: 'Ephemeral deployed integration test application.',
        regulatory_frameworks: ['AWS Well-Architected'],
        data_sensitivity: 'internal',
        cia_priority: ['confidentiality', 'integrity', 'availability'],
      },
    },
  });
  if (!body?.id) throw new Error('Application response did not contain an id.');
  return body;
}

export async function deleteApplication(token, applicationId) {
  return apiRequest(`/api/applications/by-id/${encodeURIComponent(applicationId)}`, token, {
    method: 'DELETE',
  });
}

export function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

export async function uploadBuffer(token, applicationId, filename, contentType, data) {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const wholeChecksum = sha256(buffer);
  const basePath = `/api/applications/${encodeURIComponent(applicationId)}/uploads`;
  const { body: created } = await expectApi(basePath, token, {
    method: 'POST',
    json: {
      filename,
      content_type: contentType,
      size_bytes: buffer.byteLength,
      checksum_sha256: wholeChecksum,
    },
  });
  const parts = [];
  let objectKey = null;
  try {
    for (let partNumber = 1; partNumber <= created.part_count; partNumber += 1) {
      const start = (partNumber - 1) * created.part_size_bytes;
      const part = buffer.subarray(
        start,
        Math.min(start + created.part_size_bytes, buffer.byteLength),
      );
      const checksum = sha256(part);
      const { body: signature } = await expectApi(
        `${basePath}/${encodeURIComponent(created.upload_id)}/parts`,
        token,
        {
          method: 'POST',
          json: {
            part_number: partNumber,
            size_bytes: part.byteLength,
            checksum_sha256: checksum,
          },
        },
      );
      if (objectKey === null) {
        objectKey = decodeURIComponent(
          new URL(signature.url).pathname.replace(/^\/+/, ''),
        );
      }
      const uploadHeaders = new Headers(signature.headers || {});
      uploadHeaders.set('content-length', String(part.byteLength));
      const uploaded = await fetch(signature.url, {
        method: 'PUT',
        headers: uploadHeaders,
        body: part,
      });
      if (!uploaded.ok) {
        const responseBody = await uploaded.text();
        throw new Error(
          `Presigned upload part ${partNumber} failed: ${uploaded.status} ${responseBody}`,
        );
      }
      const etag = uploaded.headers.get('etag');
      if (!etag) throw new Error('Presigned upload did not return an ETag.');
      parts.push({
        part_number: partNumber,
        size_bytes: part.byteLength,
        etag,
        checksum_sha256: checksum,
      });
    }

    const { body: completed } = await expectApi(
      `${basePath}/${encodeURIComponent(created.upload_id)}/complete`,
      token,
      { method: 'POST', json: { parts } },
    );
    const manifest = await poll(
      async () => {
        const { body } = await expectApi(
          `${basePath}/${encodeURIComponent(created.upload_id)}`,
          token,
        );
        if (body.manifest?.status === 'failed') {
          throw new Error(body.manifest.failure_reason || 'Upload normalization failed.');
        }
        return body.manifest?.status === 'ready' ? body.manifest : null;
      },
      { timeoutMs: 15 * 60_000, intervalMs: 2_000, label: 'upload normalization' },
    );
    if (objectKey === null) {
      throw new Error('Presigned upload did not expose an S3 object key.');
    }
    return { uploadId: created.upload_id, objectKey, manifest, completed };
  } catch (error) {
    await apiRequest(`${basePath}/${encodeURIComponent(created.upload_id)}`, token, {
      method: 'DELETE',
    }).catch(() => {});
    throw error;
  }
}

export async function poll(operation, options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const intervalMs = options.intervalMs ?? 1_000;
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await operation();
      if (value !== null && value !== undefined && value !== false) return value;
    } catch (error) {
      lastError = error;
      if (options.retryErrors !== true) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(
    `Timed out waiting for ${options.label || 'condition'}${
      lastError ? `: ${lastError.message}` : ''
    }`,
  );
}
