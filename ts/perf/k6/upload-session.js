import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import exec from 'k6/execution';

export const options = {
  scenarios: {
    upload_sessions: {
      executor: 'shared-iterations',
      vus: 1,
      iterations: 3,
      maxDuration: '2m',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<2000'],
    checks: ['rate>0.99'],
  },
  userAgent: 'ThreatForest-k6-upload-session-baseline/1.0',
};

const baseUrl = required('TF_BASE_URL').replace(/\/+$/, '');
const accessToken = required('TF_ACCESS_TOKEN');
const applicationId = required('TF_APPLICATION_ID');
const baseHeaders = {
  Authorization: `Bearer ${accessToken}`,
  Cookie: 'tf_session=1',
  Accept: 'application/json',
};

export default function () {
  const idempotency = `k6-upload-${exec.scenario.iterationInTest}-${Date.now()}`;
  const create = http.post(
    `${baseUrl}/api/applications/${encodeURIComponent(applicationId)}/uploads`,
    JSON.stringify({
      filename: `k6-probe-${exec.scenario.iterationInTest}.txt`,
      content_type: 'text/plain',
      size_bytes: 1,
      checksum_sha256: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    }),
    {
      headers: {
        ...baseHeaders,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotency,
      },
      redirects: 0,
    },
  );
  const created = check(create, {
    'upload session created': (response) => response.status === 201 || response.status === 200,
    'upload id returned': (response) => Boolean(response.json('upload_id')),
    'one part planned': (response) => response.json('part_count') === 1,
  });
  if (!created) fail(`Upload-session creation failed: ${create.status} ${create.body}`);

  const uploadId = create.json('upload_id');
  const abort = http.del(
    `${baseUrl}/api/applications/${encodeURIComponent(
      applicationId,
    )}/uploads/${encodeURIComponent(uploadId)}`,
    null,
    {
      headers: {
        ...baseHeaders,
        'Idempotency-Key': `${idempotency}-abort`,
      },
      redirects: 0,
    },
  );
  check(abort, {
    'upload session aborted': (response) => response.status === 200,
  });
  sleep(5);
}

function required(name) {
  const value = __ENV[name];
  if (!value) fail(`Missing required environment variable ${name}`);
  return value;
}
