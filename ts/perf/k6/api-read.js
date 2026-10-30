import http from 'k6/http';
import { check, fail, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '20s', target: 1 },
    { duration: '40s', target: 5 },
    { duration: '20s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1500', 'p(99)<3000'],
    checks: ['rate>0.99'],
  },
  noConnectionReuse: false,
  userAgent: 'ThreatForest-k6-read-baseline/1.0',
};

const baseUrl = required('TF_BASE_URL').replace(/\/+$/, '');
const accessToken = required('TF_ACCESS_TOKEN');
const headers = {
  Authorization: `Bearer ${accessToken}`,
  Cookie: 'tf_session=1',
  Accept: 'application/json',
};

export default function () {
  const responses = http.batch([
    ['GET', `${baseUrl}/api/health`, null, { headers, redirects: 0 }],
    ['GET', `${baseUrl}/api/applications`, null, { headers, redirects: 0 }],
    ['GET', `${baseUrl}/api/runs?status=pending,running`, null, { headers, redirects: 0 }],
    ['GET', `${baseUrl}/api/config/frameworks`, null, { headers, redirects: 0 }],
  ]);
  check(responses, {
    'all read endpoints returned 200': (items) =>
      items.every((response) => response.status === 200),
    'responses are JSON': (items) =>
      items.every((response) =>
        String(response.headers['Content-Type'] || '').includes('application/json'),
      ),
  });
  sleep(1);
}

function required(name) {
  const value = __ENV[name];
  if (!value) fail(`Missing required environment variable ${name}`);
  return value;
}
