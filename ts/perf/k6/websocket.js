import http from 'k6/http';
import ws from 'k6/ws';
import { check, fail } from 'k6';

export const options = {
  scenarios: {
    replay: {
      executor: 'shared-iterations',
      vus: 1,
      iterations: 1,
      maxDuration: '45s',
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    ws_connecting: ['p(95)<3000'],
    ws_session_duration: ['p(95)<30000'],
  },
  userAgent: 'ThreatForest-k6-websocket-baseline/1.0',
};

const baseUrl = required('TF_BASE_URL').replace(/\/+$/, '');
const accessToken = required('TF_ACCESS_TOKEN');
const runId = required('TF_RUN_ID');
const headers = {
  Authorization: `Bearer ${accessToken}`,
  Cookie: 'tf_session=1',
  'Content-Type': 'application/json',
};

export default function () {
  const ticketResponse = http.post(
    `${baseUrl}/api/runs/${encodeURIComponent(runId)}/replay-ticket`,
    JSON.stringify({ after_sequence: -1 }),
    {
      headers: {
        ...headers,
        'Idempotency-Key': `k6-websocket-${Date.now()}`,
      },
      redirects: 0,
    },
  );
  if (
    !check(ticketResponse, {
      'replay ticket returned': (response) =>
        response.status === 200 && Boolean(response.json('ticket')),
    })
  ) {
    fail(`Replay ticket failed: ${ticketResponse.status} ${ticketResponse.body}`);
  }

  const socketUrl =
    `${baseUrl.replace(/^https:/, 'wss:')}/ws/runs/${encodeURIComponent(runId)}` +
    `?ticket=${encodeURIComponent(ticketResponse.json('ticket'))}` +
    '&after_sequence=-1';
  const response = ws.connect(
    socketUrl,
    {
      headers: {
        Cookie: 'tf_session=1',
        Origin: baseUrl,
      },
    },
    (socket) => {
      let previousSequence = -1;
      const eventIds = new Set();
      socket.on('open', () => {
        socket.send(JSON.stringify({ action: 'replay', after_sequence: -1 }));
      });
      socket.on('message', (raw) => {
        const event = JSON.parse(raw);
        check(event, {
          'sequence is monotonic': (value) => value.sequence > previousSequence,
          'event id is unique': (value) => !eventIds.has(value.event_id),
        });
        previousSequence = event.sequence;
        eventIds.add(event.event_id);
        if (eventIds.size >= 5 || event.type === 'run_complete') socket.close();
      });
      socket.setTimeout(() => socket.close(), 20_000);
    },
  );
  check(response, {
    'WebSocket upgraded': (result) => result && result.status === 101,
  });
}

function required(name) {
  const value = __ENV[name];
  if (!value) fail(`Missing required environment variable ${name}`);
  return value;
}
