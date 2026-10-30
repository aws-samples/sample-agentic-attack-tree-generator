# ThreatForest k6 Probes

These probes are deliberately conservative and require explicit environment
values. They send requests through CloudFront, including the session cookie and
short-lived Cognito access token.

```bash
k6 run \
  -e TF_BASE_URL="$TF_BASE_URL" \
  -e TF_ACCESS_TOKEN="$TF_TEST_USER_A_ACCESS_TOKEN" \
  ts/perf/k6/api-read.js
```

The upload-session probe also requires `TF_APPLICATION_ID`. It creates and
immediately aborts small multipart sessions; it does not upload object data.
The WebSocket probe requires `TF_RUN_ID`.

Do not raise rates until the baseline passes without WAF blocks, throttles, or
increased API and Runtime error alarms.
