/**
 * Shared tracing session for a ThreatForest pipeline run.
 *
 * TS port of `src/threatforest/agents/tracing_session.py`. Provides a session
 * ID and a `traceAttributes` object that every agent passes to the Strands
 * `Agent` so all spans in Langfuse are grouped under the same session.
 *
 * Parity with the Python:
 *  - `initSession()`          <- `init_session()`        (module-level session id)
 *  - `getSessionId()`         <- `get_session_id()`
 *  - `traceAttrs(agentName)`  <- `trace_attrs(agent_name)`
 *  - `setupLangfuseOtel()`    <- `setup_langfuse_otel()`
 *
 * Langfuse wiring is byte-for-byte the same env-var contract as the Python:
 * we base64 `${public}:${secret}` and set OTEL_EXPORTER_OTLP_ENDPOINT to
 * `${host}/api/public/otel` and OTEL_EXPORTER_OTLP_HEADERS to
 * `Authorization=Basic <auth>`. The Strands TS telemetry helper
 * (`setupTracer({ exporters: { otlp: true } })`) then reads those two env vars
 * automatically — it is the analog of Python's
 * `StrandsTelemetry().setup_otlp_exporter()`. The SDK's Tracer also detects
 * Langfuse specifically from OTEL_EXPORTER_OTLP_ENDPOINT, so setting that var
 * is the correct (and sufficient) trigger.
 *
 * No-op-safe: when Langfuse is disabled/unconfigured we clear any leftover
 * OTEL env vars and never register an exporter, exactly like the Python.
 */
import { randomUUID } from 'node:crypto';
import type { AttributeValue } from '@opentelemetry/api';

let _sessionId: string | null = null;
let _otelInitialized = false;

/** Start a new tracing session and return its ID. */
export function initSession(): string {
  // Python uses uuid4().hex[:12]; randomUUID() is 8-4-4-4-12 hex with dashes,
  // so strip dashes then take the first 12 hex chars for an identical shape.
  const hex = randomUUID().replace(/-/g, '');
  _sessionId = `tf-${hex.slice(0, 12)}`;
  return _sessionId;
}

/** Current session id, or null if `initSession()` has not been called. */
export function getSessionId(): string | null {
  return _sessionId;
}

/**
 * trace_attributes for a Strands `Agent` (pass as the `traceAttributes` option).
 *
 * Returns the Python shape `{ 'session.id': sid, 'langfuse.tags': [...] }`.
 * `AttributeValue` admits `string[]`, so the tags stay a real array — no
 * JSON.stringify required. Returns `{}` (no attributes) when no session is
 * active, mirroring the Python's empty-dict short-circuit.
 */
export function traceAttrs(agentName: string): Record<string, AttributeValue> {
  if (!_sessionId) {
    return {};
  }
  return {
    'session.id': _sessionId,
    'langfuse.tags': ['threatforest', agentName],
  };
}

/**
 * Configure the Strands OTEL exporter to send traces to Langfuse.
 *
 * Reads LANGFUSE_* env vars (loaded via the app's dotenv) and sets up the OTLP
 * exporter. Safe to call multiple times — the OTEL provider is only registered
 * once (`_otelInitialized` guard, matching the Python `_otel_initialized`).
 */
export function setupLangfuseOtel(): void {
  const publicKey = process.env.LANGFUSE_PUBLIC_KEY;
  const secretKey = process.env.LANGFUSE_SECRET_KEY;
  const enabled = (process.env.LANGFUSE_ENABLED ?? 'false').toLowerCase() === 'true';
  const host = process.env.LANGFUSE_HOST ?? 'https://cloud.langfuse.com';

  if (!enabled || !publicKey || !secretKey) {
    // Clear any leftover OTEL env vars so a previously-initialized exporter
    // doesn't keep trying to reach an unreachable host.
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    delete process.env.OTEL_EXPORTER_OTLP_HEADERS;
    return;
  }

  const auth = Buffer.from(`${publicKey}:${secretKey}`).toString('base64');
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = `${host}/api/public/otel`;
  process.env.OTEL_EXPORTER_OTLP_HEADERS = `Authorization=Basic ${auth}`;

  if (_otelInitialized) {
    return;
  }
  _otelInitialized = true;

  // Lazy import so this module stays loadable in environments where the
  // telemetry subpath / its OTEL peer deps aren't present (the Python guards
  // the equivalent `from strands.telemetry import StrandsTelemetry` with
  // `except ImportError: pass`). `setupTracer` picks up the OTLP env vars set
  // above; we don't need to pass the endpoint explicitly.
  void import('@strands-agents/sdk/telemetry')
    .then(({ setupTracer }) => {
      setupTracer({ exporters: { otlp: true } });
    })
    .catch(() => {
      // Telemetry unavailable — degrade to no tracing, same as the Python.
    });
}
