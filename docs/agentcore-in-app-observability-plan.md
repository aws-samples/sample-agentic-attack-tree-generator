# ThreatForest in-app execution observability

## Behavior

The **Logs** action on the latest and previous threat models opens an execution workspace. Collapsible pipeline phases contain selectable agent/task cards, including separate attack-tree, TTP-mapping, and mitigation workers for each threat. The selected task shows its status, timing, model, and a chronological log timeline.

The running pipeline's **Activity Feed** uses the same log renderer alongside WebSocket milestones. Both views show recorded requests, responses, exposed model reasoning, tool inputs/results, errors, duration, and available token usage. JSON formatting and line breaks are preserved. Large entries have **Show more / Show less** controls. Search includes content, and the live feed can filter by phase. Scrolling up pauses **Follow latest** until the user re-enables it.

## Capture and delivery

1. The hosted engine adapter establishes an asynchronous context for the owner, application, run, correlation ID, current phase, and phase attempt. Concurrent runs do not share this context.
2. Agent SDK hooks emit short `threatforest.execution` OpenTelemetry spans for agent requests, model requests/results, tool calls/results, and final agent responses. A request span ends before its model/tool call executes, allowing it to be exported while work is still running. This avoids waiting for a long invocation span to finish.
3. Each event has a unique ID plus phase, task/worker, invocation, operation, and sequence identifiers. Deterministic TTP matching emits corresponding tool request/result events. Existing stage and human-review telemetry remains visible; deterministic phases do not manufacture model reasoning.
4. The existing runtime ADOT exporter delivers these spans to CloudWatch `aws/spans`. No new external log destination is introduced.
5. The hosted API verifies run ownership, queries CloudWatch, checks span membership, and projects accepted records into the shared `RunLogEntry` contract. New execution events carry their own scope and phase; normalization does not need their parent span on the same page.
6. Both UI views use the same paging hook and content renderer.

Legacy SDK agent/model/tool spans are supported where their recorded content and verified run association are available. SDK root spans marked as using the new execution capture are suppressed to avoid duplicate final responses. Historical runs cannot recover content that was never recorded or has expired under the log group's retention policy.

## API and pagination

`GET /api/runs/{runId}/logs`

| Query parameter | Meaning |
| --- | --- |
| `since` | Optional start timestamp; defaults to run creation. |
| `until` | Optional fixed upper timestamp for a pagination window. |
| `next_token` | CloudWatch continuation token for that same window. |

The response contains `run_id`, ordered `entries`, `next_token`, `window_end`, and source `agentcore_cloudwatch`. Entries optionally include typed `content` blocks, `agent_id`, `agent_name`, and `invocation_id`. Content kinds are `request`, `response`, `reasoning`, `tool_input`, `tool_result`, and `error`; message roles are retained when available.

- Pages contain at most 100 CloudWatch events. Empty pages with continuation tokens are consumed, with no fixed total-page cap.
- The first response establishes a fixed query end time. All continuation requests use that window; the watermark advances only after the final page.
- Live polling starts from run creation, then uses a two-minute overlap. Normal polling is every five seconds, backing off to fifteen seconds for empty responses. Only one request is in flight per view.
- Entries are merged by ID and sorted chronologically. Repeated IDs update existing entries; they are not appended again. Invocation IDs keep a later retry from inheriting an earlier invocation's completed status.
- Live polling continues for sixty seconds after completion/pause/stop/failure to allow normal export delay, then stops. Explicit refresh starts a fresh scan from run creation and recovers later arrivals.
- CloudWatch ingestion/export latency still applies. A delay exceeding the overlap or final settling period may require refresh; this is not token-by-token WebSocket streaming.
- Retrieval failures remain visible without disrupting run controls. Repeated pagination cursors produce a recoverable error instead of silently skipping unconsumed pages.

## Content integrity and access

- Run ownership is checked before querying CloudWatch. An explicit mismatching owner, application, or run rejects the span. A run ID appearing only inside arbitrary text is not sufficient association.
- The API returns normalized fields, not raw spans. Responses are displayed as text, never interpreted as HTML.
- Source excerpts and actual tool payloads are included when recorded, subject to redaction and capture bounds. This allows review of business context, source evidence, and mitigation coverage.
- Credential-shaped fields, AWS access keys, bearer/JWT values, and common inline credential assignments are redacted at capture and again on API projection. Internal owner/application/run workspace prefixes are removed. This is targeted redaction, not a guarantee that every arbitrary secret format is recognizable.
- System messages, reasoning signatures, and redacted reasoning bytes are excluded. Only text explicitly exposed by the model as reasoning is shown; no hidden reasoning is reconstructed or inferred. A completed model event without reasoning says that none was recorded.
- Total content per execution event is bounded to 12,000 characters. Long blocks share the budget so reasoning cannot erase the response. Structural limits are 100 array/object entries and twelve nesting levels. Truncation is explicitly flagged; expanding an entry reveals the recorded portion, not discarded content.
- Model parameters and reasoning settings are unchanged. Capture adds no model calls.
- CloudWatch retention and the existing HTTP Lambda's read-only log permissions remain in effect.

## Validation

Automated checks cover:

- Real SDK lifecycle hooks using an offline scripted model: requests precede model completion, tool input/result pairing, exposed reasoning, token usage, and model failures.
- Concurrent run context and hosted adapter scope propagation, plus non-fatal telemetry exporter failures.
- Content sanitization, legacy/stable message formats, credential redaction, role preservation, and accurate truncation markers.
- API ownership, conflicting scope, text-only false matches, malformed events, worker identity without a parent page, and pagination bounds.
- Paging beyond 25 pages, empty intermediate pages, transient/repeated cursors, overlapping updates, and retry task status.
- Browser navigation from application Logs actions, task selection, content expansion/filtering, recovery from retrieval errors, live pagination/updates, automatic polling, terminal settling, auto-follow, and narrow-screen rendering.

## Scaling option

If CloudWatch query volume becomes significant, a subscription consumer can project the same contract into tenant-keyed storage and publish events through the existing run WebSocket. The phase/task UI and typed content contract can remain unchanged.
