import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { decodeJwt, optional, skipUnless } from './support/env.mjs';

const MCP_PROTOCOL_VERSION = '2025-06-18';
const TOOL_PREFIX = 'ThreatForestTools___';
const AGENTCORE_SEARCH_TOOL = 'x_amz_bedrock_agentcore_search';
const TOOL_NAMES = Object.freeze([
  'list_applications',
  'get_application',
  'create_application',
  'update_application',
  'delete_application',
  'list_runs',
  'get_run',
  'start_run',
  'pause_run',
  'stop_run',
  'resume_run',
  'list_pending_interactions',
  'respond_to_interaction',
  'skip_interaction',
]);
const MUTATION_TOOL_NAMES = new Set([
  'create_application',
  'update_application',
  'delete_application',
  'start_run',
  'pause_run',
  'stop_run',
  'resume_run',
  'respond_to_interaction',
  'skip_interaction',
]);
const BUSINESS_CONTEXT = Object.freeze({
  description: 'Ephemeral AgentCore MCP deployed acceptance test.',
  regulatory_frameworks: ['AWS Well-Architected'],
  data_sensitivity: 'internal',
  cia_priority: ['confidentiality', 'integrity', 'availability'],
});

function parsePayloads(text, contentType) {
  if (text.trim() === '') return [];
  if (!contentType.includes('text/event-stream')) {
    return [JSON.parse(text)];
  }

  const payloads = [];
  let dataLines = [];
  const flush = () => {
    if (dataLines.length === 0) return;
    const data = dataLines.join('\n').trim();
    dataLines = [];
    if (data !== '' && data !== '[DONE]') payloads.push(JSON.parse(data));
  };
  for (const line of `${text}\n`.split(/\r?\n/)) {
    if (line === '') {
      flush();
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }
  return payloads;
}

function responseSummary(exchange) {
  const payload =
    exchange.payload === null
      ? exchange.text
      : JSON.stringify(exchange.payload);
  return `${exchange.status} ${payload}`.slice(0, 4_000);
}

async function mcpRequest({ token, sessionId }, method, params, id) {
  const headers = {
    authorization: `Bearer ${token}`,
    accept: 'application/json, text/event-stream',
    'content-type': 'application/json',
    'mcp-protocol-version': MCP_PROTOCOL_VERSION,
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;

  const message = { jsonrpc: '2.0', method, params };
  if (id !== undefined) message.id = id;
  const response = await fetch(optional('TF_GATEWAY_URL'), {
    method: 'POST',
    headers,
    body: JSON.stringify(message),
  });
  const text = await response.text();
  let payloads = [];
  let parseError = null;
  try {
    payloads = parsePayloads(
      text,
      response.headers.get('content-type') || '',
    );
  } catch (error) {
    parseError = error;
  }
  const payload =
    id === undefined
      ? payloads.at(-1) ?? null
      : payloads.find((candidate) => candidate?.id === id) ??
        payloads.at(-1) ??
        null;
  return {
    status: response.status,
    ok: response.ok,
    text,
    payload,
    parseError,
    sessionId: response.headers.get('mcp-session-id') || sessionId,
  };
}

function expectRpcResult(exchange, id, method) {
  assert.equal(
    exchange.ok,
    true,
    `MCP ${method} transport failed: ${responseSummary(exchange)}`,
  );
  assert.equal(
    exchange.parseError,
    null,
    `MCP ${method} returned malformed JSON/SSE: ${exchange.parseError?.message}`,
  );
  assert.equal(exchange.payload?.jsonrpc, '2.0');
  assert.equal(exchange.payload?.id, id);
  assert.equal(
    exchange.payload?.error,
    undefined,
    `MCP ${method} returned a JSON-RPC error: ${responseSummary(exchange)}`,
  );
  assert.ok(
    Object.hasOwn(exchange.payload || {}, 'result'),
    `MCP ${method} response did not contain a result.`,
  );
  return exchange.payload.result;
}

function parseNestedJson(value) {
  let current = value;
  for (
    let depth = 0;
    depth < 2 && typeof current === 'string';
    depth += 1
  ) {
    try {
      current = JSON.parse(current);
    } catch {
      return null;
    }
  }
  return current;
}

function toolEnvelope(result) {
  const candidates = [result, result?.structuredContent];
  for (const content of result?.content || []) {
    candidates.push(content?.structuredContent, content?.json, content?.text);
  }
  for (const candidate of candidates) {
    const parsed = parseNestedJson(candidate);
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      typeof parsed.ok === 'boolean'
    ) {
      return parsed;
    }
  }
  return null;
}

class McpClient {
  #nextId = 1;

  constructor(token) {
    this.token = token;
    this.sessionId = null;
  }

  async initialize() {
    const id = this.#nextId++;
    const exchange = await mcpRequest(
      this,
      'initialize',
      {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: {
          name: 'threatforest-deployed-tests',
          version: '1.0.0',
        },
      },
      id,
    );
    this.sessionId = exchange.sessionId;
    const result = expectRpcResult(exchange, id, 'initialize');
    assert.equal(result?.protocolVersion, MCP_PROTOCOL_VERSION);

    const initialized = await mcpRequest(
      this,
      'notifications/initialized',
      {},
      undefined,
    );
    this.sessionId = initialized.sessionId;
    assert.equal(
      initialized.ok,
      true,
      `MCP initialized notification failed: ${responseSummary(initialized)}`,
    );
    assert.equal(
      initialized.parseError,
      null,
      `MCP initialized notification returned malformed data: ${initialized.parseError?.message}`,
    );
    assert.equal(
      initialized.payload?.error,
      undefined,
      `MCP initialized notification was rejected: ${responseSummary(initialized)}`,
    );
    return result;
  }

  async request(method, params) {
    const id = this.#nextId++;
    const exchange = await mcpRequest(this, method, params, id);
    this.sessionId = exchange.sessionId;
    return { exchange, id };
  }

  async rpc(method, params) {
    const { exchange, id } = await this.request(method, params);
    return expectRpcResult(exchange, id, method);
  }

  async callRaw(name, args) {
    return this.request('tools/call', {
      name: `${TOOL_PREFIX}${name}`,
      arguments: args,
    });
  }

  async call(name, args) {
    const { exchange, id } = await this.callRaw(name, args);
    const result = expectRpcResult(exchange, id, `tools/call ${name}`);
    assert.notEqual(
      result?.isError,
      true,
      `MCP tool ${name} reported an error: ${JSON.stringify(result)}`,
    );
    const envelope = toolEnvelope(result);
    assert.ok(
      envelope,
      `MCP tool ${name} did not return the ThreatForest response envelope: ${JSON.stringify(
        result,
      )}`,
    );
    assert.equal(
      envelope.ok,
      true,
      `MCP tool ${name} failed: ${JSON.stringify(envelope.error)}`,
    );
    assert.equal(envelope.tool, name);
    return envelope.result;
  }
}

async function connectedClient(token) {
  const client = new McpClient(token);
  await client.initialize();
  return client;
}

function tokenSubject(token) {
  const subject = decodeJwt(token).sub;
  assert.equal(typeof subject, 'string');
  assert.notEqual(subject, '');
  return subject;
}

function fixtureSkip(...names) {
  return skipUnless(
    'TF_GATEWAY_URL',
    'TF_TEST_USER_A_ACCESS_TOKEN',
    ...names,
  );
}

test(
  'AgentCore Gateway negotiates MCP and exposes the exact ThreatForest tool contract',
  {
    skip: fixtureSkip(),
    timeout: 30_000,
  },
  async () => {
    const client = await connectedClient(
      optional('TF_TEST_USER_A_ACCESS_TOKEN'),
    );
    const result = await client.rpc('tools/list', {});
    assert.ok(Array.isArray(result?.tools));

    const toolsByName = new Map(
      result.tools.map((tool) => [tool.name, tool]),
    );
    assert.equal(
      toolsByName.size,
      result.tools.length,
      'AgentCore returned duplicate MCP tool names.',
    );
    const threatForestNames = TOOL_NAMES.map(
      (name) => `${TOOL_PREFIX}${name}`,
    );
    assert.deepEqual(
      [...toolsByName.keys()]
        .filter((name) => name.startsWith(TOOL_PREFIX))
        .sort(),
      threatForestNames.sort(),
    );
    assert.deepEqual(
      [...toolsByName.keys()].filter(
        (name) =>
          !name.startsWith(TOOL_PREFIX) &&
          name !== AGENTCORE_SEARCH_TOOL,
      ),
      [],
      'AgentCore exposed an unexpected non-ThreatForest tool.',
    );
    for (const name of TOOL_NAMES) {
      const tool = toolsByName.get(`${TOOL_PREFIX}${name}`);
      assert.equal(tool?.inputSchema?.type, 'object');
      assert.ok(tool.inputSchema.required?.includes('owner_id'));
      assert.equal(
        tool.inputSchema.required?.includes('idempotency_key') === true,
        MUTATION_TOOL_NAMES.has(name),
      );
      assert.equal(typeof tool.description, 'string');
      assert.notEqual(tool.description.trim(), '');
    }
  },
);

test(
  'MCP application CRUD is tenant-scoped and mutation retries are idempotent',
  {
    skip: fixtureSkip(),
    timeout: 60_000,
  },
  async () => {
    const token = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const ownerId = tokenSubject(token);
    const client = await connectedClient(token);
    const suffix = randomUUID();
    const createArguments = {
      owner_id: ownerId,
      idempotency_key: `deployed-mcp:create:${suffix}`,
      name: `MCP Acceptance ${suffix.slice(0, 8)}`,
      project_path: `/hosted/deployed-tests/mcp/${suffix}`,
      business_context: BUSINESS_CONTEXT,
    };
    let applicationId = null;
    let deleted = false;

    try {
      const created = await client.call(
        'create_application',
        createArguments,
      );
      assert.equal(created?.status, 201);
      assert.equal(created?.value?.name, createArguments.name);
      assert.equal(
        created?.value?.project_path,
        createArguments.project_path,
      );
      applicationId = created?.value?.id;
      assert.equal(typeof applicationId, 'string');
      assert.notEqual(applicationId, '');

      const replayed = await client.call(
        'create_application',
        createArguments,
      );
      assert.deepEqual(replayed, created);

      const listed = await client.call('list_applications', {
        owner_id: ownerId,
      });
      assert.ok(Array.isArray(listed?.applications));
      assert.equal(
        listed.applications.filter((entry) => entry.id === applicationId)
          .length,
        1,
      );

      const fetched = await client.call('get_application', {
        owner_id: ownerId,
        application_id: applicationId,
      });
      assert.equal(fetched.id, applicationId);
      assert.equal(fetched.name, createArguments.name);

      const updatedName = `${createArguments.name} Updated`;
      const updatedPath = `${createArguments.project_path}/updated`;
      const updated = await client.call('update_application', {
        owner_id: ownerId,
        idempotency_key: `deployed-mcp:update:${suffix}`,
        application_id: applicationId,
        name: updatedName,
        project_path: updatedPath,
      });
      assert.equal(updated?.status, 200);
      assert.equal(updated?.value?.id, applicationId);
      assert.equal(updated?.value?.name, updatedName);
      assert.equal(updated?.value?.project_path, updatedPath);

      const runs = await client.call('list_runs', {
        owner_id: ownerId,
      });
      assert.ok(Array.isArray(runs?.runs));

      const deleteArguments = {
        owner_id: ownerId,
        idempotency_key: `deployed-mcp:delete:${suffix}`,
        application_id: applicationId,
      };
      const removed = await client.call(
        'delete_application',
        deleteArguments,
      );
      assert.equal(removed?.status, 200);
      assert.equal(removed?.value?.success, true);
      deleted = true;
      assert.deepEqual(
        await client.call('delete_application', deleteArguments),
        removed,
      );

      const afterDelete = await client.call('list_applications', {
        owner_id: ownerId,
      });
      assert.equal(
        afterDelete.applications.some(
          (entry) => entry.id === applicationId,
        ),
        false,
      );
    } finally {
      if (applicationId !== null && !deleted) {
        await client
          .call('delete_application', {
            owner_id: ownerId,
            idempotency_key: `deployed-mcp:cleanup:${suffix}`,
            application_id: applicationId,
          })
          .catch(() => {});
      }
    }
  },
);

test(
  'AgentCore policy denies user B when owner_id is user A',
  {
    skip: skipUnless(
      'TF_GATEWAY_URL',
      'TF_TEST_USER_A_ACCESS_TOKEN',
      'TF_TEST_USER_B_ACCESS_TOKEN',
    ),
    timeout: 60_000,
  },
  async () => {
    const tokenA = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const tokenB = optional('TF_TEST_USER_B_ACCESS_TOKEN');
    const ownerA = tokenSubject(tokenA);
    const ownerB = tokenSubject(tokenB);
    assert.notEqual(ownerA, ownerB, 'User A and user B must be distinct.');

    const clientA = await connectedClient(tokenA);
    const ownA = await clientA.call('list_applications', {
      owner_id: ownerA,
    });
    assert.ok(Array.isArray(ownA?.applications));

    const clientB = await connectedClient(tokenB);
    const ownB = await clientB.call('list_applications', {
      owner_id: ownerB,
    });
    assert.ok(Array.isArray(ownB?.applications));

    const { exchange, id } = await clientB.callRaw('list_applications', {
      owner_id: ownerA,
    });
    assert.equal(
      exchange.ok,
      true,
      `Policy denial returned an unexpected transport error: ${responseSummary(
        exchange,
      )}`,
    );
    assert.equal(exchange.parseError, null);
    assert.equal(exchange.payload?.jsonrpc, '2.0');
    assert.equal(exchange.payload?.id, id);
    assert.equal(exchange.payload?.result, undefined);
    assert.equal(exchange.payload?.error?.code, -32002);
    assert.match(
      exchange.payload?.error?.message || '',
      /Tool Execution Denied.*policy/is,
      `Cross-user failure did not identify an authorization denial: ${responseSummary(
        exchange,
      )}`,
    );
  },
);

test(
  'MCP reads a deployed run and can explicitly respond to a pending HITL fixture',
  {
    skip: fixtureSkip('TF_TEST_RUN_ID'),
    timeout: 60_000,
  },
  async () => {
    const token = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const ownerId = tokenSubject(token);
    const runId = optional('TF_TEST_RUN_ID');
    const client = await connectedClient(token);

    const run = await client.call('get_run', {
      owner_id: ownerId,
      run_id: runId,
    });
    assert.equal(run?.state?.run_id, runId);

    const listed = await client.call('list_runs', {
      owner_id: ownerId,
    });
    assert.equal(
      listed.runs.some((entry) => entry.run_id === runId),
      true,
    );

    const pending = await client.call('list_pending_interactions', {
      owner_id: ownerId,
      run_id: runId,
    });
    assert.ok(Array.isArray(pending));

    const action = optional('TF_MCP_HITL_ACTION');
    if (action === null) return;
    assert.match(
      action,
      /^(respond|skip)$/,
      'TF_MCP_HITL_ACTION must be respond or skip.',
    );
    const configuredInteractionId = optional(
      'TF_MCP_HITL_INTERACTION_ID',
    );
    const interaction =
      configuredInteractionId === null
        ? pending[0]
        : pending.find(
            (entry) =>
              entry.interaction_id === configuredInteractionId,
          );
    assert.ok(
      interaction,
      'The configured run has no matching pending HITL interaction.',
    );
    assert.equal(Number.isSafeInteger(interaction.revision), true);
    assert.ok(interaction.revision > 0);

    const idempotencyKey = `deployed-mcp:hitl:${randomUUID()}`;
    const common = {
      owner_id: ownerId,
      idempotency_key: idempotencyKey,
      run_id: runId,
      interaction_id: interaction.interaction_id,
      revision: interaction.revision,
    };
    const toolName =
      action === 'respond'
        ? 'respond_to_interaction'
        : 'skip_interaction';
    const args =
      action === 'respond'
        ? {
            ...common,
            text:
              optional('TF_MCP_HITL_RESPONSE_TEXT') ||
              'Approved by the deployed AgentCore MCP acceptance test.',
          }
        : common;
    const response = await client.call(toolName, args);
    assert.equal(response?.status, 200);
    assert.equal(response?.value?.ok, true);
    assert.deepEqual(await client.call(toolName, args), response);

    const remaining = await client.call(
      'list_pending_interactions',
      {
        owner_id: ownerId,
        run_id: runId,
      },
    );
    assert.equal(
      remaining.some(
        (entry) =>
          entry.interaction_id === interaction.interaction_id &&
          entry.revision === interaction.revision,
      ),
      false,
    );
  },
);

test(
  'MCP starts, replays, reads, lists, and stops a run fixture',
  {
    skip: fixtureSkip(
      'TF_MCP_TEST_APPLICATION_ID',
      'TF_MCP_TEST_SOURCE_ARTIFACT_IDS',
    ),
    timeout: 90_000,
  },
  async () => {
    const token = optional('TF_TEST_USER_A_ACCESS_TOKEN');
    const ownerId = tokenSubject(token);
    const client = await connectedClient(token);
    const sourceArtifactIds = optional(
      'TF_MCP_TEST_SOURCE_ARTIFACT_IDS',
    )
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    assert.ok(
      sourceArtifactIds.length > 0,
      'TF_MCP_TEST_SOURCE_ARTIFACT_IDS must contain at least one artifact ID.',
    );
    const suffix = randomUUID();
    const startArguments = {
      owner_id: ownerId,
      idempotency_key: `deployed-mcp:start:${suffix}`,
      app_id: optional('TF_MCP_TEST_APPLICATION_ID'),
      source_artifact_ids: sourceArtifactIds,
    };
    let runId = null;
    let stopRequested = false;

    try {
      const started = await client.call('start_run', startArguments);
      assert.equal(started?.status, 202);
      runId = started?.value?.run_id;
      assert.equal(typeof runId, 'string');
      assert.notEqual(runId, '');
      assert.deepEqual(
        await client.call('start_run', startArguments),
        started,
      );

      const stopped = await client.call('stop_run', {
        owner_id: ownerId,
        idempotency_key: `deployed-mcp:stop:${suffix}`,
        run_id: runId,
      });
      assert.equal(stopped?.status, 200);
      assert.equal(stopped?.value?.status, 'stop_requested');
      stopRequested = true;

      const fetched = await client.call('get_run', {
        owner_id: ownerId,
        run_id: runId,
      });
      assert.equal(fetched?.state?.run_id, runId);
      const listed = await client.call('list_runs', {
        owner_id: ownerId,
      });
      assert.equal(
        listed.runs.some((entry) => entry.run_id === runId),
        true,
      );
      const pending = await client.call(
        'list_pending_interactions',
        {
          owner_id: ownerId,
          run_id: runId,
        },
      );
      assert.ok(Array.isArray(pending));
    } finally {
      if (runId !== null && !stopRequested) {
        await client
          .call('stop_run', {
            owner_id: ownerId,
            idempotency_key: `deployed-mcp:cleanup-stop:${suffix}`,
            run_id: runId,
          })
          .catch(() => {});
      }
    }
  },
);
