import assert from 'node:assert/strict';
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';

import { buildGraph, type RunGraphOptions } from '../pipeline/graph.js';
import { LocalFilesystemWorkspace } from '../workspace.js';
import { verifyThreatOutput } from '../verifiers.js';
import { buildThreatRevisionPrompt } from './hitl.js';
import {
  buildThreatAgentContext,
  buildThreatInvocationPrompt,
  buildThreatSystemPrompt,
  normalizeAuthoritativeThreats,
  resolveAuthoritativeThreatInputPaths,
} from './threat.js';

function temporaryFixture(t: TestContext): { parent: string; repo: string; runDir: string } {
  const parent = mkdtempSync(join(tmpdir(), 'threatforest-authoritative-'));
  const repo = join(parent, 'repo');
  const runDir = join(parent, 'run');
  mkdirSync(repo);
  mkdirSync(runDir);
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  return { parent, repo, runDir };
}

test('resolves relative and absolute authoritative files once inside the workspace', (t) => {
  const { repo } = temporaryFixture(t);
  const nested = join(repo, 'normalized');
  const threatFile = join(nested, 'threats.md');
  mkdirSync(nested);
  writeFileSync(threatFile, '- Credential theft through the admin API\n');

  const resolved = resolveAuthoritativeThreatInputPaths(repo, [
    'normalized/threats.md',
    threatFile,
  ]);

  assert.deepEqual(resolved, [realpathSync(threatFile)]);
});

test('rejects traversal, symlink escapes, missing paths, and directories', (t) => {
  const { parent, repo } = temporaryFixture(t);
  const outside = join(parent, 'outside.md');
  writeFileSync(outside, 'outside');

  assert.throws(
    () => resolveAuthoritativeThreatInputPaths(repo, ['../outside.md']),
    /outside the repository\/materialized workspace/,
  );

  const symlink = join(repo, 'escaped.md');
  symlinkSync(outside, symlink);
  assert.throws(
    () => resolveAuthoritativeThreatInputPaths(repo, [symlink]),
    /outside the repository\/materialized workspace/,
  );

  assert.throws(
    () => resolveAuthoritativeThreatInputPaths(repo, ['missing.md']),
    /does not exist/,
  );
  assert.throws(
    () => resolveAuthoritativeThreatInputPaths(repo, ['.']),
    /not a regular file/,
  );
});

test('RunGraphOptions propagates authoritative paths to fail-fast graph validation', async (t) => {
  const { parent, repo } = temporaryFixture(t);
  const outside = join(parent, 'outside.md');
  writeFileSync(outside, 'outside');

  const options: RunGraphOptions = { authoritativeThreatInputPaths: [outside] };
  await assert.rejects(
    buildGraph(repo, options),
    /outside the repository\/materialized workspace/,
  );
});

test('authoritative context exposes exact source files only through the threat read scope', (t) => {
  const { repo, runDir } = temporaryFixture(t);
  const source = join(repo, 'normalized-threats.md');
  writeFileSync(source, '- A supplied threat\n');

  const context = buildThreatAgentContext(repo, runDir, {
    authoritativeThreatInputPaths: [source],
  });

  assert.deepEqual(context.authoritativeThreatInputPaths, [realpathSync(source)]);
  assert.deepEqual(context.readPaths, [
    join(runDir, 'state', 'scanner_context.json'),
    realpathSync(source),
  ]);
  assert.ok(!context.readPaths.includes(realpathSync(repo)));
  assert.match(context.systemPrompt, /complete, authoritative set of threats/);
  assert.match(context.systemPrompt, /normalized-threats\.md/);

  const revisionContext = buildThreatAgentContext(repo, runDir, {
    authoritativeThreatInputPaths: [source],
    includeExistingThreatState: true,
  });
  assert.ok(revisionContext.readPaths.includes(join(runDir, 'state', 'threats.json')));
  assert.match(revisionContext.systemPrompt, /current state file is the authoritative working set/);
  assert.match(
    revisionContext.systemPrompt,
    /do not[\s\S]*restore an item removed during review/i,
  );
});

test('generated mode retains the existing repository-wide behavior', (t) => {
  const { repo, runDir } = temporaryFixture(t);
  const context = buildThreatAgentContext(repo, runDir);

  assert.deepEqual(context.authoritativeThreatInputPaths, []);
  assert.deepEqual(context.readPaths, [join(runDir, 'state', 'scanner_context.json'), repo]);
  assert.match(context.systemPrompt, /There is no target threat count/);
  assert.equal(
    buildThreatInvocationPrompt(),
    'Read the scanner context and generate threats. Write them to the state file.',
  );
});

test('authoritative prompts require extraction only for initial, retry, and review calls', () => {
  const paths = ['/workspace/evidence/threats-a.md', '/workspace/evidence/threats-b.json'];
  const systemPrompt = buildThreatSystemPrompt(
    '/run/state/scanner_context.json',
    '/run/state/threats.json',
    paths,
  );
  const invocationPrompt = buildThreatInvocationPrompt(paths);
  const revisionPrompt = buildThreatRevisionPrompt('Add the token replay threat.', true);

  for (const path of paths) assert.match(systemPrompt, new RegExp(path.replaceAll('/', '\\/')));
  assert.doesNotMatch(systemPrompt, /Generate 8-12 threat statements/);
  assert.match(systemPrompt, /Do NOT invent, infer, discover, split, or add threats/);
  assert.match(invocationPrompt, /every explicitly supplied threat/);
  assert.match(invocationPrompt, /Do not generate, infer, or add/);
  assert.match(revisionPrompt, /Add a threat only when the user explicitly describes/);
  assert.match(revisionPrompt, /Add the token replay threat\./);
});

test('normalization preserves order and content while assigning provenance and unique IDs', () => {
  const normalized = normalizeAuthoritativeThreats([
    {
      id: 'CUSTOM-7',
      title: 'First',
      description: 'First supplied statement',
      priority: 'high',
      affected_components: ['API', 'API'],
    },
    {
      id: 'CUSTOM-7',
      title: 'Second',
      description: 'Second supplied statement',
      priority: 'medium',
      affected_components: ['Worker'],
    },
    {
      title: 'Third',
      description: 'Third supplied statement',
      priority: 'low',
      affected_components: ['Database'],
    },
  ]);

  assert.deepEqual(
    normalized.map((threat) => threat.id),
    ['TS001', 'TS002', 'TS003'],
  );
  assert.equal(normalized[0]!.source_id, 'CUSTOM-7');
  assert.deepEqual(
    normalized.map((threat) => threat.title),
    ['First', 'Second', 'Third'],
  );
  assert.ok(normalized.every((threat) => threat.threat_source === 'user_provided'));
  assert.deepEqual(normalized[0]!.affected_components, ['API']);
});

test('authoritative verification accepts a supplied set of one and enforces provenance', (t) => {
  const { runDir } = temporaryFixture(t);
  const workspace = new LocalFilesystemWorkspace(runDir);
  const threat = {
    id: 'TS001',
    title: 'Supplied threat',
    description: 'A threat explicitly supplied by the user.',
    priority: 'medium',
    threat_source: 'user_provided',
    affected_components: ['application'],
  };
  workspace.writeJson('threats.json', { threats: [threat] });

  assert.deepEqual(verifyThreatOutput(workspace, { authoritative: true }), [
    true,
    'Authoritative threats are valid',
  ]);
  assert.deepEqual(verifyThreatOutput(workspace), [
    true,
    'Threats are valid',
  ]);

  workspace.writeJson('threats.json', {
    threats: [{ ...threat, threat_source: 'generated' }],
  });
  assert.deepEqual(verifyThreatOutput(workspace, { authoritative: true }), [
    false,
    "Threat 'TS001' is not marked as user_provided authoritative input",
  ]);
});
