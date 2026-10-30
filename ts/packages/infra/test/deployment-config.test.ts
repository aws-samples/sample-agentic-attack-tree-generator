import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { resolveDeployment } from '../src/deployment-config.mjs';

test('deployment defaults preserve resource names without choosing an AWS account', () => {
  assert.deepEqual(resolveDeployment({}), {
    account: '',
    region: 'eu-west-2',
    edgeRegion: 'us-east-1',
    environment: 'test',
    namePrefix: 'threatforest-test',
  });
  assert.throws(() => resolveDeployment({}, true), /12-digit AWS account/);
});

test('CDK and explicit targets support another account and environment', () => {
  assert.equal(resolveDeployment({ CDK_DEFAULT_ACCOUNT: '123456789012' }, true).account, '123456789012');
  assert.deepEqual(resolveDeployment({
    TF_ACCOUNT_ID: '210987654321',
    CDK_DEFAULT_ACCOUNT: '123456789012',
    TF_REGION: 'us-west-2',
    TF_ENVIRONMENT: 'prod',
  }, true), {
    account: '210987654321',
    region: 'us-west-2',
    edgeRegion: 'us-east-1',
    environment: 'prod',
    namePrefix: 'threatforest-prod',
  });
});

test('malformed targets and unsupported AWS partitions fail early', () => {
  for (const environment of [
    { TF_ACCOUNT_ID: 'not-an-account' },
    { TF_REGION: 'us-gov-west-1' },
    { TF_REGION: 'cn-north-1' },
    { TF_REGION: 'us-iso-east-1' },
    { TF_ENVIRONMENT: '../../prod' },
    { TF_ENVIRONMENT: 'PROD' },
    { TF_ENVIRONMENT: 'a'.repeat(17) },
  ]) {
    assert.throws(() => resolveDeployment(environment));
  }
});

const scriptDirectory = fileURLToPath(new URL('../../../scripts/deploy/', import.meta.url));
const commonScript = join(scriptDirectory, 'common.sh');

// Exercise the real shell helpers with a fake AWS CLI. No network or account
// credentials are used, including when a developer has AWS_PROFILE exported.
test('shell helpers discover accounts, support profiles/CI, and block mismatches', () => {
  const directory = mkdtempSync(join(tmpdir(), 'threatforest-deploy-test-'));
  const calls = join(directory, 'calls.jsonl');
  const fakeAws = join(directory, 'aws');
  writeFileSync(fakeAws, `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(process.env.TF_TEST_AWS_CALLS, JSON.stringify(process.argv.slice(2)) + '\\n');
const args = process.argv.slice(2);
if (args.includes('get-service-quota')) console.log(JSON.stringify({ Quota: { Value: Number(process.env.TF_TEST_QUOTA || 12) } }));
else if (args.includes('list-users')) console.log(process.env.TF_TEST_USERS || '{"Users":[]}');
else if (args.includes('admin-create-user')) console.log('{}');
else console.log('123456789012');
`, { mode: 0o755 });
  try {
    const environment = {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      AWS_PROFILE: '',
      CDK_DEFAULT_ACCOUNT: '',
      TF_ACCOUNT_ID: '',
      TF_REGION: 'us-west-2',
      TF_ENVIRONMENT: 'prod',
      TF_TEST_AWS_CALLS: calls,
      TF_SKIP_INSTALL: '0',
    };
    const command = 'source "$1"; validate_aws_identity; printf "%s|%s|%s" "$TF_ACCOUNT_ID" "$TF_REGION" "$TF_NAME_PREFIX"';
    const run = (overrides: Record<string, string> = {}) => spawnSync(
      'bash', ['-c', command, 'test', commonScript],
      { env: { ...environment, ...overrides }, encoding: 'utf8' },
    );
    const ci = run();
    assert.equal(ci.status, 0, ci.stderr);
    assert.equal(ci.stdout, '123456789012|us-west-2|threatforest-prod');
    let recorded = readFileSync(calls, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as string[]);
    assert.ok(!recorded[0]!.includes('--profile'));
    assert.ok(recorded[0]!.includes('us-west-2'));

    const named = run({ AWS_PROFILE: 'colleague-sso', TF_ACCOUNT_ID: '123456789012' });
    assert.equal(named.status, 0, named.stderr);
    recorded = readFileSync(calls, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as string[]);
    assert.ok(recorded[1]!.includes('colleague-sso'));

    const mismatch = run({ TF_ACCOUNT_ID: '210987654321' });
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /expected 210987654321/);
    assert.equal(mismatch.stdout, '');

    // A first bootstrap installs dependencies and targets both regions,
    // without needing a web build or Docker images.
    writeFileSync(join(directory, 'npm'), '#!/usr/bin/env bash\nexit 0\n', { mode: 0o755 });
    writeFileSync(join(directory, 'npx'), `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(process.env.TF_TEST_AWS_CALLS, JSON.stringify(process.argv.slice(2)) + '\\n');
`, { mode: 0o755 });
    execFileSync('bash', [join(scriptDirectory, 'bootstrap.sh')], {
      env: environment, stdio: 'pipe',
    });
    recorded = readFileSync(calls, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as string[]);
    const bootstraps = recorded.filter((args) => args.includes('bootstrap'));
    assert.equal(bootstraps.length, 2);
    assert.ok(bootstraps[0]!.includes('aws://123456789012/us-west-2'));
    assert.ok(bootstraps[1]!.includes('aws://123456789012/us-east-1'));
    assert.ok(bootstraps.every((args) => args.includes('Environment=prod') && !args.includes('--profile')));

    const preflight = (quota: string) => spawnSync(
      'bash', [join(scriptDirectory, 'preflight.sh')],
      { env: { ...environment, TF_SKIP_AWS_CHECK: '0', TF_SKIP_DOCKER_CHECK: '1', TF_TEST_QUOTA: quota }, encoding: 'utf8' },
    );
    assert.match(preflight('6').stderr, /quota.*must be at least 12/);
    const sufficientQuota = preflight('12');
    assert.equal(sufficientQuota.status, 0, sufficientQuota.stderr);

    const invite = (users: string) => execFileSync(
      'bash', [join(scriptDirectory, 'create-user.sh')],
      { env: { ...environment, TF_ADMIN_EMAIL: 'colleague@example.com', TF_TEST_USERS: users }, stdio: 'pipe' },
    );
    invite('{"Users":[]}');
    invite('{"Users":[{"Username":"colleague@example.com","Attributes":[]}]}');
    recorded = readFileSync(calls, 'utf8').trim().split('\n').map((line) => JSON.parse(line) as string[]);
    assert.equal(recorded.filter((args) => args.includes('admin-create-user')).length, 1);
    assert.equal(recorded.filter((args) => args.includes('admin-set-user-password')).length, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
