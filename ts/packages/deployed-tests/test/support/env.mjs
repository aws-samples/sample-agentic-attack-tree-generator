import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_ENV_FILE = resolve(PACKAGE_ROOT, '.env.deployed');

function loadEnvironmentFile(path) {
  if (!existsSync(path)) return;
  for (const rawLine of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) continue;
    const name = line.slice(0, separator);
    if (process.env[name] !== undefined) continue;
    let value = line.slice(separator + 1);
    if (
      (value.startsWith("'") && value.endsWith("'")) ||
      (value.startsWith('"') && value.endsWith('"'))
    ) {
      value = value.slice(1, -1);
    }
    process.env[name] = value;
  }
}

loadEnvironmentFile(process.env.TF_DEPLOYMENT_ENV_FILE || DEFAULT_ENV_FILE);

export const deployedEnabled = process.env.TF_RUN_DEPLOYED_TESTS === '1';
export const agentEnabled =
  deployedEnabled && process.env.TF_RUN_AGENT_HITL_TEST === '1';

export function optional(name) {
  return process.env[name]?.trim() || null;
}

export function required(name) {
  const value = optional(name);
  if (value === null) {
    throw new Error(`Required deployed-test environment variable is missing: ${name}`);
  }
  return value;
}

export function requiredWhenEnabled(name) {
  return deployedEnabled ? required(name) : '';
}

export function normalizedBaseUrl() {
  return required('TF_BASE_URL').replace(/\/+$/, '');
}

export function skipUnless(...names) {
  if (!deployedEnabled) return 'Set TF_RUN_DEPLOYED_TESTS=1 to run deployed probes.';
  const missing = names.filter((name) => optional(name) === null);
  return missing.length === 0
    ? false
    : `Missing deployed-test environment: ${missing.join(', ')}`;
}

export function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Access token is not a JWT.');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}
