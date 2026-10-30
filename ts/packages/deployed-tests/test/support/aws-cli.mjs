import { execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { optional, required } from './env.mjs';

export function awsJson(service, ...arguments_) {
  const profile = optional('TF_AWS_PROFILE') || optional('AWS_PROFILE');
  const region = required('TF_REGION');
  const output = execFileSync(
    'aws',
    [
      '--no-cli-pager',
      ...(profile ? ['--profile', profile] : []),
      '--region',
      region,
      service,
      ...arguments_,
      '--output',
      'json',
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return JSON.parse(output);
}

export function assertDeploymentAccount() {
  const expected = required('TF_ACCOUNT_ID');
  const identity = awsJson('sts', 'get-caller-identity');
  if (identity.Account !== expected) {
    throw new Error(`AWS CLI resolved account ${identity.Account}, expected ${expected}`);
  }
  return identity;
}

function logQueryRecord(row) {
  const fields = Object.fromEntries(
    row.map(({ field, value }) => [field, value]),
  );
  return {
    timestamp: Date.parse(fields['@timestamp'] || ''),
    logStreamName: fields['@logStream'] || '',
    message: fields['@message'] || '',
  };
}

export async function queryLogEvents(
  logGroupName,
  terms,
  {
    lookbackMs = 24 * 60 * 60_000,
    queryTimeoutMs = 30_000,
    limit = 50,
  } = {},
) {
  const termList = Array.isArray(terms) ? terms : [terms];
  if (termList.length === 0 || termList.some((term) => typeof term !== 'string')) {
    throw new Error('CloudWatch Logs Insights terms must be non-empty strings');
  }
  const filters = termList
    .map((term) => `strcontains(@message, ${JSON.stringify(term)})`)
    .join(' and ');
  const queryString = [
    'fields @timestamp, @logStream, @message',
    `| filter ${filters}`,
    '| sort @timestamp desc',
    `| limit ${limit}`,
  ].join(' ');
  const endTime = Math.ceil(Date.now() / 1000);
  const startTime = Math.floor((Date.now() - lookbackMs) / 1000);
  const { queryId } = awsJson(
    'logs',
    'start-query',
    '--log-group-name',
    logGroupName,
    '--start-time',
    String(startTime),
    '--end-time',
    String(endTime),
    '--query-string',
    queryString,
  );
  const deadline = Date.now() + queryTimeoutMs;
  do {
    const response = awsJson('logs', 'get-query-results', '--query-id', queryId);
    if (response.status === 'Complete') {
      return (response.results || []).map(logQueryRecord);
    }
    if (['Cancelled', 'Failed', 'Timeout', 'Unknown'].includes(response.status)) {
      throw new Error(
        `CloudWatch Logs Insights query ${queryId} ended with ${response.status}`,
      );
    }
    await delay(250);
  } while (Date.now() < deadline);
  throw new Error(`CloudWatch Logs Insights query ${queryId} did not complete`);
}

export async function waitForLogEvents(
  logGroupName,
  terms,
  {
    timeoutMs = 10 * 60_000,
    intervalMs = 15_000,
  } = {},
) {
  const deadline = Date.now() + timeoutMs;
  do {
    const events = await queryLogEvents(logGroupName, terms);
    if (events.length > 0) return events;
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await delay(Math.min(intervalMs, remaining));
  } while (Date.now() < deadline);
  return [];
}

export function requiredAwsEnvironment() {
  return {
    bucket: required('TF_ARTIFACT_BUCKET'),
    table: required('TF_STATE_TABLE'),
    artifactKeyArn: required('TF_ARTIFACT_KMS_KEY_ARN'),
    stateKeyArn: required('TF_STATE_KMS_KEY_ARN'),
  };
}
