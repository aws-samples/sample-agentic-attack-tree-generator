import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CreateSecretCommand,
  DescribeSecretCommand,
  PutSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { UserIdSchema } from '@threatforest/types';
import { SecretsManagerProviderCredentialStore } from '../src/aws/provider-credentials.js';

const ownerId = UserIdSchema.parse('usr_provider_settings');
const secretId =
  'threatforest/test/users/usr_provider_settings/providers/openai';

test('provider credentials are created under the selected user with the configured KMS key', async () => {
  const commands: unknown[] = [];
  const store = new SecretsManagerProviderCredentialStore({
    secretPrefix: '/threatforest/test/users/',
    kmsKeyId: 'arn:aws:kms:eu-west-2:123456789012:key/provider-key',
    client: {
      async send(command: unknown) {
        commands.push(command);
        if (command instanceof PutSecretValueCommand) {
          const error = new Error('missing');
          error.name = 'ResourceNotFoundException';
          throw error;
        }
        return {};
      },
    } as never,
  });

  await store.put(ownerId, 'OpenAI', 'secret-api-key');

  assert.equal(commands.length, 2);
  assert.ok(commands[0] instanceof PutSecretValueCommand);
  assert.equal(commands[0].input.SecretId, secretId);
  assert.ok(commands[1] instanceof CreateSecretCommand);
  assert.equal(commands[1].input.Name, secretId);
  assert.equal(
    commands[1].input.KmsKeyId,
    'arn:aws:kms:eu-west-2:123456789012:key/provider-key',
  );
  assert.deepEqual(JSON.parse(commands[1].input.SecretString ?? ''), {
    apiKey: 'secret-api-key',
  });
});

test('provider credential replacement never returns or logs the stored value', async () => {
  const commands: unknown[] = [];
  const store = new SecretsManagerProviderCredentialStore({
    secretPrefix: 'threatforest/test/users',
    kmsKeyId: 'provider-key',
    client: {
      async send(command: unknown) {
        commands.push(command);
        return {};
      },
    } as never,
  });

  await store.put(ownerId, 'Anthropic', 'replacement-key');
  assert.equal(commands.length, 1);
  assert.ok(commands[0] instanceof PutSecretValueCommand);
  assert.equal(
    commands[0].input.SecretId,
    'threatforest/test/users/usr_provider_settings/providers/anthropic',
  );
});

test('configured checks are scoped by user and tolerate only missing secrets', async () => {
  const requested: string[] = [];
  const store = new SecretsManagerProviderCredentialStore({
    secretPrefix: 'threatforest/test/users',
    kmsKeyId: 'provider-key',
    client: {
      async send(command: unknown) {
        assert.ok(command instanceof DescribeSecretCommand);
        requested.push(command.input.SecretId ?? '');
        if (requested.length === 1) {
          const error = new Error('missing');
          error.name = 'ResourceNotFoundException';
          throw error;
        }
        return {};
      },
    } as never,
  });

  assert.equal(await store.configured(ownerId, 'Google Gemini'), false);
  assert.equal(await store.configured(ownerId, 'Google Gemini'), true);
  assert.deepEqual(requested, [
    'threatforest/test/users/usr_provider_settings/providers/gemini',
    'threatforest/test/users/usr_provider_settings/providers/gemini',
  ]);
  assert.equal(await store.configured(ownerId, 'AWS Bedrock'), false);
});
