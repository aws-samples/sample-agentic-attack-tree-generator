import assert from 'node:assert/strict';
import test from 'node:test';

import { UserIdSchema } from '@threatforest/types';
import { SecretsManagerModelCredentialResolver } from '../src/model-credentials.js';

const ownerId = UserIdSchema.parse('usr_model_credentials');

test('Bedrock uses the runtime role without reading a user secret', async () => {
  let calls = 0;
  const resolver = new SecretsManagerModelCredentialResolver({
    secretPrefix: 'threatforest/test/users',
    client: {
      async send() {
        calls += 1;
        return {};
      },
    } as never,
  });

  assert.deepEqual(await resolver.resolve(ownerId, 'AWS Bedrock'), {});
  assert.equal(calls, 0);
});

test('external providers resolve only the selected user secret', async () => {
  const secretIds: string[] = [];
  const resolver = new SecretsManagerModelCredentialResolver({
    secretPrefix: '/threatforest/test/users/',
    client: {
      async send(command: { input: { SecretId?: string } }) {
        secretIds.push(command.input.SecretId ?? '');
        return { SecretString: '{"apiKey":"managed-openai-key"}' };
      },
    } as never,
  });

  const credentials = await resolver.resolve(ownerId, 'OpenAI');
  assert.deepEqual(credentials, { apiKey: 'managed-openai-key' });
  assert.deepEqual(secretIds, [
    `threatforest/test/users/${ownerId}/providers/openai`,
  ]);
  assert.equal(Object.isFrozen(credentials), true);
});

test('missing external credentials fail without exposing a secret identifier', async () => {
  const resolver = new SecretsManagerModelCredentialResolver({
    secretPrefix: 'threatforest/test/users',
    client: {
      async send() {
        const error = new Error('not found');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    } as never,
  });

  await assert.rejects(
    resolver.resolve(ownerId, 'Anthropic'),
    (error: unknown) => {
      assert.match(String((error as Error).message), /No managed Anthropic/);
      assert.doesNotMatch(
        String((error as Error).message),
        /usr_model_credentials/,
      );
      return true;
    },
  );
});
