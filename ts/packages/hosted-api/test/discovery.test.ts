import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BedrockClient,
  ListFoundationModelsCommand,
  ListInferenceProfilesCommand,
} from '@aws-sdk/client-bedrock';
import { BedrockDiscoveryService } from '../src/aws/discovery.js';

function clientFor(region: string, calls: string[]): BedrockClient {
  return {
    async send(command: unknown) {
      calls.push(region);
      if (command instanceof ListFoundationModelsCommand) {
        return {
          modelSummaries: [
            {
              modelId: `anthropic.model-in-${region}`,
              modelName: `Model in ${region}`,
              providerName: 'Anthropic',
              outputModalities: ['TEXT'],
              inferenceTypesSupported: ['ON_DEMAND'],
              modelLifecycle: { status: 'ACTIVE' },
            },
          ],
        };
      }
      assert.ok(command instanceof ListInferenceProfilesCommand);
      return { inferenceProfileSummaries: [] };
    },
  } as unknown as BedrockClient;
}

test('Bedrock discovery uses the user-selected region instead of the deployment client', async () => {
  const calls: string[] = [];
  const service = new BedrockDiscoveryService(
    clientFor('eu-west-2', calls),
    'eu-west-2',
    (region) => clientFor(region, calls),
  );

  const result = await service.models('us-west-2');
  assert.equal(result.source, 'live');
  assert.equal(result.region, 'us-west-2');
  assert.deepEqual(
    result.models.map((entry) => entry.id),
    ['anthropic.model-in-us-west-2'],
  );
  assert.deepEqual(calls, ['us-west-2', 'us-west-2']);
});
