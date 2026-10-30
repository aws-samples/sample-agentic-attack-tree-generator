import assert from 'node:assert/strict';
import test from 'node:test';
import {
  readHostedMcpEnvironment,
  readHostedWebSocketEnvironment,
} from '../src/composition.js';

test('MCP environment requires DynamoDB state and normalization status', () => {
  assert.deepEqual(
    readHostedMcpEnvironment({
      AWS_REGION: 'eu-west-2',
      CONTROL_PLANE_TABLE_NAME: 'threatforest-state',
      INGESTION_QUEUE_URL:
        'https://sqs.eu-west-2.amazonaws.com/123456789012/ingestion',
    }),
    {
      region: 'eu-west-2',
      controlPlaneTableName: 'threatforest-state',
      ingestionQueueUrl:
        'https://sqs.eu-west-2.amazonaws.com/123456789012/ingestion',
    },
  );
  assert.throws(
    () => readHostedMcpEnvironment({ AWS_REGION: 'eu-west-2' }),
    /CONTROL_PLANE_TABLE_NAME environment variable is required/,
  );
  assert.throws(
    () =>
      readHostedMcpEnvironment({
        AWS_REGION: 'eu-west-2',
        CONTROL_PLANE_TABLE_NAME: 'threatforest-state',
      }),
    /INGESTION_QUEUE_URL environment variable is required/,
  );
});

test('WebSocket environment excludes HTTP, S3, Bedrock, and queue settings', () => {
  const parsed = readHostedWebSocketEnvironment({
    AWS_REGION: 'eu-west-2',
    CONTROL_PLANE_TABLE_NAME: 'threatforest-state',
    ORIGIN_SECRET_ARN: 'arn:aws:secretsmanager:origin',
    REPLAY_TICKET_SECRET_ARN: 'arn:aws:secretsmanager:replay',
    WEBSOCKET_MANAGEMENT_ENDPOINT:
      'https://socket.execute-api.eu-west-2.amazonaws.com/prod',
    COGNITO_ISSUER: 'https://cognito-idp.eu-west-2.amazonaws.com/pool',
    COGNITO_AUDIENCE: 'client-id',
    ALLOW_UNTICKETED_WEBSOCKET: 'false',
  });
  assert.deepEqual(parsed, {
    region: 'eu-west-2',
    controlPlaneTableName: 'threatforest-state',
    originSecretArn: 'arn:aws:secretsmanager:origin',
    replayTicketSecretArn: 'arn:aws:secretsmanager:replay',
    webSocketManagementEndpoint:
      'https://socket.execute-api.eu-west-2.amazonaws.com/prod',
    cognitoIssuer:
      'https://cognito-idp.eu-west-2.amazonaws.com/pool',
    cognitoAudience: 'client-id',
    allowUnticketedWebSocket: false,
  });
  assert.deepEqual(Object.keys(parsed).sort(), [
    'allowUnticketedWebSocket',
    'cognitoAudience',
    'cognitoIssuer',
    'controlPlaneTableName',
    'originSecretArn',
    'region',
    'replayTicketSecretArn',
    'webSocketManagementEndpoint',
  ]);
  assert.throws(
    () =>
      readHostedWebSocketEnvironment({
        CONTROL_PLANE_TABLE_NAME: 'threatforest-state',
        ORIGIN_SECRET_ARN: 'arn:aws:secretsmanager:origin',
        WEBSOCKET_MANAGEMENT_ENDPOINT:
          'https://socket.execute-api.eu-west-2.amazonaws.com/prod',
      }),
    /REPLAY_TICKET_SECRET_ARN environment variable is required/,
  );
});
