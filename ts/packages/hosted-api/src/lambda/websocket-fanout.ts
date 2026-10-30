import {
  ApiGatewayManagementApiClient,
} from '@aws-sdk/client-apigatewaymanagementapi';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { S3Client } from '@aws-sdk/client-s3';
import {
  DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { DynamoControlPlane } from '@threatforest/control-plane';
import {
  DynamoConnectionAdapter,
  DynamoHostedState,
} from '../aws/state.js';
import { dynamoStreamBatchItemIdentifier } from '../aws/dynamodb-stream.js';
import {
  WebSocketFanout,
  type WebSocketFanoutChange,
} from '../websocket-fanout.js';

const region = process.env.AWS_REGION ?? 'eu-west-2';
const tableName = required('CONTROL_PLANE_TABLE_NAME');
const managementEndpoint = required('WEBSOCKET_MANAGEMENT_ENDPOINT');
const documentClient = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region }),
  { marshallOptions: { removeUndefinedValues: true } },
);
const connections = new DynamoConnectionAdapter(
  new DynamoHostedState({
    tableName,
    documentClient,
    s3: new S3Client({ region }),
    artifactsBucket: process.env.ARTIFACTS_BUCKET_NAME ?? 'unused',
    webSocketManagementClient: new ApiGatewayManagementApiClient({
      region,
      endpoint: managementEndpoint,
    }),
  }),
);
const controlPlane = new DynamoControlPlane({
  tableName,
  client: documentClient,
});
const fanout = new WebSocketFanout({
  connections,
  events: {
    list: (scope, runId, afterSequence) =>
      controlPlane.listEvents(scope, runId, afterSequence),
  },
});

interface DynamoStreamEvent {
  Records: Array<{
    eventID: string;
    eventName?: string;
    dynamodb?: {
      NewImage?: Record<string, unknown>;
      OldImage?: Record<string, unknown>;
      SequenceNumber?: string;
    };
  }>;
}

interface DynamoStreamBatchResponse {
  batchItemFailures: Array<{ itemIdentifier: string }>;
}

export async function handler(
  event: DynamoStreamEvent,
): Promise<DynamoStreamBatchResponse> {
  const batchItemFailures: Array<{ itemIdentifier: string }> = [];
  for (const record of event.Records) {
    const itemIdentifier = dynamoStreamBatchItemIdentifier(record);
    try {
      const change = streamChange(record);
      if (change !== null) {
        await fanout.process(change);
      }
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'threatforest.websocket_fanout.failed',
          eventId: record.eventID,
          errorName: error instanceof Error ? error.name : 'UnknownError',
          errorMessage:
            error instanceof Error ? error.message : 'Unknown fanout failure',
        }),
      );
      batchItemFailures.push({ itemIdentifier });
      break;
    }
  }
  return { batchItemFailures };
}

function streamChange(
  record: DynamoStreamEvent['Records'][number],
): WebSocketFanoutChange | null {
  if (
    record.eventName !== 'INSERT' &&
    record.eventName !== 'MODIFY' &&
    record.eventName !== 'REMOVE'
  ) {
    return null;
  }
  return {
    eventName: record.eventName,
    ...(record.dynamodb?.NewImage === undefined
      ? {}
      : {
          newItem: unmarshall(
            record.dynamodb.NewImage as Parameters<typeof unmarshall>[0],
          ),
        }),
    ...(record.dynamodb?.OldImage === undefined
      ? {}
      : {
          oldItem: unmarshall(
            record.dynamodb.OldImage as Parameters<typeof unmarshall>[0],
          ),
        }),
  };
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}
