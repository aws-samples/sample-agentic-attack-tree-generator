import {
  SendMessageCommand,
  SQSClient,
} from '@aws-sdk/client-sqs';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  DispatchRelay,
  type DispatchDestination,
  type DispatchRelayChange,
} from '../dispatch-relay.js';
import { dynamoStreamBatchItemIdentifier } from '../aws/dynamodb-stream.js';

const region = process.env.AWS_REGION ?? 'eu-west-2';
const queueUrls: Record<DispatchDestination, string> = {
  'run-command': required('RUN_QUEUE_URL'),
  'report-import': required('REPORT_IMPORT_QUEUE_URL'),
  ingestion: required('INGESTION_QUEUE_URL'),
};
const sqs = new SQSClient({ region });
const relay = new DispatchRelay({
  async send(destination, payload) {
    const body = JSON.stringify(payload);
    if (Buffer.byteLength(body) > 256 * 1024) {
      throw new Error('Dispatch payload exceeds the SQS message limit');
    }
    await sqs.send(
      new SendMessageCommand({
        QueueUrl: queueUrls[destination],
        MessageBody: body,
      }),
    );
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

export async function handler(event: DynamoStreamEvent) {
  const batchItemFailures: Array<{ itemIdentifier: string }> = [];
  for (const record of event.Records) {
    const itemIdentifier = dynamoStreamBatchItemIdentifier(record);
    try {
      const change = streamChange(record);
      if (change !== null) await relay.process(change);
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'threatforest.dispatch_relay.failed',
          eventId: record.eventID,
          errorName: error instanceof Error ? error.name : 'UnknownError',
          errorMessage:
            error instanceof Error ? error.message : 'Unknown relay failure',
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
): DispatchRelayChange | null {
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
