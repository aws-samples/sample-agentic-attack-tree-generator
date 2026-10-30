import assert from 'node:assert/strict';
import test from 'node:test';
import { dynamoStreamBatchItemIdentifier } from '../src/aws/dynamodb-stream.js';

test('DynamoDB partial batch failures use stream sequence numbers', () => {
  assert.equal(
    dynamoStreamBatchItemIdentifier({
      dynamodb: { SequenceNumber: '1234567890' },
    }),
    '1234567890',
  );
  assert.throws(
    () => dynamoStreamBatchItemIdentifier({}),
    /sequence number is required/,
  );
});
