export interface DynamoStreamRecordIdentity {
  readonly dynamodb?: {
    readonly SequenceNumber?: string;
  };
}

export function dynamoStreamBatchItemIdentifier(
  record: DynamoStreamRecordIdentity,
): string {
  const sequenceNumber = record.dynamodb?.SequenceNumber;
  if (typeof sequenceNumber !== 'string' || sequenceNumber.length === 0) {
    throw new Error('DynamoDB stream sequence number is required');
  }
  return sequenceNumber;
}
