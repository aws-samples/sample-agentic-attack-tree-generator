import { createProductionIngestionWorker } from '../environment.js';
import type { IngestionJob, IngestionWorkerResult } from '../types.js';

export interface SqsRecord {
  readonly messageId: string;
  readonly body: string;
}

export interface SqsEvent {
  readonly Records: readonly SqsRecord[];
}

export interface SqsBatchResponse {
  readonly batchItemFailures: readonly { readonly itemIdentifier: string }[];
}

export interface IngestionJobProcessor {
  handle(job: IngestionJob): Promise<IngestionWorkerResult>;
}

export type IngestionProcessorProvider = () => Promise<IngestionJobProcessor>;

export function createSqsIngestionHandler(
  processorProvider: IngestionProcessorProvider,
): (event: SqsEvent) => Promise<SqsBatchResponse> {
  return async (event: SqsEvent): Promise<SqsBatchResponse> => {
    if (!Array.isArray(event.Records)) {
      throw new Error('SQS event Records must be an array');
    }
    const outcomes = await Promise.all(
      event.Records.map(async (record) => {
        try {
          const job = parseJob(record.body);
          const result = await (await processorProvider()).handle(job);
          console.info(
            JSON.stringify({
              event: 'threatforest.ingestion.completed',
              messageId: record.messageId,
              jobId: job.jobId,
              uploadId: job.uploadId,
              status: result.status,
              failureCode: result.failureCode,
            }),
          );
          return null;
        } catch (error) {
          console.error(
            JSON.stringify({
              event: 'threatforest.ingestion.record_failed',
              messageId: record.messageId,
              errorName: error instanceof Error ? error.name : 'UnknownError',
              errorMessage:
                error instanceof Error ? error.message.slice(0, 2_048) : 'Unknown queue error',
            }),
          );
          return { itemIdentifier: record.messageId };
        }
      }),
    );
    return {
      batchItemFailures: outcomes.filter(
        (outcome): outcome is { readonly itemIdentifier: string } => outcome !== null,
      ),
    };
  };
}

let productionProcessor: Promise<IngestionJobProcessor> | undefined;

function productionProcessorProvider(): Promise<IngestionJobProcessor> {
  productionProcessor ??= createProductionIngestionWorker();
  return productionProcessor;
}

/** Stable AWS Lambda entrypoint for an SQS event source with ReportBatchItemFailures. */
export const handler = createSqsIngestionHandler(productionProcessorProvider);

function parseJob(body: string): IngestionJob {
  let value: unknown;
  try {
    value = JSON.parse(body) as unknown;
  } catch {
    throw new Error('SQS record body is not valid JSON');
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('SQS record body must contain an ingestion job object');
  }
  return value as IngestionJob;
}
