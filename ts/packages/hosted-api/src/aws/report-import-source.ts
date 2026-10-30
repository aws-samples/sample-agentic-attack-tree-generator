import { createHash } from 'node:crypto';
import {
  GetObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { HostedApiError } from '../errors.js';
import type {
  ReportImportSourceObject,
  ReportImportSourceReader,
} from '../report-import-worker.js';
import type { ReportImportSession } from '../report-import-service.js';
import { multipartCompositeChecksumSha256 } from './multipart.js';

export class S3ReportImportSourceReader
  implements ReportImportSourceReader
{
  readonly #client: S3Client;

  constructor(client: S3Client) {
    this.#client = client;
  }

  async get(
    session: ReportImportSession,
  ): Promise<ReportImportSourceObject> {
    const response = await this.#client.send(
      new GetObjectCommand({
        Bucket: session.bucket,
        Key: session.key,
        ChecksumMode: 'ENABLED',
      }),
    );
    if (
      response.Body === undefined ||
      typeof response.Body.transformToByteArray !== 'function'
    ) {
      throw new Error('Uploaded report body is not readable.');
    }
    const expectedStorageChecksum = multipartCompositeChecksumSha256(
      session.completedParts,
    );
    if (
      response.ChecksumType !== 'COMPOSITE' ||
      response.ChecksumSHA256 !== expectedStorageChecksum
    ) {
      throw new HostedApiError(
        422,
        'report_source_integrity_failed',
        'Uploaded report failed its S3 multipart checksum validation.',
      );
    }
    const body = await response.Body.transformToByteArray();
    return {
      body,
      sizeBytes: response.ContentLength ?? -1,
      checksumSha256: createHash('sha256').update(body).digest('hex'),
      serverSideEncryption: response.ServerSideEncryption ?? '',
      kmsKeyId: response.SSEKMSKeyId ?? '',
      bucketKeyEnabled: response.BucketKeyEnabled === true,
      metadata: response.Metadata ?? {},
    };
  }
}
