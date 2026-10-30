import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  HeadObjectCommand,
  ListPartsCommand,
  UploadPartCommand,
  type CompletedPart as S3CompletedPart,
  type S3Client,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createHash } from 'node:crypto';
import type {
  CompletedPart,
  CompletedMultipartObject,
  MultipartInitiateRequest,
  MultipartInspection,
  MultipartPartRequest,
  MultipartPartSignature,
  MultipartStorageAdapter,
} from '../contracts.js';

function toS3Checksum(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64');
}

function fromS3PartChecksum(base64: string | undefined): string {
  if (base64 === undefined) {
    throw new Error('S3 did not return the required SHA-256 part checksum');
  }
  return Buffer.from(base64, 'base64').toString('hex');
}

function orderedParts(parts: readonly CompletedPart[]): CompletedPart[] {
  const ordered = [...parts].sort(
    (left, right) => left.partNumber - right.partNumber,
  );
  if (
    ordered.length === 0 ||
    ordered.some((part, index) => part.partNumber !== index + 1)
  ) {
    throw new Error(
      'Multipart SHA-256 requires a non-empty consecutive part sequence',
    );
  }
  return ordered;
}

function multipartCompositeChecksumBase64(
  parts: readonly CompletedPart[],
): string {
  // S3 hashes the ordered binary part digests, not the concatenated object bytes.
  const checksumBytes = orderedParts(parts).map((part) =>
    Buffer.from(part.checksumSha256, 'hex'),
  );
  return createHash('sha256')
    .update(Buffer.concat(checksumBytes))
    .digest('base64');
}

export function multipartCompositeChecksumSha256(
  parts: readonly CompletedPart[],
): string {
  return `${multipartCompositeChecksumBase64(parts)}-${parts.length}`;
}

export class S3MultipartStorageAdapter implements MultipartStorageAdapter {
  readonly #client: S3Client;

  constructor(client: S3Client) {
    this.#client = client;
  }

  async initiate(
    request: MultipartInitiateRequest,
  ): Promise<{ storageUploadId: string }> {
    const response = await this.#client.send(
      new CreateMultipartUploadCommand({
        Bucket: request.bucket,
        Key: request.key,
        ContentType: request.contentType,
        ChecksumAlgorithm: 'SHA256',
        ChecksumType: 'COMPOSITE',
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: request.kmsKeyId,
        Metadata: request.metadata,
      }),
    );
    if (!response.UploadId) {
      throw new Error('S3 did not return a multipart upload ID');
    }
    return { storageUploadId: response.UploadId };
  }

  async presignPart(request: MultipartPartRequest): Promise<MultipartPartSignature> {
    const checksum = toS3Checksum(request.partChecksumSha256);
    const command = new UploadPartCommand({
      Bucket: request.bucket,
      Key: request.key,
      UploadId: request.storageUploadId,
      PartNumber: request.partNumber,
      ContentLength: request.partSizeBytes,
      ChecksumSHA256: checksum,
    });
    const url = await getSignedUrl(this.#client, command, {
      expiresIn: request.expiresInSeconds,
      unhoistableHeaders: new Set(['x-amz-checksum-sha256']),
    });
    return {
      url,
      expiresAt: new Date(
        Date.now() + request.expiresInSeconds * 1000,
      ).toISOString(),
      headers: {
        'content-length': String(request.partSizeBytes),
        'x-amz-checksum-sha256': checksum,
      },
    };
  }

  async inspect(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<MultipartInspection> {
    const parts: CompletedPart[] = [];
    let marker: string | undefined;
    do {
      const response = await this.#client.send(
        new ListPartsCommand({
          Bucket: request.bucket,
          Key: request.key,
          UploadId: request.storageUploadId,
          PartNumberMarker: marker,
        }),
      );
      for (const part of response.Parts ?? []) {
        if (
          part.PartNumber === undefined ||
          part.Size === undefined ||
          part.ETag === undefined
        ) {
          throw new Error('S3 returned an incomplete multipart part record');
        }
        parts.push({
          partNumber: part.PartNumber,
          sizeBytes: part.Size,
          etag: part.ETag,
          checksumSha256: fromS3PartChecksum(part.ChecksumSHA256),
        });
      }
      marker = response.IsTruncated
        ? response.NextPartNumberMarker
        : undefined;
    } while (marker !== undefined);
    return {
      ...request,
      parts: parts.sort((left, right) => left.partNumber - right.partNumber),
    };
  }

  async complete(
    request: MultipartInitiateRequest & {
      storageUploadId: string;
      parts: CompletedPart[];
    },
  ): Promise<{ versionId: string | null }> {
    const ordered = orderedParts(request.parts);
    const parts: S3CompletedPart[] = ordered.map((part) => ({
      PartNumber: part.partNumber,
      ETag: part.etag,
      ChecksumSHA256: toS3Checksum(part.checksumSha256),
    }));
    const compositeChecksum =
      multipartCompositeChecksumBase64(ordered);
    const storedCompositeChecksum =
      multipartCompositeChecksumSha256(ordered);
    try {
      const response = await this.#client.send(
        new CompleteMultipartUploadCommand({
          Bucket: request.bucket,
          Key: request.key,
          UploadId: request.storageUploadId,
          ChecksumSHA256: compositeChecksum,
          ChecksumType: 'COMPOSITE',
          MpuObjectSize: request.sizeBytes,
          MultipartUpload: { Parts: parts },
        }),
      );
      if (
        response.ChecksumType !== 'COMPOSITE' ||
        response.ChecksumSHA256 !== storedCompositeChecksum
      ) {
        throw new Error(
          `S3 completed multipart object ${request.key} with an unexpected composite checksum`,
        );
      }
      return { versionId: response.VersionId ?? null };
    } catch (error) {
      if (error instanceof Error && error.name === 'NoSuchUpload') {
        const completed = await this.inspectCompleted(request);
        if (completed !== null) {
          return completed;
        }
      }
      throw error;
    }
  }

  async inspectCompleted(
    request: MultipartInitiateRequest & { parts: CompletedPart[] },
  ): Promise<CompletedMultipartObject | null> {
    try {
      const response = await this.#client.send(
        new HeadObjectCommand({
          Bucket: request.bucket,
          Key: request.key,
          ChecksumMode: 'ENABLED',
        }),
      );
      const metadata = response.Metadata ?? {};
      const metadataMatches = Object.entries(request.metadata).every(
        ([name, value]) => metadata[name.toLowerCase()] === value,
      );
      if (
        response.ContentLength !== request.sizeBytes ||
        response.ContentType !== request.contentType ||
        response.ServerSideEncryption !== 'aws:kms' ||
        response.SSEKMSKeyId !== request.kmsKeyId ||
        response.ChecksumType !== 'COMPOSITE' ||
        response.ChecksumSHA256 !==
          multipartCompositeChecksumSha256(request.parts) ||
        !metadataMatches
      ) {
        throw new Error(
          `Completed multipart object ${request.key} does not match its durable constraints`,
        );
      }
      return { versionId: response.VersionId ?? null };
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === 'NotFound' ||
          error.name === 'NoSuchKey' ||
          (isRecord(error) &&
            isRecord(error['$metadata']) &&
            error['$metadata']['httpStatusCode'] === 404))
      ) {
        return null;
      }
      throw error;
    }
  }

  async abort(
    request: MultipartInitiateRequest & { storageUploadId: string },
  ): Promise<void> {
    await this.#client.send(
      new AbortMultipartUploadCommand({
        Bucket: request.bucket,
        Key: request.key,
        UploadId: request.storageUploadId,
      }),
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
