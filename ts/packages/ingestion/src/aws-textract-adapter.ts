import { canonicalObjectKey } from './keys.js';
import {
  textractBlocksToOcrDocument,
  type OcrAdapter,
  type OcrDocument,
  type TextractBlock,
} from './extractors.js';
import type { WorkspaceObjectLocator } from './types.js';

interface SdkCommand {
  readonly input?: unknown;
}

interface SdkCommandConstructor {
  new (input: Record<string, unknown>): SdkCommand;
}

interface SdkClient {
  send(command: SdkCommand): Promise<Record<string, unknown>>;
}

interface TextractSdkModule {
  readonly TextractClient: new (configuration: Record<string, unknown>) => SdkClient;
  readonly DetectDocumentTextCommand: SdkCommandConstructor;
  readonly StartDocumentTextDetectionCommand: SdkCommandConstructor;
  readonly GetDocumentTextDetectionCommand: SdkCommandConstructor;
}

interface TextractCommands {
  readonly detect: SdkCommandConstructor;
  readonly start: SdkCommandConstructor;
  readonly get: SdkCommandConstructor;
}

export interface AwsTextractAdapterConfiguration {
  readonly bucket: string;
  readonly region?: string;
  readonly endpoint?: string;
  readonly pollIntervalMs?: number;
  readonly maximumWaitMs?: number;
  readonly clientConfiguration?: Readonly<Record<string, unknown>>;
}

export async function createAwsTextractOcrAdapter(
  configuration: AwsTextractAdapterConfiguration,
): Promise<OcrAdapter> {
  const packageName = '@aws-sdk/client-textract';
  const sdk = (await import(packageName)) as unknown as TextractSdkModule;
  const client = new sdk.TextractClient({
    ...configuration.clientConfiguration,
    ...(configuration.region === undefined ? {} : { region: configuration.region }),
    ...(configuration.endpoint === undefined ? {} : { endpoint: configuration.endpoint }),
  });
  return new AwsTextractOcrAdapter(configuration.bucket, client, {
    detect: sdk.DetectDocumentTextCommand,
    start: sdk.StartDocumentTextDetectionCommand,
    get: sdk.GetDocumentTextDetectionCommand,
  }, configuration);
}

export class AwsTextractOcrAdapter implements OcrAdapter {
  private readonly pollIntervalMs: number;
  private readonly maximumWaitMs: number;

  public constructor(
    private readonly bucket: string,
    private readonly client: SdkClient,
    private readonly commands: TextractCommands,
    configuration: Pick<AwsTextractAdapterConfiguration, 'pollIntervalMs' | 'maximumWaitMs'> = {},
    private readonly sleep: (milliseconds: number) => Promise<void> = defaultSleep,
  ) {
    this.pollIntervalMs = configuration.pollIntervalMs ?? 2_000;
    this.maximumWaitMs = configuration.maximumWaitMs ?? 10 * 60 * 1_000;
    if (bucket.trim().length === 0) {
      throw new Error('Textract source bucket is required');
    }
    if (this.pollIntervalMs < 1 || this.maximumWaitMs < this.pollIntervalMs) {
      throw new Error('Invalid Textract polling configuration');
    }
  }

  public async analyze(input: {
    readonly bytes: Uint8Array;
    readonly mediaType: string;
    readonly filename: string;
    readonly workspaceLocator?: WorkspaceObjectLocator;
  }): Promise<OcrDocument> {
    if (input.mediaType === 'application/pdf' || input.mediaType === 'image/tiff') {
      if (input.workspaceLocator === undefined) {
        throw new Error('Asynchronous Textract extraction requires a canonical workspace locator');
      }
      return this.analyzeAsynchronous(input.workspaceLocator);
    }
    const response = await this.client.send(
      new this.commands.detect({
        Document: { Bytes: Uint8Array.from(input.bytes) },
      }),
    );
    return textractBlocksToOcrDocument(asBlocks(response['Blocks']));
  }

  private async analyzeAsynchronous(locator: WorkspaceObjectLocator): Promise<OcrDocument> {
    const started = await this.client.send(
      new this.commands.start({
        DocumentLocation: {
          S3Object: {
            Bucket: this.bucket,
            Name: canonicalObjectKey(locator),
          },
        },
      }),
    );
    const jobId = asString(started['JobId']);
    if (jobId === undefined) {
      throw new Error('Textract did not return a job ID');
    }
    const deadline = Date.now() + this.maximumWaitMs;
    const blocks: TextractBlock[] = [];
    let nextToken: string | undefined;
    for (;;) {
      if (Date.now() >= deadline) {
        throw new Error(`Textract job ${jobId} timed out`);
      }
      const response = await this.client.send(
        new this.commands.get({
          JobId: jobId,
          ...(nextToken === undefined ? {} : { NextToken: nextToken }),
        }),
      );
      const status = asString(response['JobStatus']);
      if (status === 'IN_PROGRESS') {
        await this.sleep(this.pollIntervalMs);
        continue;
      }
      if (status === 'FAILED') {
        throw new Error(
          `Textract job failed: ${asString(response['StatusMessage']) ?? 'unknown reason'}`,
        );
      }
      if (status !== 'SUCCEEDED' && status !== 'PARTIAL_SUCCESS') {
        throw new Error(`Textract returned unexpected job status: ${status ?? 'missing'}`);
      }
      blocks.push(...asBlocks(response['Blocks']));
      nextToken = asString(response['NextToken']);
      if (nextToken === undefined) {
        break;
      }
    }
    return textractBlocksToOcrDocument(blocks);
  }
}

function asBlocks(value: unknown): TextractBlock[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is TextractBlock => item !== null && typeof item === 'object',
      )
    : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

async function defaultSleep(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}
