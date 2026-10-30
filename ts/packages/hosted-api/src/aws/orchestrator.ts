import { SendMessageCommand, type SQSClient } from '@aws-sdk/client-sqs';
import type {
  ControlPlaneScope,
} from '@threatforest/control-plane';
import type { RunId } from '@threatforest/types';
import type {
  RunDispatch,
  RunOrchestrator,
} from '../contracts.js';

export class SqsRunOrchestrator implements RunOrchestrator {
  readonly #client: SQSClient;
  readonly #queueUrl: string;

  constructor(client: SQSClient, queueUrl: string) {
    this.#client = client;
    this.#queueUrl = queueUrl;
  }

  async dispatch(input: RunDispatch): Promise<void> {
    await this.#send({
      schema_version: 1,
      command: 'execute',
      owner_id: input.run.owner_id,
      application_id: input.run.application_id,
      run_id: input.run.run_id,
      resumed_from_run_id: input.resumedFromRunId,
      trace_id: input.run.trace_id,
    });
  }

  async continue(
    scope: ControlPlaneScope,
    runId: RunId,
    traceId: string,
  ): Promise<void> {
    await this.#send({
      schema_version: 1,
      command: 'execute',
      owner_id: scope.owner_id,
      application_id: scope.application_id,
      run_id: runId,
      resumed_from_run_id: null,
      trace_id: traceId,
    });
  }

  async requestControl(
    scope: ControlPlaneScope,
    runId: RunId,
    action: 'pause' | 'stop',
  ): Promise<void> {
    await this.#send({
      schema_version: 1,
      command: action,
      owner_id: scope.owner_id,
      application_id: scope.application_id,
      run_id: runId,
    });
  }

  async #send(body: Record<string, unknown>): Promise<void> {
    await this.#client.send(
      new SendMessageCommand({
        QueueUrl: this.#queueUrl,
        MessageBody: JSON.stringify(body),
      }),
    );
  }
}

export class StreamRunOrchestrator implements RunOrchestrator {
  async dispatch(_input: RunDispatch): Promise<void> {}

  async continue(
    _scope: ControlPlaneScope,
    _runId: RunId,
    _traceId: string,
  ): Promise<void> {}

  async requestControl(
    _scope: ControlPlaneScope,
    _runId: RunId,
    _action: 'pause' | 'stop',
  ): Promise<void> {}
}
