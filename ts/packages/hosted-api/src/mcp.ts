import type {
  ApplicationId,
  InteractionId,
  RunId,
  UserId,
} from '@threatforest/types';
import type { ApplicationService } from './application-service.js';
import type {
  CreateApplicationPayload,
  StartRunPayload,
  UpdateApplicationPayload,
} from './mcp-contracts.js';
import type { HitlService, RunService } from './run-service.js';

export interface HostedMcpServiceOptions {
  applications: ApplicationService;
  runs: RunService;
  hitl: HitlService;
}

export class HostedMcpServices {
  readonly #applications: ApplicationService;
  readonly #runs: RunService;
  readonly #hitl: HitlService;

  constructor(options: HostedMcpServiceOptions) {
    this.#applications = options.applications;
    this.#runs = options.runs;
    this.#hitl = options.hitl;
  }

  listApplications(ownerId: UserId) {
    return this.#applications.list(ownerId);
  }

  getApplication(ownerId: UserId, applicationId: ApplicationId) {
    return this.#applications.get(ownerId, applicationId);
  }

  createApplication(
    ownerId: UserId,
    idempotencyKey: string,
    input: CreateApplicationPayload,
  ) {
    return this.#applications.create({ ownerId, idempotencyKey }, input);
  }

  updateApplication(
    ownerId: UserId,
    idempotencyKey: string,
    applicationId: ApplicationId,
    input: UpdateApplicationPayload,
  ) {
    return this.#applications.update(
      { ownerId, idempotencyKey },
      applicationId,
      input,
    );
  }

  deleteApplication(
    ownerId: UserId,
    idempotencyKey: string,
    applicationId: ApplicationId,
  ) {
    return this.#applications.delete(
      { ownerId, idempotencyKey },
      applicationId,
    );
  }

  listRuns(ownerId: UserId, statuses?: Set<string>) {
    return this.#runs.list(ownerId, statuses);
  }

  getRun(ownerId: UserId, runId: RunId) {
    return this.#runs.get(ownerId, runId);
  }

  startRun(
    ownerId: UserId,
    idempotencyKey: string,
    input: StartRunPayload,
  ) {
    return this.#runs.create({ ownerId, idempotencyKey }, input);
  }

  pauseRun(ownerId: UserId, idempotencyKey: string, runId: RunId) {
    return this.#runs.control({ ownerId, idempotencyKey }, runId, 'pause');
  }

  stopRun(ownerId: UserId, idempotencyKey: string, runId: RunId) {
    return this.#runs.control({ ownerId, idempotencyKey }, runId, 'stop');
  }

  resumeRun(ownerId: UserId, idempotencyKey: string, runId: RunId) {
    return this.#runs.resume({ ownerId, idempotencyKey }, runId);
  }

  pendingInteractions(ownerId: UserId, runId: RunId) {
    return this.#hitl.pending(ownerId, runId);
  }

  respondToInteraction(
    ownerId: UserId,
    idempotencyKey: string,
    runId: RunId,
    interactionId: InteractionId,
    revision: number,
    text: string,
  ) {
    return this.#hitl.respond(
      { ownerId, idempotencyKey },
      runId,
      interactionId,
      revision,
      'submit',
      text,
    );
  }

  skipInteraction(
    ownerId: UserId,
    idempotencyKey: string,
    runId: RunId,
    interactionId: InteractionId,
    revision: number,
  ) {
    return this.#hitl.respond(
      { ownerId, idempotencyKey },
      runId,
      interactionId,
      revision,
      'skip',
      null,
    );
  }
}
