import {
  createRunEngineConfig,
  runGraph,
  withExecutionObservability,
  type InteractionResponse,
  type RunGraphOptions,
  type SimpleInterrupt,
} from '@threatforest/engine';
import type { ArtifactRef } from '@threatforest/types';
import type {
  AwaitingInputStageResult,
  StageExecutionContext,
  StageExecutionResult,
  StageExecutor,
  StageOutputPublisher,
} from './contracts.js';
import type { ApprovedFeedbackMemory } from './memory.js';
import type { ModelCredentialResolver } from './model-credentials.js';

const SAFE_MODEL_PARAMETER_KEYS = new Set([
  'temperature',
  'max_tokens',
  'maxTokens',
  'top_p',
  'topP',
  'context_window_limit',
  'contextWindowLimit',
]);

export interface MaterializedWorkspace {
  repoPath: string;
  runDir?: string;
  authoritativeThreatInputPaths?: readonly string[];
}

export interface RecoveredWorkspace {
  workspace: MaterializedWorkspace;
  checkpointArtifact: ArtifactRef;
}

export interface WorkspaceResolver {
  resolve(context: StageExecutionContext): Promise<MaterializedWorkspace>;
  checkpoint?(
    context: StageExecutionContext,
    workspace: MaterializedWorkspace,
    boundary: 'completed' | 'awaiting_input',
  ): Promise<ArtifactRef>;
  recover?(
    context: StageExecutionContext,
    checkpoint: StageExecutionContext['checkpoint'],
  ): Promise<RecoveredWorkspace | null>;
}

export interface EngineGraphStageExecutorOptions {
  workspaceResolver: WorkspaceResolver;
  graphRunner?: typeof runGraph;
  outputPublisher?: StageOutputPublisher;
  memory?: ApprovedFeedbackMemory;
  modelCredentials?: ModelCredentialResolver;
  logger?: Pick<Console, 'error'>;
}

class HitlBoundarySignal extends Error {
  readonly interrupts: readonly SimpleInterrupt[];
  readonly marker = 'threatforest-durable-hitl-boundary';

  constructor(interrupts: readonly SimpleInterrupt[]) {
    super('durable HITL boundary reached');
    this.name = 'HitlBoundarySignal';
    this.interrupts = interrupts;
  }
}

function findBoundary(error: unknown): HitlBoundarySignal | null {
  let current = error;
  for (let depth = 0; depth < 8 && current !== null && typeof current === 'object'; depth += 1) {
    if (
      current instanceof HitlBoundarySignal ||
      (current as { marker?: unknown }).marker === 'threatforest-durable-hitl-boundary'
    ) {
      return current as HitlBoundarySignal;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return null;
}

function awaiting(interrupts: readonly SimpleInterrupt[]): AwaitingInputStageResult {
  const first = interrupts[0];
  return {
    status: 'awaiting_input',
    reason: first?.reason ?? { message: 'Human input required' },
    transcript: {
      schema_version: 1,
      interrupts: interrupts.map((interrupt) => ({
        id: interrupt.id,
        reason: interrupt.reason,
      })),
    },
  };
}

function safeModelParameters(
  parameters: Readonly<Record<string, string | number | boolean>>,
): Record<string, string | number | boolean> {
  for (const key of Object.keys(parameters)) {
    if (!SAFE_MODEL_PARAMETER_KEYS.has(key)) {
      throw new Error(`Unsupported hosted model parameter ${JSON.stringify(key)}`);
    }
  }
  return { ...parameters };
}

/**
 * Compatibility bridge for the current engine graph. It runs only the target
 * node by replacing already-completed nodes with the engine's skip nodes and
 * interrupting at the target boundary.
 */
export class EngineGraphStageExecutor implements StageExecutor {
  readonly #workspaceResolver: WorkspaceResolver;
  readonly #graphRunner: typeof runGraph;
  readonly #outputPublisher: StageOutputPublisher | null;
  readonly #memory: ApprovedFeedbackMemory | null;
  readonly #modelCredentials: ModelCredentialResolver | null;
  readonly #logger: Pick<Console, 'error'>;

  constructor(options: EngineGraphStageExecutorOptions) {
    this.#workspaceResolver = options.workspaceResolver;
    this.#graphRunner = options.graphRunner ?? runGraph;
    this.#outputPublisher = options.outputPublisher ?? null;
    this.#memory = options.memory ?? null;
    this.#modelCredentials = options.modelCredentials ?? null;
    this.#logger = options.logger ?? console;
  }

  async execute(context: StageExecutionContext): Promise<StageExecutionResult> {
    const workspace = await this.#workspaceResolver.resolve(context);
    let targetCompleted = false;
    const stageBoundary = new AbortController();
    const forwardShutdown = () => stageBoundary.abort(context.signal.reason);
    if (context.signal.aborted) {
      forwardShutdown();
    } else {
      context.signal.addEventListener('abort', forwardShutdown, { once: true });
    }
    const responseQueue = context.hitlHistory.map((exchange) => exchange.response);
    const interactionFn: NonNullable<RunGraphOptions['interactionFn']> = async (
      interrupts,
    ): Promise<InteractionResponse[] | null> => {
      const response = responseQueue.shift();
      if (response === undefined) {
        throw new HitlBoundarySignal(interrupts);
      }
      if (response.action === 'skip') {
        return null;
      }
      return interrupts.map((interrupt, index) => ({
        interruptResponse: {
          interruptId: interrupt.id,
          response: index === 0 ? response.text : null,
        },
      }));
    };
    try {
      const modelParameters = safeModelParameters(
        context.settings.model_parameters,
      );
      const credentials =
        this.#modelCredentials === null
          ? {}
          : await this.#modelCredentials.resolve(
              context.scope.owner_id,
              context.settings.provider,
            );
      const engineConfig = createRunEngineConfig({
        provider: context.settings.provider,
        modelId: context.settings.model_id,
        modelParameters: {
          ...modelParameters,
          ...credentials,
        },
        embeddingsModel: context.settings.embeddings_model,
        awsRegion: context.settings.aws_region ?? undefined,
      });
      const historicalContext =
        context.stage.id === 'scanner' && this.#memory !== null
          ? await this.#memory
              .retrieveApplicationContext({
                actorId: context.actorId,
                applicationId: context.scope.application_id,
                query:
                  'Prior threat models, architecture changes, recurring risks, ' +
                  'approved corrections, and mitigation decisions for this application.',
                topK: 5,
              })
              .catch((error: unknown) => {
                this.#logger.error(
                  'AgentCore Memory context retrieval failed',
                  error,
                );
                return [];
              })
          : [];
      const result = await withExecutionObservability({
        ownerId: context.scope.owner_id,
        applicationId: context.scope.application_id,
        runId: context.run.run_id,
        correlationId: context.run.trace_id,
        stage: context.stage.id,
        attempt: context.checkpoint.attempt,
      }, () => this.#graphRunner(workspace.repoPath, {
        runDir: workspace.runDir,
        frameworks: context.settings.frameworks,
        engineConfig,
        authoritativeThreatInputPaths: [
          ...(workspace.authoritativeThreatInputPaths ?? []),
        ],
        historicalContext,
        businessContext: context.settings.business_context,
        interactionFn,
        skipNodes: [...context.completedStageIds],
        shouldInterrupt: () => targetCompleted,
        cancelSignal: stageBoundary.signal,
        onNodeEvent: (event) => {
          if (event.phase === 'complete' && event.nodeId === context.stage.id) {
            targetCompleted = true;
            stageBoundary.abort();
          }
        },
        throwOnNodeFailure: true,
      }));
      if (result.status === 'failed') {
        throw new Error(result.error ?? `engine stage ${context.stage.id} failed`);
      }
      if (result.status === 'interrupted' && context.signal.aborted) {
        if (context.signal.reason !== undefined) {
          throw context.signal.reason;
        }
        const cancellation = new Error('hosted runtime stage cancelled');
        cancellation.name = 'AbortError';
        throw cancellation;
      }
      if (!targetCompleted) {
        throw new Error(`engine stopped before stage ${context.stage.id} completed`);
      }
      let outputArtifacts: ArtifactRef[] = [];
      if (
        context.stage.id === 'report_verifier' &&
        this.#outputPublisher !== null
      ) {
        if (workspace.runDir === undefined) {
          throw new Error(
            'report publication requires a materialized run directory',
          );
        }
        outputArtifacts = [
          ...(await this.#outputPublisher.publish(context, workspace.runDir, workspace.repoPath)),
        ];
      }
      const checkpointArtifact = await this.#checkpointWorkspace(
        context,
        workspace,
        'completed',
      );
      return {
        status: 'completed',
        outputArtifacts:
          checkpointArtifact === null
            ? outputArtifacts
            : [...outputArtifacts, checkpointArtifact],
      };
    } catch (error) {
      const boundary = findBoundary(error);
      if (boundary !== null) {
        const checkpointArtifact = await this.#checkpointWorkspace(
          context,
          workspace,
          'awaiting_input',
        );
        return {
          ...awaiting(boundary.interrupts),
          ...(checkpointArtifact === null
            ? {}
            : { outputArtifacts: [checkpointArtifact] }),
        };
      }
      throw error;
    } finally {
      context.signal.removeEventListener('abort', forwardShutdown);
    }
  }

  async recover(
    context: StageExecutionContext,
    checkpoint: StageExecutionContext['checkpoint'],
  ): Promise<StageExecutionResult | null> {
    const recovered = await this.#workspaceResolver.recover?.(
      context,
      checkpoint,
    );
    if (recovered === undefined || recovered === null) {
      return this.execute(context);
    }
    const outputArtifacts: ArtifactRef[] = [recovered.checkpointArtifact];
    if (
      context.stage.id === 'report_verifier' &&
      this.#outputPublisher !== null
    ) {
      if (recovered.workspace.runDir === undefined) {
        throw new Error(
          'report recovery requires a materialized run directory',
        );
      }
      outputArtifacts.unshift(
        ...(await this.#outputPublisher.publish(
          context,
          recovered.workspace.runDir,
          recovered.workspace.repoPath,
        )),
      );
    }
    return { status: 'completed', outputArtifacts };
  }

  async #checkpointWorkspace(
    context: StageExecutionContext,
    workspace: MaterializedWorkspace,
    boundary: 'completed' | 'awaiting_input',
  ): Promise<ArtifactRef | null> {
    if (this.#workspaceResolver.checkpoint === undefined) {
      return null;
    }
    await context.assertLease();
    const artifact = await this.#workspaceResolver.checkpoint(
      context,
      workspace,
      boundary,
    );
    await context.assertLease();
    return artifact;
  }
}
