/**
 * @threatforest/engine — the ThreatForest agent pipeline on the Strands TS SDK.
 *
 * Public surface for the server (WS-4) and CLI (WS-5): build/run the graph,
 * plus the individual stages/agents/config for finer-grained orchestration.
 */
export {
  runGraph,
  buildGraph,
  type RunGraphOptions,
  type RunGraphResult,
  type NodeProgressEvent,
} from './pipeline/graph.js';
export {
  config,
  Config,
  RunEngineConfig,
  createRunEngineConfig,
  FRAMEWORKS,
  type EngineConfigSource,
  type RunEngineConfigInput,
  type ModelParameterValue,
} from './config.js';
export { createModel, activeProvider, type SupportedProvider } from './providers.js';
// Retry policy for transient Bedrock failures. Every Agent in the pipeline is
// constructed with `retryStrategy: makeRetryStrategy()`; see retry.ts for why the
// SDK's default is not sufficient on its own.
export { makeRetryStrategy, TransientBedrockRetryStrategy } from './retry.js';
export { MlServiceClient } from './ml-client.js';
// TTP matching runs in the Python ML service (`python -m ml_service`) — the only
// backend, because it is the one that honours `embeddings.model`. See ml/index.ts.
export { matchSteps, mlHealthCheck } from './ml/index.js';
export {
  LocalFilesystemWorkspace,
  resolveStateDir,
  resolveOutputDir,
} from './workspace.js';
export { initSession, setupLangfuseOtel, traceAttrs } from './tracing.js';

// Stages
export { runParallelPipeline } from './stages/parallel.js';
export { runProbabilityStage } from './stages/probability-stage.js';
export { runReportGenerator, verifyReportOutput } from './stages/report.js';
export { runTtpEmbedding, verifyTtpCoverage } from './stages/ttp.js';
export {
  evaluateDomainOutputQuality,
  findMitigationQualityIssues,
  findTtpDecisionQualityIssues,
  hasUsableMitigationEvidence,
  findAttackTreeQualityIssues,
  type DomainQualityInput,
  type DomainQualityReport,
} from './quality/domain-quality.js';
export { createSourceEvidenceResolver, type EvidenceResolver } from './quality/evidence.js';
export {
  selectTtpDecision,
  TTP_ACCEPTED_PRECISION_TARGET,
  TTP_ACCEPTANCE_POLICY_VERSION,
  TTP_MINIMUM_ACCEPTANCE_MARGIN,
  TTP_STRONG_MATCH_SIMILARITY,
  type TtpDecision,
} from './quality/ttp-confidence.js';

// Agents (factories + verifiers)
export { createScannerAgent, runScanner } from './agents/scanner.js';
export {
  createThreatAgent,
  runThreat,
  type ThreatAgentOptions,
} from './agents/threat.js';
export { createTreeAgent, runTree } from './agents/tree.js';
export { createMitigationAgent, verifyMitigationOutput } from './agents/mitigation.js';
export {
  verifyScannerOutput,
  verifyThreatOutput,
  type VerifyThreatOutputOptions,
} from './verifiers.js';
export type { InteractionFn, InteractionResponse, SimpleInterrupt } from './agents/hitl.js';
export { withExecutionObservability } from './execution-observability.js';
