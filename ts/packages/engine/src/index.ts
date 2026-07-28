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
export { config, Config, FRAMEWORKS } from './config.js';
export { createModel, activeProvider, type SupportedProvider } from './providers.js';
// Retry policy for transient Bedrock failures. Every Agent in the pipeline is
// constructed with `retryStrategy: makeRetryStrategy()`; see retry.ts for why the
// SDK's default is not sufficient on its own.
export { makeRetryStrategy, TransientBedrockRetryStrategy } from './retry.js';
export { MlServiceClient } from './ml-client.js';
// TTP matching: in-process TS embedding (transformers.js + ATTACK-BERT ONNX) by
// default, Python ML service as fallback. See ml/index.ts for backend selection.
export { matchSteps, matchStepsInProcess, getEmbedding, localModelAvailable } from './ml/index.js';
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
export { runTtpEmbedding } from './stages/ttp.js';

// Agents (factories + verifiers)
export { createScannerAgent, runScanner } from './agents/scanner.js';
export { createThreatAgent, runThreat } from './agents/threat.js';
export { createTreeAgent, runTree } from './agents/tree.js';
export { createMitigationAgent, verifyMitigationOutput } from './agents/mitigation.js';
export { verifyScannerOutput, verifyThreatOutput } from './verifiers.js';
export type { InteractionFn, InteractionResponse, SimpleInterrupt } from './agents/hitl.js';
