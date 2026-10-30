/**
 * Both generated and supplied threats use the same application-owned storage
 * contract. Supplied text retains its original wording and provenance.
 */
import { Agent, tool, type Model } from '@strands-agents/sdk';
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { z } from 'zod';
import { config, type EngineConfigSource } from '../config.js';
import { observeAgent } from '../execution-observability.js';
import { createModel } from '../providers.js';
import { makeRetryStrategy } from '../retry.js';
import { makeSandboxedFileRead } from '../tools/sandboxed-file.js';
import { normalizeThreats, ThreatDraftSchema, OUTPUT_CONTRACT_VERSION, type CanonicalThreat } from '../output-contract.js';
import { makeStructuralAnalyzer } from '../tools/structural-analyzer.js';
import { traceAttrs } from '../tracing.js';
import { resolveStateDir } from './scanner.js';
import {
  AUTHORITATIVE_THREAT_REVISION_ADDENDUM,
  AUTHORITATIVE_THREAT_SYSTEM_PROMPT,
  THREAT_SYSTEM_PROMPT,
} from './threat.prompt.js';

export const STATE_FILE = 'threats.json';

export interface ThreatAgentOptions {
  /**
   * Files containing the complete threat set supplied by the user. Paths may be
   * absolute or relative to repoPath, but must resolve to regular files inside
   * repoPath (the local repository or hosted materialized workspace).
   */
  authoritativeThreatInputPaths?: readonly string[] | null;
  /** Allow the threat agent to read existing threats.json during a HITL revision. */
  includeExistingThreatState?: boolean;
  /** Per-run model/TTP configuration. Defaults to the local filesystem config. */
  engineConfig?: EngineConfigSource;
}

export interface ThreatAgentContext {
  scannerState: string;
  threatState: string;
  authoritativeThreatInputPaths: string[];
  readPaths: string[];
  systemPrompt: string;
}

export type AuthoritativeThreatDraft = z.infer<typeof ThreatDraftSchema>;
export type NormalizedAuthoritativeThreat = CanonicalThreat;

/**
 * Normalize model-extracted supplied threats into the existing threats.json
 * object shape. The model cannot set provenance, and missing/duplicate IDs are
 * replaced deterministically without changing item order.
 */
export function normalizeAuthoritativeThreats(
  drafts: readonly AuthoritativeThreatDraft[],
): NormalizedAuthoritativeThreat[] {
  return normalizeThreats(drafts, 'user_provided');
}

const StoreThreatsSchema = z.object({
  threats: z
    .array(ThreatDraftSchema)
    .min(1)
    .describe('The complete threat set, in stable source or analysis order.'),
});

export function makeStoreThreats(outputPath: string, source: CanonicalThreat['threat_source']) {
  return tool({
    name: source === 'user_provided' ? 'store_authoritative_threats' : 'store_threats',
    description:
      'Validate and store the complete threat set. This tool assigns provenance and ' +
      'canonical IDs. Reuse returned IDs when revising existing threats.',
    inputSchema: StoreThreatsSchema,
    callback: (input: z.infer<typeof StoreThreatsSchema>): string => {
      const previous = existsSync(outputPath)
        ? JSON.parse(readFileSync(outputPath, 'utf8')) as { threats?: Record<string, unknown>[]; next_threat_number?: number }
        : {};
      const threats = normalizeThreats(input.threats, source, previous.threats ?? [], previous.next_threat_number);
      const nextThreatNumber = Math.max(previous.next_threat_number ?? 1,
        ...threats.map(threat => Number(threat.id.slice(2)) + 1));
      mkdirSync(dirname(outputPath), { recursive: true });
      writeFileSync(outputPath, JSON.stringify({
        output_contract_version: OUTPUT_CONTRACT_VERSION,
        next_threat_number: nextThreatNumber,
        threats,
      }, null, 2), 'utf-8');
      return JSON.stringify({ stored: threats.length, threats: threats.map(({ id, title }) => ({ id, title })) });
    },
  });
}

function isWithinRoot(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Resolve and validate authoritative inputs before any model is constructed.
 * realpath checks prevent both lexical traversal and symlink escapes.
 */
export function resolveAuthoritativeThreatInputPaths(
  repoPath: string,
  inputPaths: readonly string[] | null | undefined,
): string[] {
  if (!inputPaths || inputPaths.length === 0) return [];

  let repoRoot: string;
  try {
    repoRoot = realpathSync(repoPath);
  } catch (error) {
    throw new Error(
      `Cannot resolve repository/materialized workspace ${JSON.stringify(repoPath)}: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!statSync(repoRoot).isDirectory()) {
    throw new Error(
      `Repository/materialized workspace is not a directory: ${JSON.stringify(repoPath)}`,
    );
  }

  const resolvedPaths: string[] = [];
  const seen = new Set<string>();
  for (const rawPath of inputPaths) {
    if (typeof rawPath !== 'string' || rawPath.trim() === '') {
      throw new Error('Authoritative threat input paths must be non-empty strings');
    }

    const candidate = isAbsolute(rawPath) ? rawPath : resolve(repoRoot, rawPath);
    let resolvedPath: string;
    try {
      resolvedPath = realpathSync(candidate);
    } catch (error) {
      throw new Error(
        `Authoritative threat input does not exist: ${JSON.stringify(rawPath)} ` +
          `(${error instanceof Error ? error.message : String(error)})`,
      );
    }

    if (!isWithinRoot(resolvedPath, repoRoot)) {
      throw new Error(
        `Authoritative threat input is outside the repository/materialized workspace: ` +
          `${JSON.stringify(rawPath)}`,
      );
    }
    if (!statSync(resolvedPath).isFile()) {
      throw new Error(
        `Authoritative threat input is not a regular file: ${JSON.stringify(rawPath)}`,
      );
    }
    if (!seen.has(resolvedPath)) {
      seen.add(resolvedPath);
      resolvedPaths.push(resolvedPath);
    }
  }
  return resolvedPaths;
}

/** Build the mode-specific prompt without constructing a model. */
export function buildThreatSystemPrompt(
  scannerState: string,
  threatState: string,
  authoritativeThreatInputPaths: readonly string[] = [],
  includeExistingThreatState = false,
): string {
  if (authoritativeThreatInputPaths.length === 0) {
    return (
      THREAT_SYSTEM_PROMPT +
      `\n\n## Paths\n- Scanner context: \`${scannerState}\`\n` +
      (includeExistingThreatState
        ? `- Existing threat state: \`${threatState}\`\n`
        : '') +
      `- Write output to: \`${threatState}\`\n`
    );
  }

  const inputs = authoritativeThreatInputPaths
    .map((inputPath, index) => `- Input ${index + 1}: ${JSON.stringify(inputPath)}`)
    .join('\n');
  return (
    AUTHORITATIVE_THREAT_SYSTEM_PROMPT +
    (includeExistingThreatState ? AUTHORITATIVE_THREAT_REVISION_ADDENDUM : '') +
    `\n\n## Paths\n- Scanner context: ${JSON.stringify(scannerState)}\n` +
    `- Existing/output state: ${JSON.stringify(threatState)}\n` +
    `- Authoritative threat inputs:\n${inputs}\n`
  );
}

/** User prompt shared by the initial run and verifier-owned retries. */
export function buildThreatInvocationPrompt(
  authoritativeThreatInputPaths: readonly string[] = [],
): string {
  if (authoritativeThreatInputPaths.length === 0) {
    return 'Read the scanner context and generate threats. Write them to the state file.';
  }
  return (
    'Read every authoritative threat input file and normalize every explicitly supplied ' +
    'threat into the state file. Do not generate, infer, or add any threat that is not ' +
    'present in those files.'
  );
}

/** Build all filesystem and prompt inputs used by createThreatAgent. */
export function buildThreatAgentContext(
  repoPath: string,
  runDir?: string,
  options: ThreatAgentOptions = {},
): ThreatAgentContext {
  const stateDir = resolveStateDir(repoPath, runDir);
  const scannerState = join(stateDir, 'scanner_context.json');
  const threatState = join(stateDir, STATE_FILE);
  const authoritativeThreatInputPaths = resolveAuthoritativeThreatInputPaths(
    repoPath,
    options.authoritativeThreatInputPaths,
  );
  const authoritative = authoritativeThreatInputPaths.length > 0;
  const includeExistingThreatState = options.includeExistingThreatState ?? false;

  return {
    scannerState,
    threatState,
    authoritativeThreatInputPaths,
    // In authoritative mode, exact source files are exposed through this read
    // tool; repository-wide exploration is intentionally unavailable.
    readPaths: authoritative
      ? [
          scannerState,
          ...(includeExistingThreatState ? [threatState] : []),
          ...authoritativeThreatInputPaths,
        ]
      : [scannerState, ...(includeExistingThreatState ? [threatState] : []), repoPath],
    systemPrompt: buildThreatSystemPrompt(
      scannerState,
      threatState,
      authoritativeThreatInputPaths,
      includeExistingThreatState,
    ),
  };
}

/** Create a Threat Agent scoped to the given repository. */
export async function createThreatAgent(
  repoPath: string,
  runDir?: string,
  options: ThreatAgentOptions = {},
): Promise<Agent> {
  const context = buildThreatAgentContext(repoPath, runDir, options);
  const authoritative = context.authoritativeThreatInputPaths.length > 0;
  const tools = [
    makeSandboxedFileRead(context.readPaths),
    makeStoreThreats(context.threatState, authoritative ? 'user_provided' : 'generated'),
    ...(authoritative ? [] : [makeStructuralAnalyzer(repoPath)]),
  ];

  const model: Model = await createModel(options.engineConfig ?? config, {
    temperature: 0,
  });

  return observeAgent(new Agent({
    id: 'threat',
    name: 'Threat',
    model,
    systemPrompt: context.systemPrompt,
    tools,
    printer: false,
    retryStrategy: makeRetryStrategy(),
    traceAttributes: traceAttrs('threat'),
  }), 'threat', 'Threat generation');
}

/** Run the Threat Agent and return the state file path. */
export async function runThreat(
  repoPath: string,
  runDir?: string,
  options: ThreatAgentOptions = {},
): Promise<string> {
  const context = buildThreatAgentContext(repoPath, runDir, options);
  const agent = await createThreatAgent(repoPath, runDir, {
    authoritativeThreatInputPaths: context.authoritativeThreatInputPaths,
    includeExistingThreatState: options.includeExistingThreatState,
    engineConfig: options.engineConfig,
  });
  await agent.invoke(buildThreatInvocationPrompt(context.authoritativeThreatInputPaths));
  const stateDir = resolveStateDir(repoPath, runDir);
  return join(stateDir, STATE_FILE);
}
