/**
 * Tree Generator Agent — TS port of `src/threatforest/agents/tree/agent.py`.
 *
 * Reads `threats.json` + `scanner_context.json` (and the repo, to verify code
 * paths) and writes `attack_trees.json`. The agent writes JSON itself via
 * `sandboxed_file_write` (no `structuredOutputSchema`), exactly like the Python,
 * so state round-trips byte-for-byte.
 *
 * `resolveStateDir` / `STATE_DIR` are imported from scanner.ts, mirroring the
 * Python `from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir`.
 */
import { Agent, type Model } from '@strands-agents/sdk';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { config, type EngineConfigSource } from '../config.js';
import { observeAgent } from '../execution-observability.js';
import { createModel } from '../providers.js';
import { makeRetryStrategy } from '../retry.js';
import { makeSandboxedFileRead } from '../tools/sandboxed-file.js';
import { makeStoreAttackTrees } from '../tools/store-attack-trees.js';
import { makeStructuralAnalyzer } from '../tools/structural-analyzer.js';
import { traceAttrs } from '../tracing.js';
import { resolveStateDir } from './scanner.js';
import { TREE_SYSTEM_PROMPT } from './tree.prompt.js';

export const STATE_FILE = 'attack_trees.json';

/** Create a Tree Generator Agent scoped to the given repository. */
export async function createTreeAgent(
  repoPath: string,
  runDir?: string,
  engineConfig: EngineConfigSource = config,
): Promise<Agent> {
  const stateDir = resolveStateDir(repoPath, runDir);

  const scannerState = join(stateDir, 'scanner_context.json');
  const threatsState = join(stateDir, 'threats.json');
  const treeState = join(stateDir, STATE_FILE);

  const tools = [
    makeSandboxedFileRead([scannerState, threatsState, repoPath]),
    makeStoreAttackTrees(treeState, () => JSON.parse(readFileSync(threatsState, 'utf8')).threats),
    makeStructuralAnalyzer(repoPath),
  ];

  let systemPrompt = TREE_SYSTEM_PROMPT;
  systemPrompt +=
    `\n\n## Paths\n` +
    `- Scanner context: \`${scannerState}\`\n` +
    `- Threats: \`${threatsState}\`\n` +
    `- Write output to: \`${treeState}\`\n`;

  const model: Model = await createModel(engineConfig, { temperature: 0 });

  return observeAgent(new Agent({
    id: 'tree',
    name: 'Tree',
    model,
    systemPrompt,
    tools,
    printer: false,
    retryStrategy: makeRetryStrategy(),
    traceAttributes: traceAttrs('tree'),
  }), 'tree', 'Attack tree');
}

/** Run the Tree Generator and return the state file path. */
export async function runTree(
  repoPath: string,
  runDir?: string,
  engineConfig: EngineConfigSource = config,
): Promise<string> {
  const agent = await createTreeAgent(repoPath, runDir, engineConfig);
  await agent.invoke(
    'Read the threats and scanner context, then generate attack trees. Write them to the state file.',
  );
  const stateDir = resolveStateDir(repoPath, runDir);
  return join(stateDir, STATE_FILE);
}
