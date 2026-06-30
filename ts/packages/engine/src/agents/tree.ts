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
import { config } from '../config.js';
import { createModel } from '../providers.js';
import { makeSandboxedFileRead, makeSandboxedFileWrite } from '../tools/sandboxed-file.js';
import { makeStructuralAnalyzer } from '../tools/structural-analyzer.js';
import { traceAttrs } from '../tracing.js';
import { resolveStateDir } from './scanner.js';
import { TREE_SYSTEM_PROMPT } from './tree.prompt.js';

export const STATE_FILE = 'attack_trees.json';

/** Create a Tree Generator Agent scoped to the given repository. */
export async function createTreeAgent(repoPath: string, runDir?: string): Promise<Agent> {
  const stateDir = resolveStateDir(repoPath, runDir);

  const scannerState = join(stateDir, 'scanner_context.json');
  const threatsState = join(stateDir, 'threats.json');
  const treeState = join(stateDir, STATE_FILE);

  const tools = [
    makeSandboxedFileRead([scannerState, threatsState, repoPath]),
    makeSandboxedFileWrite([treeState]),
    makeStructuralAnalyzer(repoPath),
  ];

  let systemPrompt = TREE_SYSTEM_PROMPT;
  systemPrompt +=
    `\n\n## Paths\n` +
    `- Scanner context: \`${scannerState}\`\n` +
    `- Threats: \`${threatsState}\`\n` +
    `- Write output to: \`${treeState}\`\n`;

  const model: Model = await createModel(config, { temperature: 0 });

  return new Agent({
    id: 'tree',
    name: 'Tree',
    model,
    systemPrompt,
    tools,
    printer: false,
    traceAttributes: traceAttrs('tree'),
  });
}

/** Run the Tree Generator and return the state file path. */
export async function runTree(repoPath: string, runDir?: string): Promise<string> {
  const agent = await createTreeAgent(repoPath, runDir);
  await agent.invoke(
    'Read the threats and scanner context, then generate attack trees. Write them to the state file.',
  );
  const stateDir = resolveStateDir(repoPath, runDir);
  return join(stateDir, STATE_FILE);
}
