/**
 * Threat Agent — TS port of `src/threatforest/agents/threat/agent.py`.
 *
 * Reads `scanner_context.json` (and the repo, for deeper investigation) and
 * writes `threats.json`. The agent writes JSON itself via `sandboxed_file_write`
 * (no `structuredOutputSchema`), exactly like the Python, so state round-trips.
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
import { THREAT_SYSTEM_PROMPT } from './threat.prompt.js';

export const STATE_FILE = 'threats.json';

/** Create a Threat Agent scoped to the given repository. */
export async function createThreatAgent(repoPath: string, runDir?: string): Promise<Agent> {
  const stateDir = resolveStateDir(repoPath, runDir);

  const scannerState = join(stateDir, 'scanner_context.json');
  const threatState = join(stateDir, STATE_FILE);

  const tools = [
    makeSandboxedFileRead([scannerState, repoPath]),
    makeSandboxedFileWrite([threatState]),
    makeStructuralAnalyzer(repoPath),
  ];

  let systemPrompt = THREAT_SYSTEM_PROMPT;
  systemPrompt += `\n\n## Paths\n- Scanner context: \`${scannerState}\`\n- Write output to: \`${threatState}\`\n`;

  const model: Model = await createModel(config, { temperature: 0 });

  return new Agent({
    model,
    systemPrompt,
    tools,
    printer: false,
    traceAttributes: traceAttrs('threat'),
  });
}

/** Run the Threat Agent and return the state file path. */
export async function runThreat(repoPath: string, runDir?: string): Promise<string> {
  const agent = await createThreatAgent(repoPath, runDir);
  await agent.invoke(
    'Read the scanner context and generate threat statements. Write them to the state file.',
  );
  const stateDir = resolveStateDir(repoPath, runDir);
  return join(stateDir, STATE_FILE);
}
