import { tool } from '@strands-agents/sdk';
import { z } from 'zod';
import { scanTool, getRunTool, listRunsTool, getFindingsTool } from './tools.js';

const ScanInput = z.object({
  project_path: z.string().describe('Absolute path to the project directory to threat-model.'),
  frameworks: z
    .array(z.string())
    .nullable()
    .default(null)
    .describe('MITRE frameworks: "attack", "atlas", "wiz". Null = all.'),
});

const GetRunInput = z.object({
  run_id: z.string().describe('The run_id returned by threatforest_scan.'),
});

const GetFindingsInput = z.object({
  run_id: z.string().describe('The run_id of a completed scan.'),
});

export function makeScanTool() {
  return tool({
    name: 'threatforest_scan',
    description:
      'Start a ThreatForest threat model scan against a project directory. Returns a run_id ' +
      'immediately (scan runs 5-30 min in background). Poll with threatforest_get_run.',
    inputSchema: ScanInput,
    callback: async (input: z.infer<typeof ScanInput>) => {
      return scanTool(input);
    },
  });
}

export function makeGetRunTool() {
  return tool({
    name: 'threatforest_get_run',
    description:
      'Check the status and progress of a ThreatForest scan. Returns progress percentage, ' +
      'current stage, and a summary of findings when complete.',
    inputSchema: GetRunInput,
    callback: (input: z.infer<typeof GetRunInput>) => {
      return getRunTool(input);
    },
  });
}

export function makeListRunsTool() {
  return tool({
    name: 'threatforest_list_runs',
    description: 'List all active and recently completed ThreatForest threat model scans.',
    inputSchema: z.object({}),
    callback: () => {
      return listRunsTool();
    },
  });
}

export function makeGetFindingsTool() {
  return tool({
    name: 'threatforest_get_findings',
    description:
      'Retrieve the full structured findings from a completed ThreatForest scan: attack trees, ' +
      'MITRE TTP mappings, attack step probabilities, and mitigation recommendations.',
    inputSchema: GetFindingsInput,
    callback: (input: z.infer<typeof GetFindingsInput>) => {
      return getFindingsTool(input);
    },
  });
}
