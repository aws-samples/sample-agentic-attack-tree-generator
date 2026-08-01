#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { scanTool, getRunTool, listRunsTool, getFindingsTool, seedExistingRuns } from './tools.js';

function resolveProjectRoot(): string {
  const explicit = process.env.THREATFOREST_ROOT ?? process.argv[2];
  if (explicit) return resolve(explicit);
  let dir = process.cwd();
  while (dir !== dirname(dir)) {
    if (existsSync(resolve(dir, '.threatforest', 'config.yaml'))) return dir;
    dir = dirname(dir);
  }
  return process.cwd();
}

const root = resolveProjectRoot();
process.chdir(root);

const server = new McpServer({
  name: 'threatforest',
  version: '0.1.0',
});

server.registerTool(
  'threatforest_scan',
  {
    title: 'ThreatForest Scan',
    description:
      'Start a threat model scan against a project directory. Returns a run_id immediately ' +
      '(the scan runs 5-30 min in background). Poll with threatforest_get_run to monitor progress.',
    inputSchema: {
      project_path: z.string().describe('Absolute path to the project directory to analyze.'),
      frameworks: z
        .array(z.string())
        .nullable()
        .optional()
        .describe('MITRE frameworks: "attack", "atlas", "wiz". Omit for all.'),
    },
  },
  async (args) => {
    const result = await scanTool({
      project_path: args.project_path as string,
      frameworks: (args.frameworks as string[] | null) ?? null,
    });
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  },
);

server.registerTool(
  'threatforest_get_run',
  {
    title: 'ThreatForest Get Run',
    description:
      'Check the status of a threat model scan. Returns progress percentage, current stage, ' +
      'and a summary of findings when complete.',
    inputSchema: {
      run_id: z.string().describe('The run_id returned by threatforest_scan.'),
    },
  },
  (args) => {
    const result = getRunTool({ run_id: args.run_id as string });
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  },
);

server.registerTool(
  'threatforest_list_runs',
  {
    title: 'ThreatForest List Runs',
    description: 'List all active and recently completed threat model scans.',
    inputSchema: {},
  },
  () => {
    const result = listRunsTool();
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  },
);

server.registerTool(
  'threatforest_get_findings',
  {
    title: 'ThreatForest Get Findings',
    description:
      'Retrieve the full structured findings (attack trees, TTP mappings, mitigations) ' +
      'from a completed scan. Returns rich JSON with threat statements, MITRE technique ' +
      'mappings, attack step probabilities, and mitigation recommendations.',
    inputSchema: {
      run_id: z.string().describe('The run_id of a completed scan.'),
    },
  },
  (args) => {
    const result = getFindingsTool({ run_id: args.run_id as string });
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  },
);

async function main(): Promise<void> {
  seedExistingRuns();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`ThreatForest MCP server error: ${(err as Error).message}\n`);
  process.exit(1);
});
