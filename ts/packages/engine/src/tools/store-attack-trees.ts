import { tool } from '@strands-agents/sdk';
import { z } from 'zod';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { AttackTreeDraftSchema, normalizeAttackTrees, OUTPUT_CONTRACT_VERSION } from '../output-contract.js';

const Input = z.object({ attack_trees: z.array(AttackTreeDraftSchema).min(1) });

export function makeStoreAttackTrees(outputPath: string, threats: () => Record<string, unknown>[]) {
  return tool({
    name: 'store_attack_trees',
    description: 'Validate and store all trees. IDs, parent references, leaf flags and metadata are assigned consistently by ThreatForest. Use the threat IDs from the supplied threats file.',
    inputSchema: Input,
    callback: (input: z.infer<typeof Input>): string => {
      const trees = normalizeAttackTrees(input.attack_trees, threats());
      mkdirSync(dirname(outputPath), { recursive: true });
      writeFileSync(outputPath, JSON.stringify({
        output_contract_version: OUTPUT_CONTRACT_VERSION, attack_trees: trees,
      }, null, 2));
      return JSON.stringify({ stored: trees.length, ids: trees.map(tree => tree['id']) });
    },
  });
}
