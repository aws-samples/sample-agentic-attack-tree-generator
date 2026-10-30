import type { StageDefinition } from './contracts.js';

/**
 * This order mirrors engine/src/pipeline/graph.ts. Each node is a durable
 * boundary, including deterministic verifier nodes.
 */
export const THREATFOREST_STAGE_PLAN: readonly StageDefinition[] = Object.freeze([
  { id: 'scanner', version: 1, hitlKind: null, usesModel: true },
  { id: 'scanner_verifier', version: 1, hitlKind: null, usesModel: false },
  { id: 'scanner_review', version: 1, hitlKind: 'scanner_review', usesModel: false },
  { id: 'interviewer', version: 1, hitlKind: 'interviewer', usesModel: true },
  { id: 'threat', version: 1, hitlKind: null, usesModel: true },
  { id: 'threat_verifier', version: 1, hitlKind: null, usesModel: false },
  { id: 'threat_review', version: 1, hitlKind: 'threat_review', usesModel: true },
  { id: 'parallel_pipeline', version: 1, hitlKind: null, usesModel: true },
  { id: 'parallel_verifier', version: 1, hitlKind: null, usesModel: false },
  { id: 'probability', version: 1, hitlKind: null, usesModel: false },
  { id: 'report', version: 1, hitlKind: null, usesModel: false },
  { id: 'report_verifier', version: 1, hitlKind: null, usesModel: false },
]);

export function validateStagePlan(plan: readonly StageDefinition[]): void {
  if (plan.length === 0) {
    throw new Error('stage plan must contain at least one stage');
  }
  const ids = new Set<string>();
  for (const stage of plan) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(stage.id)) {
      throw new Error(`invalid stage id: ${stage.id}`);
    }
    if (!Number.isInteger(stage.version) || stage.version < 1) {
      throw new Error(`invalid version for stage ${stage.id}`);
    }
    if (ids.has(stage.id)) {
      throw new Error(`duplicate stage id: ${stage.id}`);
    }
    ids.add(stage.id);
  }
}
