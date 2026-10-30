import { z } from 'zod';
import { findAttackTreeQualityIssues } from './quality/domain-quality.js';

type Json = Record<string, unknown>;
export const OUTPUT_CONTRACT_VERSION = '2.0.0';
export const THREAT_ID = /^TS[0-9]{3,}$/;

export const ThreatDraftSchema = z.object({
  id: z.string().trim().optional(),
  title: z.string().trim().min(1),
  description: z.string().trim().min(1),
  priority: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
  affected_components: z.array(z.string().trim().min(1)).min(1),
});

export type CanonicalThreat = z.infer<typeof ThreatDraftSchema> & {
  id: string;
  threat_source: 'generated' | 'user_provided';
  source_id?: string;
};

/** Generated statements have one grammar. Never invent missing claim fields. */
function threatStatementParts(description: string): RegExpMatchArray | null {
  return description.trim().replace(/\s+/g, ' ').match(
    /^A (.+?) with (.+?) can (.+?), which leads to (.+?), resulting in reduced (confidentiality|integrity|availability) of (.+?)[.]?$/i,
  );
}

export function canonicalThreatStatement(description: string): string {
  const match = threatStatementParts(description);
  if (!match) {
    throw new Error('Threat description must use: A [actor] with [prerequisites] can [action], which leads to [impact], resulting in reduced [confidentiality|integrity|availability] of [assets]. Use only source-supported details.');
  }
  return `A ${match[1]} with ${match[2]} can ${match[3]}, which leads to ${match[4]}, resulting in reduced ${match[5]!.toLowerCase()} of ${match[6]}.`;
}

/**
 * IDs belong to the application. On review, retain existing IDs and allocate
 * new ones above the persisted high-water mark.
 */
export function normalizeThreats(
  input: unknown,
  source: CanonicalThreat['threat_source'],
  previous: readonly Json[] = [],
  nextThreatNumber = 1,
): CanonicalThreat[] {
  const drafts = z.array(ThreatDraftSchema).min(1).parse(input);
  const previousById = new Map(previous.map(threat => [String(threat['id']), threat]));
  const previousBySourceId = new Map(previous.filter(threat => threat['source_id'])
    .map(threat => [String(threat['source_id']), threat]));
  const used = new Set<string>();
  let next = Math.max(nextThreatNumber - 1, 0, ...previous.map(threat =>
    THREAT_ID.test(String(threat['id'])) ? Number(String(threat['id']).slice(2)) : 0,
  )) + 1;
  return drafts.map(draft => {
    const description = source === 'generated'
      ? canonicalThreatStatement(draft.description) : draft.description;
    // A retried model call may choose another temporary ID. Preserve the ID of
    // an unambiguous unchanged item rather than treating that retry as new work.
    const same = previous.filter(value =>
      value['title'] === draft.title && value['description'] === description);
    const prior = (draft.id ? previousById.get(draft.id) ?? previousBySourceId.get(draft.id) : undefined) ??
      (same.length === 1 ? same[0] : undefined);
    const priorId = String(prior?.['id'] ?? '');
    const keep = THREAT_ID.test(priorId) && !used.has(priorId);
    const id = keep ? priorId : `TS${String(next++).padStart(3, '0')}`;
    used.add(id);
    const sourceId = source === 'user_provided'
      ? (typeof prior?.['source_id'] === 'string' ? prior['source_id'] : !prior ? draft.id : undefined)
      : undefined;
    return {
      id,
      title: draft.title,
      // Authoritative input is a source quotation, not a license to invent
      // absent prerequisites or CIA impacts merely to satisfy a sentence form.
      description,
      priority: draft.priority,
      threat_source: source,
      affected_components: [...new Set(draft.affected_components)],
      ...(sourceId && sourceId !== id ? { source_id: sourceId } : {}),
    };
  });
}

const Factor = z.enum(['', 'low', 'med', 'high']);
const StepDraft = z.object({
  id: z.string().trim().min(1),
  title: z.string().trim().min(1),
  description: z.string().trim().min(1),
  parent_id: z.string().trim(),
  category: z.enum(['fact', 'attack']).default('attack'),
  is_leaf: z.boolean().optional(),
  feasibility_note: z.string().default(''),
  skill_required: Factor.optional(),
  access_required: z.enum(['', 'none', 'authenticated', 'privileged']).optional(),
  detectability: Factor.optional(),
  exploit_maturity: z.enum(['', 'theoretical', 'poc', 'weaponised']).optional(),
});
export const AttackTreeDraftSchema = z.object({
  id: z.string().optional(),
  threat_id: z.string().trim().min(1),
  root_goal: z.string().trim().min(1),
  steps: z.array(StepDraft).min(2),
});

/** Shared by initial storage and final merge; every reference uses the same map. */
export function renumberAttackTrees(trees: readonly Json[], start = 1): [Json[], Record<string, string>] {
  const mapping: Record<string, string> = {};
  const result = trees.map((tree, index) => {
    const id = `AT${String(start + index).padStart(3, '0')}`;
    const steps = tree['steps'] as Json[];
    const local = new Map(steps.map((step, offset) => [String(step['id']), `${id}-S${offset + 1}`]));
    if (local.size !== steps.length) throw new Error('Attack steps contain duplicate IDs');
    return {
      ...tree, id,
      steps: steps.map(step => {
        const oldId = String(step['id']);
        if (mapping[oldId]) throw new Error(`Attack step ID ${oldId} is shared by multiple trees`);
        mapping[oldId] = local.get(oldId)!;
        const parent = String(step['parent_id']);
        if (parent && !local.has(parent)) throw new Error(`${oldId}: unknown parent ${parent}`);
        return { ...step, id: local.get(oldId)!, parent_id: parent ? local.get(parent)! : '' };
      }),
    };
  });
  return [result, mapping];
}

export function normalizeAttackTrees(input: unknown, threats: readonly Json[]): Json[] {
  const drafts = z.array(AttackTreeDraftSchema).min(1).parse(input);
  const trees: Json[] = drafts.map(tree => {
    const threat = threats.find(value => value['id'] === tree.threat_id || value['source_id'] === tree.threat_id);
    if (!threat) throw new Error(`Unknown threat_id ${tree.threat_id}; use the IDs from the threats file`);
    const root = tree.steps[0]!;
    if (root.category !== 'fact' || root.parent_id !== '' ||
        tree.steps.filter(step => step.category === 'fact').length !== 1) {
      throw new Error(`${tree.threat_id}: the first step must be the single fact root`);
    }
    const statement = threat['threat_source'] === 'generated'
      ? threatStatementParts(String(threat['description'])) : null;
    if (statement) {
      // The fact root describes the scenario's actor and prerequisites, not
      // model-generated provenance or the attack's eventual outcome.
      root.title = 'Attacker prerequisites';
      root.description = `A ${statement[1]} with ${statement[2]}.`;
    }
    const parents = new Set(tree.steps.map(step => step.parent_id).filter(Boolean));
    for (const step of tree.steps.slice(1)) {
      if (!step.skill_required || !step.access_required || !step.detectability || !step.exploit_maturity) {
        throw new Error(`${step.id}: all four attacker factors are required`);
      }
    }
    return {
      ...tree, id: tree.id ?? tree.threat_id, threat_id: String(threat['id']),
      steps: tree.steps.map(step => ({
        ...step,
        is_leaf: !parents.has(step.id),
        skill_required: step.category === 'fact' ? '' : step.skill_required,
        access_required: step.category === 'fact' ? '' : step.access_required,
        detectability: step.category === 'fact' ? '' : step.detectability,
        exploit_maturity: step.category === 'fact' ? '' : step.exploit_maturity,
      })),
    };
  });
  const [canonical] = renumberAttackTrees(trees);
  const issues = findAttackTreeQualityIssues(canonical, threats);
  if (issues.length) throw new Error(issues.join('; '));
  return canonical;
}
