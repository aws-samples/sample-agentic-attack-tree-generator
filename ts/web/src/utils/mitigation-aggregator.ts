/**
 * Mitigation aggregation utility.
 * Collects mitigations from all sources in an attack tree, deduplicates by name,
 * and tracks which attack steps each mitigation is associated with.
 *
 * The functions here read the *report-bundle* attack-tree shape
 * (`threatforest_data.json`), which is richer and looser than the strict
 * `UiAttackTree` schema in `@threatforest/types` — the report stage accretes
 * `attack_steps`, tree-level `mitigations`, `priority`, override fields, etc.
 * The input interfaces below describe exactly the fields these functions read;
 * `UiTTPMapping` is referenced where the ttc_mapping shape matches.
 */
import type { UiTTPMapping } from '@threatforest/types';

// ─── Input shapes (report-bundle / loose runtime JSON) ────────────

/** A raw mitigation object as it appears anywhere in the report bundle. */
export interface RawMitigation {
  mitigation_text?: string;
  name?: string;
  mitigation?: string;
  implementation_guidance?: string;
  description?: string;
  details?: string;
  remediation_type?: string;
  priority?: number | string | null;
  technique_id?: string;
  evidence?: unknown[];
  override_status?: string | null;
  override_comment?: string;
  override_updated_at?: string;
  relationship_description?: string;
  [key: string]: unknown;
}

/** A raw attack step in the report bundle (carries optional nested mitigations). */
export interface RawAttackStep {
  node_id?: string;
  label?: string;
  description?: string;
  category?: string;
  probability?: number;
  reach_probability?: number;
  probability_rationale?: string;
  mitigations?: RawMitigation[];
  [key: string]: unknown;
}

/** A raw ttc_mapping in the report bundle (a {@link UiTTPMapping} plus extras). */
export interface RawTtcMapping extends Partial<UiTTPMapping> {
  attack_step?: string;
  mitigations?: RawMitigation[] | null;
  reasoning?: string;
  priority?: number | string | null;
  [key: string]: unknown;
}

/** The loose report-bundle attack-tree shape these utilities consume. */
export interface ReportAttackTree {
  threat_id?: string;
  threat_category?: string;
  threat_statement?: string;
  threat_description?: string;
  priority?: number | string | null;
  attack_steps?: RawAttackStep[];
  ttc_mappings?: RawTtcMapping[];
  mitigations?: RawMitigation[];
  [key: string]: unknown;
}

/** A threat row from the top-level `threats` list (used for asset lookup). */
export interface ThreatRow {
  id?: string;
  threat_id?: string;
  affected_components?: string[];
  impactedAssets?: string[];
  [key: string]: unknown;
}

// ─── Output shapes ────────────────────────────────────────────────

/** A {label, nodeId} reference to an attack step the mitigation defends. */
export interface AttackStepRef {
  label: string;
  nodeId: string;
}

/** A mitigation aggregated + deduplicated within a single attack tree. */
export interface AggregatedMitigation {
  name: string;
  description: string;
  remediationType: string;
  /** Display labels of associated attack steps. */
  attackSteps: string[];
  /** {label, nodeId} refs for click-to-focus in the ReactFlow viewer. */
  attackStepRefs: AttackStepRef[];
  priority: number | string | null;
  techniqueId: string;
  evidence: unknown[];
  overrideStatus: string | null;
  overrideComment: string;
  overrideUpdatedAt: string;
}

/** A threat reference attached to a globally-aggregated mitigation. */
export interface MitigationThreatRef {
  id: string;
  category: string;
}

/** A mitigation deduplicated across *every* attack tree. */
export interface GlobalAggregatedMitigation extends AggregatedMitigation {
  /** Every threat that surfaced this mitigation. */
  threats: MitigationThreatRef[];
  /** Union of impacted assets across those threats. */
  affectedAssets: string[];
}

// ─── Internal helpers ─────────────────────────────────────────────

/**
 * Build a lookup from any attack-step identifier (node_id, label, description)
 * to a tuple of {label, nodeId} so the aggregator can both display a friendly
 * label *and* preserve the raw node_id needed to focus the ReactFlow viewer.
 */
function buildStepLabelMap(attackSteps: RawAttackStep[] | undefined): Map<string, AttackStepRef> {
  const labelMap = new Map<string, AttackStepRef>();
  if (!Array.isArray(attackSteps)) return labelMap;

  for (const step of attackSteps) {
    const label = step.label || step.description || step.node_id || '';
    const entry: AttackStepRef = { label, nodeId: step.node_id || '' };
    if (step.node_id) labelMap.set(step.node_id, entry);
    if (step.description) labelMap.set(step.description, entry);
    if (step.label) labelMap.set(step.label, entry);
  }
  return labelMap;
}

/**
 * Resolve a display label and the underlying node_id for an attack-step
 * reference (which may itself be the node_id, label, or description).
 */
function resolveStepRef(
  attackStepRef: string,
  labelMap: Map<string, AttackStepRef>,
): AttackStepRef {
  if (!attackStepRef) return { label: '', nodeId: '' };
  const hit = labelMap.get(attackStepRef);
  if (hit) return hit;
  return { label: attackStepRef, nodeId: '' };
}

/** Mutable accumulator for a single mitigation while aggregating. */
interface MitigationAccumulator {
  description: string;
  remediationType: string;
  attackSteps: Map<string, string>; // label → nodeId
  priority: number | string | null;
  techniqueId: string;
  evidence: unknown[];
  overrideStatus: string | null;
  overrideComment: string;
  overrideUpdatedAt: string;
}

/**
 * Aggregate and deduplicate mitigations from an attack tree.
 *
 * Collects mitigations from three sources:
 * 1. attack_steps[].mitigations - mitigations directly on attack steps
 * 2. ttc_mappings[].mitigations - mitigations nested inside MITRE technique mappings
 * 3. mitigations[] - tree-level mitigations array
 *
 * Deduplicates by mitigation name (case-sensitive), collecting all associated
 * attack step labels per mitigation.
 */
export function aggregateMitigations(
  attackTree: ReportAttackTree | null | undefined,
): AggregatedMitigation[] {
  if (!attackTree || typeof attackTree !== 'object') {
    return [];
  }

  const attackSteps = Array.isArray(attackTree.attack_steps) ? attackTree.attack_steps : [];
  const ttcMappings = Array.isArray(attackTree.ttc_mappings) ? attackTree.ttc_mappings : [];
  const treeMitigations = Array.isArray(attackTree.mitigations) ? attackTree.mitigations : [];

  const labelMap = buildStepLabelMap(attackSteps);

  // Map of mitigation name → accumulator.
  const mitigationMap = new Map<string, MitigationAccumulator>();

  function addMitigation(mit: RawMitigation | null | undefined, stepRef: AttackStepRef): void {
    if (!mit || typeof mit !== 'object') return;
    const name = mit.mitigation_text || mit.name || mit.mitigation || '';
    if (!name) return;

    const description = mit.implementation_guidance || mit.description || mit.details || '';
    const remediationType = mit.remediation_type || '';

    if (!mitigationMap.has(name)) {
      mitigationMap.set(name, {
        description,
        remediationType,
        attackSteps: new Map<string, string>(), // label → nodeId
        priority: mit.priority || null,
        techniqueId: mit.technique_id || '',
        evidence: mit.evidence || [],
        // M3 v1: user-disposition layer merged into the API response. Same
        // override applies to every duplicate, so first-seen wins.
        overrideStatus: mit.override_status || null,
        overrideComment: mit.override_comment || '',
        overrideUpdatedAt: mit.override_updated_at || '',
      });
    }

    const entry = mitigationMap.get(name)!;
    if (!entry.description && description) {
      entry.description = description;
    }
    if (!entry.remediationType && remediationType) {
      entry.remediationType = remediationType;
    }
    if (!entry.priority && mit.priority) {
      entry.priority = mit.priority;
    }
    if (!entry.techniqueId && mit.technique_id) {
      entry.techniqueId = mit.technique_id;
    }
    if (entry.evidence.length === 0 && mit.evidence && mit.evidence.length > 0) {
      entry.evidence = mit.evidence;
    }
    if (!entry.overrideStatus && mit.override_status) {
      entry.overrideStatus = mit.override_status;
      entry.overrideComment = mit.override_comment || '';
      entry.overrideUpdatedAt = mit.override_updated_at || '';
    }

    if (stepRef && stepRef.label) {
      // Prefer the first non-empty nodeId we see for a given label.
      const existing = entry.attackSteps.get(stepRef.label);
      if (!existing || (!existing && stepRef.nodeId)) {
        entry.attackSteps.set(stepRef.label, stepRef.nodeId || existing || '');
      } else if (!existing && stepRef.nodeId) {
        entry.attackSteps.set(stepRef.label, stepRef.nodeId);
      }
    }
  }

  // 1. Collect from attack_steps[].mitigations
  for (const step of attackSteps) {
    const stepRef: AttackStepRef = {
      label: step.label || step.description || step.node_id || '',
      nodeId: step.node_id || '',
    };
    if (Array.isArray(step.mitigations)) {
      for (const mit of step.mitigations) {
        addMitigation(mit, stepRef);
      }
    }
  }

  // 2. Collect from ttc_mappings[].mitigations
  // Skip STIX reference mitigations (generic MITRE controls with only name/description/relationship_description)
  for (const mapping of ttcMappings) {
    const stepRef = resolveStepRef(mapping.attack_step || '', labelMap);
    if (Array.isArray(mapping.mitigations)) {
      for (const mit of mapping.mitigations) {
        if (mit.relationship_description && !mit.priority) continue;
        addMitigation(mit, stepRef);
      }
    }
  }

  // 3. Collect from tree-level mitigations
  for (const mit of treeMitigations) {
    const stepRef = resolveStepRef(
      (typeof mit.attack_step === 'string' ? mit.attack_step : '') || '',
      labelMap,
    );
    addMitigation(mit, stepRef);
  }

  // Convert map to array.
  // attackSteps stays a string[] (labels) so existing callers + tests don't
  // break; attackStepRefs is the new {label, nodeId}[] used for click-to-focus.
  const result: AggregatedMitigation[] = [];
  for (const [name, entry] of mitigationMap) {
    const refs: AttackStepRef[] = [];
    for (const [label, nodeId] of entry.attackSteps) {
      if (label) refs.push({ label, nodeId });
    }
    result.push({
      name,
      description: entry.description,
      remediationType: entry.remediationType,
      attackSteps: refs.map((r) => r.label),
      attackStepRefs: refs,
      priority: entry.priority,
      techniqueId: entry.techniqueId,
      evidence: entry.evidence,
      overrideStatus: entry.overrideStatus,
      overrideComment: entry.overrideComment,
      overrideUpdatedAt: entry.overrideUpdatedAt,
    });
  }

  return result;
}

/**
 * Look up the affected_components / impactedAssets list for an attack tree
 * by matching its threat_id against the top-level threats list.
 *
 * Strips the trailing ``" [AttackTree…]"`` debug suffix that some legacy
 * runs leave on tree.threat_id so the match still works.
 */
export function getAffectedComponentsForTree(
  tree: ReportAttackTree | null | undefined,
  threats: ThreatRow[] | null | undefined,
): string[] {
  const matchId = (tree?.threat_id || '').replace(/ \[AttackTree.*\]/, '');
  const match = (threats || []).find(
    (t) => (t.id || t.threat_id) === matchId,
  );
  return match?.affected_components || match?.impactedAssets || [];
}

/** Mutable accumulator for {@link aggregateAllMitigations}. */
interface GlobalMitigationAccumulator {
  name: string;
  description: string;
  remediationType: string;
  priority: number | string | null;
  techniqueId: string;
  evidence: unknown[];
  attackSteps: string[];
  attackStepRefs: AttackStepRef[];
  threats: MitigationThreatRef[];
  allAffectedAssets: Set<string>;
  overrideStatus: string | null;
  overrideComment: string;
  overrideUpdatedAt: string;
}

/**
 * Globally-deduplicated mitigations across every attack tree, keyed by the
 * mitigation name. Same dedup the dedup tab uses on the summary page —
 * exporters call this so the PDF/CSV totals match what's on screen.
 *
 * Each result row carries:
 *   - description, remediationType, priority, techniqueId, evidence
 *   - attackSteps (string labels) + attackStepRefs ({label, nodeId})
 *   - overrideStatus / overrideComment / overrideUpdatedAt (when an override
 *     is recorded for that mitigation in the merged /data response)
 *   - threats: [{id, category}] — every threat that surfaced this mitigation
 *   - affectedAssets: string[]  — union of impacted assets across those threats
 */
export function aggregateAllMitigations(
  attackTrees: ReportAttackTree[] | null | undefined,
  threats: ThreatRow[] | null | undefined,
): GlobalAggregatedMitigation[] {
  const map = new Map<string, GlobalMitigationAccumulator>();

  for (const tree of attackTrees || []) {
    const threatId = tree.threat_id || '';
    const threatCategory = tree.threat_category || '';
    const affected = getAffectedComponentsForTree(tree, threats);
    const mits = aggregateMitigations(tree);

    for (const mit of mits) {
      if (!mit.name) continue;

      if (!map.has(mit.name)) {
        map.set(mit.name, {
          name: mit.name,
          description: mit.description || '',
          remediationType: mit.remediationType || '',
          priority: mit.priority,
          techniqueId: mit.techniqueId || '',
          evidence: mit.evidence || [],
          attackSteps: [...(mit.attackSteps || [])],
          attackStepRefs: [...(mit.attackStepRefs || [])],
          threats: [],
          allAffectedAssets: new Set<string>(),
          overrideStatus: mit.overrideStatus || null,
          overrideComment: mit.overrideComment || '',
          overrideUpdatedAt: mit.overrideUpdatedAt || '',
        });
      }

      const entry = map.get(mit.name)!;
      if (!entry.description && mit.description) entry.description = mit.description;
      if (!entry.remediationType && mit.remediationType) entry.remediationType = mit.remediationType;
      if (!entry.priority && mit.priority) entry.priority = mit.priority;
      if (!entry.techniqueId && mit.techniqueId) entry.techniqueId = mit.techniqueId;
      if (entry.evidence.length === 0 && mit.evidence?.length > 0) entry.evidence = mit.evidence;
      if (!entry.overrideStatus && mit.overrideStatus) {
        entry.overrideStatus = mit.overrideStatus;
        entry.overrideComment = mit.overrideComment || '';
        entry.overrideUpdatedAt = mit.overrideUpdatedAt || '';
      }
      if (threatId && !entry.threats.some((t) => t.id === threatId)) {
        entry.threats.push({ id: threatId, category: threatCategory });
      }
      for (const a of affected) entry.allAffectedAssets.add(a);
    }
  }

  return [...map.values()].map((entry): GlobalAggregatedMitigation => {
    const { allAffectedAssets, ...rest } = entry;
    return {
      ...rest,
      affectedAssets: [...allAffectedAssets],
    };
  });
}
