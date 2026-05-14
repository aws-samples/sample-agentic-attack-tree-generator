/**
 * Mitigation aggregation utility.
 * Collects mitigations from all sources in an attack tree, deduplicates by name,
 * and tracks which attack steps each mitigation is associated with.
 */

/**
 * Build a lookup from any attack-step identifier (node_id, label, description)
 * to a tuple of {label, nodeId} so the aggregator can both display a friendly
 * label *and* preserve the raw node_id needed to focus the ReactFlow viewer.
 *
 * @param {Array} attackSteps - The attack_steps array from the attack tree
 * @returns {Map<string, {label: string, nodeId: string}>}
 */
function buildStepLabelMap(attackSteps) {
  const labelMap = new Map();
  if (!Array.isArray(attackSteps)) return labelMap;

  for (const step of attackSteps) {
    const label = step.label || step.description || step.node_id || '';
    const entry = { label, nodeId: step.node_id || '' };
    if (step.node_id) labelMap.set(step.node_id, entry);
    if (step.description) labelMap.set(step.description, entry);
    if (step.label) labelMap.set(step.label, entry);
  }
  return labelMap;
}

/**
 * Resolve a display label and the underlying node_id for an attack-step
 * reference (which may itself be the node_id, label, or description).
 *
 * @param {string} attackStepRef
 * @param {Map<string, {label: string, nodeId: string}>} labelMap
 * @returns {{label: string, nodeId: string}}
 */
function resolveStepRef(attackStepRef, labelMap) {
  if (!attackStepRef) return { label: '', nodeId: '' };
  const hit = labelMap.get(attackStepRef);
  if (hit) return hit;
  return { label: attackStepRef, nodeId: '' };
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
 *
 * @param {Object} attackTree - The attack tree object with attack_steps, ttc_mappings, mitigations
 * @returns {Array<{name: string, description: string, attackSteps: string[]}>}
 */
export function aggregateMitigations(attackTree) {
  if (!attackTree || typeof attackTree !== 'object') {
    return [];
  }

  const attackSteps = Array.isArray(attackTree.attack_steps) ? attackTree.attack_steps : [];
  const ttcMappings = Array.isArray(attackTree.ttc_mappings) ? attackTree.ttc_mappings : [];
  const treeMitigations = Array.isArray(attackTree.mitigations) ? attackTree.mitigations : [];

  const labelMap = buildStepLabelMap(attackSteps);

  // Map of mitigation name → { description, attackSteps: Set<string> }
  const mitigationMap = new Map();

  /**
   * Add a mitigation to the aggregation map.
   * @param {Object} mit
   * @param {{label: string, nodeId: string}} stepRef
   */
  function addMitigation(mit, stepRef) {
    if (!mit || typeof mit !== 'object') return;
    const name = mit.mitigation_text || mit.name || mit.mitigation || '';
    if (!name) return;

    const description = mit.implementation_guidance || mit.description || mit.details || '';
    const remediationType = mit.remediation_type || '';

    if (!mitigationMap.has(name)) {
      mitigationMap.set(name, {
        description,
        remediationType,
        attackSteps: new Map(),  // label → nodeId
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

    const entry = mitigationMap.get(name);
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
    const stepRef = {
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
    const stepRef = resolveStepRef(mit.attack_step || '', labelMap);
    addMitigation(mit, stepRef);
  }

  // Convert map to array.
  // attackSteps stays a string[] (labels) so existing callers + tests don't
  // break; attackStepRefs is the new {label, nodeId}[] used for click-to-focus.
  const result = [];
  for (const [name, entry] of mitigationMap) {
    const refs = [];
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
export function getAffectedComponentsForTree(tree, threats) {
  const matchId = (tree?.threat_id || '').replace(/ \[AttackTree.*\]/, '');
  const match = (threats || []).find(
    (t) => (t.id || t.threat_id) === matchId
  );
  return match?.affected_components || match?.impactedAssets || [];
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
export function aggregateAllMitigations(attackTrees, threats) {
  const map = new Map();

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
          allAffectedAssets: new Set(),
          overrideStatus: mit.overrideStatus || null,
          overrideComment: mit.overrideComment || '',
          overrideUpdatedAt: mit.overrideUpdatedAt || '',
        });
      }

      const entry = map.get(mit.name);
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

  return [...map.values()].map((entry) => ({
    ...entry,
    affectedAssets: [...entry.allAffectedAssets],
    allAffectedAssets: undefined,
  }));
}
