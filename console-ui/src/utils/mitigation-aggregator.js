/**
 * Mitigation aggregation utility.
 * Collects mitigations from all sources in an attack tree, deduplicates by name,
 * and tracks which attack steps each mitigation is associated with.
 */

/**
 * Build a lookup from attack_step identifier to a human-readable label.
 * Attack steps have node_id and description; the label used in the tree
 * is typically the short mermaid node label. Since we don't have the parsed
 * mermaid graph here, we use the attack_step's description or node_id as the label.
 *
 * @param {Array} attackSteps - The attack_steps array from the attack tree
 * @returns {Map<string, string>} Map from any identifier to the best display label
 */
function buildStepLabelMap(attackSteps) {
  const labelMap = new Map();
  if (!Array.isArray(attackSteps)) return labelMap;

  for (const step of attackSteps) {
    const label = step.label || step.description || step.node_id || '';
    if (step.node_id) {
      labelMap.set(step.node_id, label);
    }
    if (step.description) {
      labelMap.set(step.description, label);
    }
    if (step.label) {
      labelMap.set(step.label, label);
    }
  }
  return labelMap;
}

/**
 * Resolve the display label for an attack step reference.
 * @param {string} attackStepRef - The attack_step field value from a mitigation or ttc_mapping
 * @param {Map<string, string>} labelMap - Lookup map from buildStepLabelMap
 * @returns {string} The best display label, or the reference itself as fallback
 */
function resolveStepLabel(attackStepRef, labelMap) {
  if (!attackStepRef) return '';
  return labelMap.get(attackStepRef) || attackStepRef;
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
   * @param {Object} mit - Mitigation object with name and description
   * @param {string} stepLabel - The attack step label to associate
   */
  function addMitigation(mit, stepLabel) {
    if (!mit || typeof mit !== 'object') return;
    const name = mit.name || mit.mitigation || '';
    if (!name) return;

    const description = mit.description || mit.details || '';

    if (!mitigationMap.has(name)) {
      mitigationMap.set(name, {
        description,
        attackSteps: new Set(),
        priority: mit.priority || null,
        techniqueId: mit.technique_id || '',
        evidence: mit.evidence || [],
      });
    }

    const entry = mitigationMap.get(name);
    if (!entry.description && description) {
      entry.description = description;
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

    if (stepLabel) {
      entry.attackSteps.add(stepLabel);
    }
  }

  // 1. Collect from attack_steps[].mitigations
  for (const step of attackSteps) {
    const stepLabel = step.label || step.description || step.node_id || '';
    if (Array.isArray(step.mitigations)) {
      for (const mit of step.mitigations) {
        addMitigation(mit, stepLabel);
      }
    }
  }

  // 2. Collect from ttc_mappings[].mitigations
  for (const mapping of ttcMappings) {
    const stepRef = mapping.attack_step || '';
    const stepLabel = resolveStepLabel(stepRef, labelMap);
    if (Array.isArray(mapping.mitigations)) {
      for (const mit of mapping.mitigations) {
        addMitigation(mit, stepLabel);
      }
    }
  }

  // 3. Collect from tree-level mitigations
  for (const mit of treeMitigations) {
    const stepRef = mit.attack_step || '';
    const stepLabel = resolveStepLabel(stepRef, labelMap);
    addMitigation(mit, stepLabel);
  }

  // Convert map to array, converting Sets to sorted arrays
  const result = [];
  for (const [name, entry] of mitigationMap) {
    result.push({
      name,
      description: entry.description,
      attackSteps: [...entry.attackSteps].filter(Boolean),
      priority: entry.priority,
      techniqueId: entry.techniqueId,
      evidence: entry.evidence,
    });
  }

  return result;
}
