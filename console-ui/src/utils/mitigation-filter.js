/**
 * Mitigation filtering utility.
 * Pure functions for filtering aggregated mitigations by attack step or
 * mitigation name, and for extracting unique dropdown option values.
 *
 * Input shape (from aggregateMitigations):
 *   Array<{ name: string, description: string, attackSteps: string[] }>
 */

/**
 * Filter mitigations by attack step or mitigation name.
 * Only one filter is active at a time (enforced by the UI).
 *
 * @param {Array<{name: string, description: string, attackSteps: string[]}>} mitigations
 * @param {{ attackStep?: string | null, mitigationName?: string | null }} filters
 * @returns {Array<{name: string, description: string, attackSteps: string[]}>}
 */
export function filterMitigations(mitigations, filters) {
  if (!Array.isArray(mitigations)) return [];
  if (!filters || typeof filters !== 'object') return mitigations;

  const { attackStep, mitigationName } = filters;

  if (attackStep) {
    return mitigations.filter(
      (m) => Array.isArray(m.attackSteps) && m.attackSteps.includes(attackStep)
    );
  }

  if (mitigationName) {
    return mitigations.filter((m) => m.name === mitigationName);
  }

  return mitigations;
}

/**
 * Extract sorted unique attack step labels across all mitigations.
 *
 * @param {Array<{name: string, description: string, attackSteps: string[]}>} mitigations
 * @returns {string[]} Sorted array of unique attack step labels
 */
export function getUniqueAttackSteps(mitigations) {
  if (!Array.isArray(mitigations)) return [];

  const steps = new Set();
  for (const m of mitigations) {
    if (Array.isArray(m.attackSteps)) {
      for (const s of m.attackSteps) {
        if (s) steps.add(s);
      }
    }
  }
  return [...steps].sort();
}

/**
 * Extract sorted unique mitigation names.
 *
 * @param {Array<{name: string, description: string, attackSteps: string[]}>} mitigations
 * @returns {string[]} Sorted array of unique mitigation names
 */
export function getUniqueMitigationNames(mitigations) {
  if (!Array.isArray(mitigations)) return [];

  const names = new Set();
  for (const m of mitigations) {
    if (m.name) names.add(m.name);
  }
  return [...names].sort();
}
