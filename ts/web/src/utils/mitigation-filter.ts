/**
 * Mitigation filtering utility.
 * Pure functions for filtering aggregated mitigations by attack step or
 * mitigation name, and for extracting unique dropdown option values.
 *
 * Input shape (from aggregateMitigations):
 *   Array<{ name: string, description: string, attackSteps: string[] }>
 */

/** The minimal mitigation shape these filters read. */
export interface FilterableMitigation {
  name: string;
  attackSteps: string[];
  [key: string]: unknown;
}

/** Active filter selection — only one is honoured at a time. */
export interface MitigationFilters {
  attackStep?: string | null;
  mitigationName?: string | null;
}

/**
 * Filter mitigations by attack step or mitigation name.
 * Only one filter is active at a time (enforced by the UI).
 */
export function filterMitigations<T extends FilterableMitigation>(
  mitigations: T[] | null | undefined,
  filters: MitigationFilters | null | undefined,
): T[] {
  if (!Array.isArray(mitigations)) return [];
  if (!filters || typeof filters !== 'object') return mitigations;

  const { attackStep, mitigationName } = filters;

  if (attackStep) {
    return mitigations.filter(
      (m) => Array.isArray(m.attackSteps) && m.attackSteps.includes(attackStep),
    );
  }

  if (mitigationName) {
    return mitigations.filter((m) => m.name === mitigationName);
  }

  return mitigations;
}

/**
 * Extract sorted unique attack step labels across all mitigations.
 */
export function getUniqueAttackSteps(
  mitigations: FilterableMitigation[] | null | undefined,
): string[] {
  if (!Array.isArray(mitigations)) return [];

  const steps = new Set<string>();
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
 */
export function getUniqueMitigationNames(
  mitigations: FilterableMitigation[] | null | undefined,
): string[] {
  if (!Array.isArray(mitigations)) return [];

  const names = new Set<string>();
  for (const m of mitigations) {
    if (m.name) names.add(m.name);
  }
  return [...names].sort();
}
