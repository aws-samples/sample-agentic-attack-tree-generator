/**
 * Risk-posture + coverage derivations for the Threat Model Summary dashboard.
 *
 * All inputs come straight from the merged `/data` report bundle the summary
 * page already fetches — no new endpoint. Severity is read from each threat's
 * `priority` (`high` | `medium` | `low`, matching the engine output) with a
 * tolerant fallback so legacy/numeric priorities still bucket sensibly.
 */

import type { ReportAttackTree, ThreatRow } from './mitigation-aggregator';

export type Severity = 'high' | 'medium' | 'low';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export interface SeverityCounts {
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface TopThreat {
  /** Stable threat id (e.g. "TS001") used for the deep-link label. */
  id: string;
  /** Zero-based index into attack_trees — the dashboard deep-links by index. */
  index: number;
  title: string;
  severity: Severity;
}

export interface CoverageStats {
  /** Attack trees that have at least one mitigation. */
  treesCovered: number;
  treesTotal: number;
  /** Attack steps defended by at least one mitigation. */
  stepsCovered: number;
  stepsTotal: number;
  /** 0–100, rounded. Step-level when steps exist, else tree-level. */
  percent: number;
}

const NUMERIC_HIGH = 2; // priority <= 2 → high (1=critical, 2=high in numeric scales)

/** Normalise any priority value to a high/medium/low severity bucket. */
export function toSeverity(priority: unknown): Severity {
  if (typeof priority === 'number') {
    if (priority <= NUMERIC_HIGH) return 'high';
    if (priority === 3) return 'medium';
    return 'low';
  }
  const s = String(priority ?? '').trim().toLowerCase();
  if (s === 'high' || s === 'critical' || s === 'p1' || s === 'p2') return 'high';
  if (s === 'medium' || s === 'med' || s === 'moderate' || s === 'p3') return 'medium';
  return 'low';
}

/** Count threats by severity. Prefers the top-level `threats` list, falling
 *  back to per-tree `priority` when the threats list is absent. */
export function severityCounts(
  threats: ThreatRow[],
  attackTrees: ReportAttackTree[],
): SeverityCounts {
  const source: ReadonlyArray<Record<string, unknown>> =
    threats && threats.length > 0
      ? (threats as ReadonlyArray<Record<string, unknown>>)
      : (attackTrees as ReadonlyArray<Record<string, unknown>>);
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0, total: 0 };
  for (const t of source) {
    counts[toSeverity(t.priority)] += 1;
    counts.total += 1;
  }
  return counts;
}

/**
 * Overall risk posture from severity mix.
 *  - critical: 5+ high-severity threats
 *  - high:     1+ high
 *  - medium:   no high but 1+ medium
 *  - low:      only low-severity threats
 *  - none:     no threats at all
 */
export function riskLevel(counts: SeverityCounts): RiskLevel {
  if (counts.total === 0) return 'none';
  if (counts.high >= 5) return 'critical';
  if (counts.high > 0) return 'high';
  if (counts.medium > 0) return 'medium';
  return 'low';
}

/** The N highest-severity threats, for the "top critical" call-out. */
export function topThreats(
  threats: ThreatRow[],
  attackTrees: ReportAttackTree[],
  limit = 3,
): TopThreat[] {
  const rank: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  const rows = (attackTrees || []).map((tree, index) => {
    const threat = threats?.[index];
    const severity = toSeverity(
      (threat as { priority?: unknown } | undefined)?.priority ?? tree.priority,
    );
    const id =
      (threat as { id?: string } | undefined)?.id ||
      tree.threat_id ||
      `TS${String(index + 1).padStart(3, '0')}`;
    const title =
      (threat as { title?: string } | undefined)?.title ||
      tree.threat_statement ||
      tree.threat_description ||
      tree.threat_category ||
      id;
    return { id, index, title, severity };
  });
  return rows
    .sort((a, b) => rank[a.severity] - rank[b.severity])
    .slice(0, limit);
}

/** Mitigation coverage across trees and attack steps. */
export function coverageStats(attackTrees: ReportAttackTree[]): CoverageStats {
  const treesTotal = attackTrees.length;
  let treesCovered = 0;
  let stepsTotal = 0;
  let stepsCovered = 0;

  for (const tree of attackTrees) {
    const mitigations = tree.mitigations || [];
    if (mitigations.length > 0) treesCovered += 1;

    const steps = tree.attack_steps || [];
    stepsTotal += steps.length;

    // A step is covered if any mitigation targets it directly or via
    // `also_applies_to`. Mitigation shape uses `attack_step` for the id.
    const covered = new Set<string>();
    for (const m of mitigations) {
      const direct = (m as { attack_step?: string }).attack_step;
      if (direct) covered.add(direct);
      for (const a of ((m as { also_applies_to?: string[] }).also_applies_to || [])) {
        covered.add(a);
      }
    }
    for (const step of steps) {
      // Engine attack-step ids live in `node_id` (e.g. "S0"); the mitigation's
      // `attack_step` references that. Fall back to `id` for older bundles.
      const sid =
        (step as { node_id?: string }).node_id ?? (step as { id?: string }).id;
      if (sid && covered.has(sid)) stepsCovered += 1;
    }
  }

  const percent =
    stepsTotal > 0
      ? Math.round((stepsCovered / stepsTotal) * 100)
      : treesTotal > 0
        ? Math.round((treesCovered / treesTotal) * 100)
        : 0;

  return { treesCovered, treesTotal, stepsCovered, stepsTotal, percent };
}
