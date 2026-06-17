/**
 * Single source of truth for the mitigation-status enum used by the
 * editable-mitigations feature (M3 v1).
 *
 * Keep these values in sync with src/server/models.py::MitigationStatus
 * (and the `MitigationStatus` Zod enum in @threatforest/types).
 */

/** A concrete (non-empty) mitigation status value. */
export type MitigationStatusValue =
  | 'already_implemented'
  | 'in_progress'
  | 'accepted_risk'
  | 'not_relevant'
  | 'wont_do';

/** The {value, label, color} record describing a single status. */
export interface StatusInfo {
  value: MitigationStatusValue;
  label: string;
  color: string;
}

export const MITIGATION_STATUSES: readonly StatusInfo[] = [
  { value: 'already_implemented', label: 'Already implemented', color: 'green' },
  { value: 'in_progress',         label: 'In progress',         color: 'blue' },
  { value: 'accepted_risk',       label: 'Accepted risk',       color: 'severity-medium' },
  { value: 'not_relevant',        label: 'Not relevant',        color: 'grey' },
  { value: 'wont_do',             label: "Won't do",            color: 'red' },
];

const STATUS_BY_VALUE: Map<string, StatusInfo> = new Map(
  MITIGATION_STATUSES.map((s) => [s.value, s]),
);

/** Return the {value, label, color} record for a status, or null if unknown. */
export function statusInfo(value: string | null | undefined): StatusInfo | null {
  if (!value) return null;
  return STATUS_BY_VALUE.get(value) || null;
}

/** A Cloudscape Select option ({value, label}). */
export interface StatusOption {
  value: string;
  label: string;
}

/** Cloudscape Select option list, with an explicit "no status" option at top. */
export const STATUS_OPTIONS: readonly StatusOption[] = [
  { value: '', label: 'Open (no status)' },
  ...MITIGATION_STATUSES.map(({ value, label }) => ({ value, label })),
];

/**
 * Statuses that visually deprioritise the row — the work has been resolved
 * one way or another. Open and In progress remain full-strength.
 */
export const TERMINAL_STATUSES: ReadonlySet<string> = new Set([
  'already_implemented',
  'not_relevant',
  'wont_do',
  'accepted_risk',
]);

export function isTerminal(status: string | null | undefined): boolean {
  return status != null && TERMINAL_STATUSES.has(status);
}
