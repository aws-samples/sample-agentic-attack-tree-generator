/**
 * Single source of truth for the mitigation-status enum used by the
 * editable-mitigations feature (M3 v1).
 *
 * Keep these values in sync with src/server/models.py::MitigationStatus.
 */

export const MITIGATION_STATUSES = [
  { value: 'already_implemented', label: 'Already implemented', color: 'green' },
  { value: 'in_progress',         label: 'In progress',         color: 'blue' },
  { value: 'accepted_risk',       label: 'Accepted risk',       color: 'severity-medium' },
  { value: 'not_relevant',        label: 'Not relevant',        color: 'grey' },
  { value: 'wont_do',             label: "Won't do",            color: 'red' },
];

const STATUS_BY_VALUE = new Map(MITIGATION_STATUSES.map((s) => [s.value, s]));

/** Return the {value, label, color} record for a status, or null if unknown. */
export function statusInfo(value) {
  if (!value) return null;
  return STATUS_BY_VALUE.get(value) || null;
}

/** Cloudscape Select option list, with an explicit "no status" option at top. */
export const STATUS_OPTIONS = [
  { value: '', label: 'Open (no status)' },
  ...MITIGATION_STATUSES.map(({ value, label }) => ({ value, label })),
];

/**
 * Statuses that visually deprioritise the row — the work has been resolved
 * one way or another. Open and In progress remain full-strength.
 */
export const TERMINAL_STATUSES = new Set([
  'already_implemented',
  'not_relevant',
  'wont_do',
  'accepted_risk',
]);

export function isTerminal(status) {
  return TERMINAL_STATUSES.has(status);
}
