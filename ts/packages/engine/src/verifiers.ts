/**
 * Deterministic output verifiers — ports of
 * `agents/scanner/verifier.py` and `agents/threat/verifier.py`.
 *
 * These gate the graph's retry edges: each returns [passed, feedback]. The
 * orchestrator reads these to decide pass→next vs fail→retry (see graph.ts;
 * note the TS Graph AND-edge remodel of the Python OR-edge retry loops).
 *
 * mitigation + report verifiers live with their stages (mitigation.ts / report.ts).
 */
import { LocalFilesystemWorkspace } from './workspace.js';

const SCANNER_REQUIRED_FIELDS = [
  'tech_stack',
  'cloud_provider',
  'services',
  'auth_mechanisms',
  'files_analyzed',
  'file_guide',
];

export interface VerifyThreatOutputOptions {
  /**
   * Supplied-threat mode validates extraction/provenance without applying the
   * generated-mode minimum count, which would pressure retries to invent data.
   */
  authoritative?: boolean;
}

function isEmpty(v: unknown): boolean {
  if (v === undefined || v === null || v === '') return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'object') return Object.keys(v as object).length === 0;
  return false;
}

/** Port of verify_scanner_output. */
export function verifyScannerOutput(ws: LocalFilesystemWorkspace): [boolean, string] {
  if (!ws.exists('scanner_context.json')) return [false, 'State file does not exist'];
  let data: Record<string, unknown>;
  try {
    data = ws.readJson('scanner_context.json');
  } catch (e) {
    return [false, `State file is not valid JSON: ${(e as Error).message}`];
  }
  const missing = SCANNER_REQUIRED_FIELDS.filter((f) => isEmpty(data[f]));
  if (missing.length) return [false, `Missing or empty fields: ${missing.join(', ')}`];
  if (isEmpty(data['files_analyzed'])) {
    return [false, 'No files were analyzed — scanner may have failed to read the repo'];
  }
  if (isEmpty(data['tech_stack'])) {
    return [false, 'Tech stack is empty — scanner did not identify any technologies'];
  }
  return [true, 'Context is complete'];
}

/** Port of verify_threat_output, with an authoritative supplied-threat mode. */
export function verifyThreatOutput(
  ws: LocalFilesystemWorkspace,
  options: VerifyThreatOutputOptions = {},
): [boolean, string] {
  if (!ws.exists('threats.json')) return [false, 'State file does not exist'];
  let data: Record<string, unknown>;
  try {
    data = ws.readJson('threats.json');
  } catch (e) {
    return [false, `State file is not valid JSON: ${(e as Error).message}`];
  }
  const rawThreats = data['threats'];
  if (!Array.isArray(rawThreats)) {
    return [false, "State file field 'threats' must be an array"];
  }
  const threats = rawThreats as Array<Record<string, unknown>>;
  const minimum = 1;
  if (threats.length < minimum) {
    if (options.authoritative) {
      return [false, 'No explicit threats were found in the authoritative input files'];
    }
    return [false, 'No supported threats were generated; review the source evidence and scope'];
  }
  for (let i = 0; i < threats.length; i++) {
    const t = threats[i]!;
    if (!t['title'] && !t['description']) return [false, `Threat ${i} has no title or description`];
    if (isEmpty(t['affected_components'])) {
      return [
        false,
        `Threat '${t['id'] ?? i}' has no affected_components — threats must be tied to specific components`,
      ];
    }
    if (!t['priority'] && !t['severity']) {
      return [
        false,
        `Threat '${t['id'] ?? i}' has no priority — must be 'critical', 'high', 'medium', or 'low'`,
      ];
    }
    if (options.authoritative && t['threat_source'] !== 'user_provided') {
      return [
        false,
        `Threat '${t['id'] ?? i}' is not marked as user_provided authoritative input`,
      ];
    }
  }
  return [true, options.authoritative ? 'Authoritative threats are valid' : 'Threats are valid'];
}
