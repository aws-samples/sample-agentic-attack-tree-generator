/**
 * Build a deep link for a technique id across the three frameworks we map
 * against: MITRE ATT&CK Enterprise, MITRE ATLAS, and Wiz Cloud Threat Landscape.
 *
 * Format detection:
 *   - "AML.*"            → ATLAS                    https://atlas.mitre.org/techniques/<id>
 *   - "T1234" / "T1234.001" → ATT&CK                https://attack.mitre.org/techniques/T1234[/001]/
 *   - "lowercase-slug"   → Wiz                      https://threats.wiz.io/all-techniques/<slug>
 *
 * The Wiz check has to live before any ATT&CK fallback; otherwise slugs like
 * ``refresh-token-compromise`` get mistakenly routed to attack.mitre.org and
 * 404. Returns null when the id is empty.
 */
export function buildTechniqueUrl(techniqueId: string | null | undefined): string | null {
  if (!techniqueId) return null;
  if (techniqueId.startsWith('AML.')) {
    return `https://atlas.mitre.org/techniques/${techniqueId}`;
  }
  if (/^[a-z][a-z0-9-]+$/.test(techniqueId)) {
    return `https://threats.wiz.io/all-techniques/${techniqueId}`;
  }
  const parts = techniqueId.split('.');
  if (parts[1]) return `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`;
  return `https://attack.mitre.org/techniques/${parts[0]}/`;
}
