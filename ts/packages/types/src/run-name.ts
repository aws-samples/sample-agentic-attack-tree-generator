/**
 * Display labels are independent of provider and opaque storage identifiers.
 * UTC makes the persisted fallback identical in API responses and exports.
 */
export function runDisplayName(applicationName: string | null | undefined, createdAt: string): string {
  const name = applicationName?.trim() || 'Threat model';
  const date = new Date(createdAt);
  if (!Number.isFinite(date.getTime())) return name;
  const stamp = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'UTC', day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).format(date);
  return `${name} · ${stamp} UTC`;
}
