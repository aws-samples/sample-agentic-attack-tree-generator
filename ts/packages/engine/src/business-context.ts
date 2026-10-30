import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { BusinessContextSchema, type BusinessContext } from '@threatforest/types';

const SNAPSHOT_FILE = 'business_context.snapshot.json';

/** These fields describe user intent; inferred scanner fields must not replace them. */
export function preserveBusinessContext(
  data: Record<string, unknown>,
  context: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ...data,
    business_context: structuredClone(context),
    ...(Array.isArray(context['regulatory_frameworks'])
      ? { compliance_requirements: [...new Set([
          ...context['regulatory_frameworks'],
          ...(Array.isArray(data['compliance_requirements']) ? data['compliance_requirements'] : []),
        ])] }
      : {}),
    ...(typeof context['data_sensitivity'] === 'string'
      ? { data_sensitivity: context['data_sensitivity'] }
      : {}),
    ...(Array.isArray(context['cia_priority'])
      ? { cia_priority: [...context['cia_priority']], main_cia_risk: context['cia_priority'][0] }
      : {}),
  };
}

/** A checkpointed snapshot makes local resumes and hosted stage retries consistent. */
export function seedBusinessContext(stateDir: string, supplied?: BusinessContext): void {
  const snapshotFile = join(stateDir, SNAPSHOT_FILE);
  const saved = existsSync(snapshotFile)
    ? BusinessContextSchema.parse(JSON.parse(readFileSync(snapshotFile, 'utf8')))
    : undefined;
  if (saved !== undefined && supplied !== undefined && !isDeepStrictEqual(saved, supplied)) {
    throw new Error('Business context differs from the immutable run snapshot');
  }
  const context = saved ?? supplied;
  if (context === undefined) return;
  mkdirSync(stateDir, { recursive: true });
  if (saved === undefined) {
    writeFileSync(snapshotFile, JSON.stringify(context, null, 2), { flag: 'wx' });
  }
  const stateFile = join(stateDir, 'scanner_context.json');
  // Completed scanner/review output is checkpointed. Explicit human corrections
  // made during this run must survive later stage invocations and resume.
  if (saved !== undefined && existsSync(stateFile)) return;
  const state = existsSync(stateFile) ? JSON.parse(readFileSync(stateFile, 'utf8')) : {};
  if (state === null || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error('Scanner context must be a JSON object');
  }
  writeFileSync(stateFile, JSON.stringify(preserveBusinessContext(state, context), null, 2));
}
