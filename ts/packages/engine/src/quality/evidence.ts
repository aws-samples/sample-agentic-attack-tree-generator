import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

type Json = Record<string, unknown>;
export interface VerifiedEvidence {
  source_ref: string;
  source_sha256: string;
  line_start: number;
  line_end: number;
}
export type EvidenceResolver = (evidence: Json) => VerifiedEvidence | null;

function contained(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Only current source files can substantiate application claims. Generated
 * scanner/tree output and technique IDs are not independent source evidence.
 * Never follow a citation outside the source root, including through symlinks.
 */
export function createSourceEvidenceResolver(
  repoPath: string,
  excludedPaths: readonly string[] = [],
): EvidenceResolver {
  return (evidence) => {
    if (
      !['repository', 'project_file', 'source', 'normalized_evidence'].includes(String(evidence['source_type'])) ||
      typeof evidence['source_ref'] !== 'string' ||
      typeof evidence['excerpt'] !== 'string' ||
      !evidence['excerpt'].trim()
    ) return null;
    try {
      const root = realpathSync(repoPath);
      const file = realpathSync(resolve(root, evidence['source_ref']));
      const sourceRef = relative(root, file);
      const excluded = excludedPaths.some((path) => {
        let canonical = resolve(path);
        try { canonical = realpathSync(path); } catch { /* absent output directory */ }
        return contained(canonical, file);
      });
      if (
        excluded || !sourceRef || !contained(root, file) ||
        sourceRef.split(/[\\/]/).includes('.threatforest') ||
        !statSync(file).isFile()
      ) return null;
      const body = readFileSync(file);
      const content = new TextDecoder('utf-8', { fatal: true }).decode(body);
      if (content.includes('\0')) return null;
      // Permit platform line endings, but not paraphrases or invented quotes.
      const normalized = content.replace(/\r\n?/g, '\n');
      const excerpt = evidence['excerpt'].replace(/\r\n?/g, '\n').trim();
      const offset = normalized.indexOf(excerpt);
      if (offset < 0) return null;
      const digest = createHash('sha256').update(body).digest('hex');
      const lineStart = normalized.slice(0, offset).split('\n').length;
      const lineEnd = lineStart + excerpt.split('\n').length - 1;
      if (
        (evidence['source_sha256'] !== undefined && evidence['source_sha256'] !== digest) ||
        (evidence['line_start'] !== undefined && evidence['line_start'] !== lineStart) ||
        (evidence['line_end'] !== undefined && evidence['line_end'] !== lineEnd)
      ) return null;
      return { source_ref: sourceRef, source_sha256: digest, line_start: lineStart, line_end: lineEnd };
    } catch {
      return null;
    }
  };
}
