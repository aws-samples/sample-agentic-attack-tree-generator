/**
 * Sandboxed file read/write tools with per-agent path restrictions.
 *
 * Faithful port of `src/threatforest/tools/sandboxed_file.py`.
 *
 * Parity notes:
 * - `_validate_path` is reproduced exactly: relative paths are resolved against
 *   each allowed prefix (first existing candidate wins; else first prefix that is
 *   a directory is used as the base), then the resolved real path must fall
 *   within one of the allowed prefixes (via realpath relative-to check). Symlink
 *   resolution uses fs.realpathSync to mirror Python's Path.resolve().
 * - The 200KB MAX_FILE_SIZE cap, ranged reads (offset/limit), large-file
 *   head(100)+tail(20) preview, directory listing, and the per-tool read cache
 *   all match the Python byte-for-byte, including the bracketed status strings.
 * - CAVEAT: the PDF/Office DOCUMENT_EXTENSIONS branch is NOT ported for v1. When
 *   a document extension is requested, we return a clear string explaining that
 *   binary document read is not yet supported in the TS port (instead of the
 *   Bedrock `{document:{...bytes}}` content block the Python emits).
 */
import { existsSync, statSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { mkdirSync, appendFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve as pathResolve, basename, extname, relative } from 'node:path';
import { tool, type JSONValue } from '@strands-agents/sdk';
import { z } from 'zod';
import { RemediationType } from '@threatforest/types';

const DOCUMENT_EXTENSIONS = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv']);
const MAX_FILE_SIZE = 200_000; // ~200KB / ~50K tokens — prevent giant files from flooding the context

/** True iff `child` is the same as `prefix` or nested beneath it (mirrors Path.is_relative_to). */
function isRelativeTo(child: string, prefix: string): boolean {
  const rel = relative(prefix, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/** Resolve a real path, falling back to lexical resolution when the path does not yet exist. */
function realResolve(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return pathResolve(p);
  }
}

/**
 * Resolve `path` and check it falls within allowed prefixes.
 * Throws on access outside the sandbox (matches Python's PermissionError).
 */
function validatePath(path: string, allowedPrefixes: string[]): string {
  let p = path;
  if (!isAbsolute(p)) {
    // Resolve relative paths against each allowed prefix until one works.
    let matched = false;
    for (const prefix of allowedPrefixes) {
      const candidate = pathResolve(realResolve(prefix), path);
      if (existsSync(candidate)) {
        p = candidate;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // No match found, try first directory prefix as default base.
      for (const prefix of allowedPrefixes) {
        const base = realResolve(prefix);
        if (existsSync(base) && statSync(base).isDirectory()) {
          p = pathResolve(base, path);
          break;
        }
      }
    }
  }
  const resolved = realResolve(p);
  for (const prefix of allowedPrefixes) {
    if (isRelativeTo(resolved, realResolve(prefix))) {
      return resolved;
    }
  }
  throw new Error(`Access denied: ${resolved} is outside allowed paths`);
}

const InputSchema = z.object({
  path: z.string().describe('Path to the file to read (can be relative to the project root).'),
  offset: z
    .number()
    .int()
    .default(0)
    .describe('Line number to start reading from (0-based, default: start of file).'),
  limit: z
    .number()
    .int()
    .default(0)
    .describe('Maximum number of lines to return (default: 0 = up to the size cap).'),
});

/** Split into lines keeping line endings, matching Python str.splitlines(keepends=True). */
function splitlinesKeepends(content: string): string[] {
  // Match on \n, \r\n, or a trailing \r; keep the terminator attached to each line.
  const out: string[] = [];
  const re = /[^\n\r]*(?:\r\n|\r|\n|$)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (m[0] === '' && m.index === content.length) break; // avoid trailing empty match
    out.push(m[0]);
    if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-length loops
  }
  return out;
}

/** Number formatting matching Python's f"{n:,}" (comma thousands separators). */
function commaGroup(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * Create a file_read tool restricted to specific paths.
 *
 * Relative paths are automatically resolved against the allowed directories.
 */
export function makeSandboxedFileRead(allowedReadPaths: string[]) {
  const cache = new Map<string, JSONValue>();

  return tool({
    name: 'sandboxed_file_read',
    description:
      'Read file content — restricted to allowed paths for this agent. For large files, only ' +
      'the first portion is returned. Use offset/limit to read specific sections.',
    inputSchema: InputSchema,
    callback: (input: z.infer<typeof InputSchema>): JSONValue => {
      const { path, offset, limit } = input;
      const resolved = validatePath(path, allowedReadPaths);
      // For ranged reads, use a cache key that includes the range.
      const cacheKey = `${resolved}:${offset}:${limit}`;
      if (cache.has(cacheKey)) {
        const cached = cache.get(cacheKey);
        if (typeof cached === 'object' && cached !== null) {
          return cached;
        }
        return `[CACHED — already read this range]\n${cached as string}`;
      }

      const st = statSync(resolved);
      if (st.isDirectory()) {
        const entries = readdirSync(resolved).sort();
        const result = entries.join('\n');
        cache.set(cacheKey, result);
        return result;
      }

      if (DOCUMENT_EXTENSIONS.has(extname(resolved).toLowerCase())) {
        // CAVEAT: binary document ingestion is not ported in v1.
        const result =
          `[binary document read not yet supported in TS port] ${basename(resolved)} ` +
          `(${extname(resolved).toLowerCase().replace(/^\./, '')}). ` +
          'Use the Python pipeline for PDF/Office document extraction.';
        cache.set(cacheKey, result);
        return result;
      }

      const content = readFileSync(resolved, 'utf-8');
      const lines = splitlinesKeepends(content);
      const totalLines = lines.length;
      const fileSize = st.size;

      // Ranged read — agent is drilling into a specific section.
      if (offset > 0 || limit > 0) {
        let sliced = lines.slice(offset);
        if (limit > 0) {
          sliced = sliced.slice(0, limit);
        }
        let result = sliced.join('');
        if (result.length > MAX_FILE_SIZE) {
          result = result.slice(0, MAX_FILE_SIZE);
          const shown = (result.match(/\n/g) ?? []).length;
          result +=
            `\n\n[TRUNCATED at ${Math.trunc(MAX_FILE_SIZE / 1000)}KB — showing ~${shown} lines ` +
            `starting at line ${offset}. Use offset=${offset + shown} to continue.]`;
        } else {
          result += `\n\n[Lines ${offset}-${offset + sliced.length} of ${totalLines}]`;
        }
        cache.set(cacheKey, result);
        return result;
      }

      // Full read — small files return as-is.
      if (fileSize <= MAX_FILE_SIZE) {
        cache.set(cacheKey, content);
        return content;
      }

      // Large file — return a smart preview (head + tail + metadata).
      const HEAD_LINES = 100;
      const TAIL_LINES = 20;
      const head = lines.slice(0, HEAD_LINES).join('');
      const tail = lines.slice(-TAIL_LINES).join('');
      const result =
        `[LARGE FILE: ${commaGroup(fileSize)} bytes, ${totalLines} lines — showing preview]\n` +
        `--- First ${HEAD_LINES} lines ---\n` +
        `${head}\n` +
        `--- Last ${TAIL_LINES} lines ---\n` +
        `${tail}\n` +
        `[Use offset and limit to read specific sections, e.g. offset=100 limit=200]`;
      cache.set(cacheKey, result);
      return result;
    },
  });
}

const WriteInputSchema = z.object({
  path: z.string().describe('Path to the file to write.'),
  content: z.string().describe('Content to write.'),
  mode: z
    .string()
    .default('overwrite')
    .describe('"overwrite" (default) replaces file, "append" adds to end.'),
});

/** Create a file_write tool restricted to specific paths. */
export function makeSandboxedFileWrite(allowedWritePaths: string[]) {
  return tool({
    name: 'sandboxed_file_write',
    description: 'Write file content — restricted to allowed paths for this agent.',
    inputSchema: WriteInputSchema,
    callback: (input: z.infer<typeof WriteInputSchema>): string => {
      const { path, content, mode } = input;
      const resolved = validatePath(path, allowedWritePaths);
      mkdirSync(dirname(resolved), { recursive: true });
      if (mode === 'append') {
        appendFileSync(resolved, content);
      } else {
        writeFileSync(resolved, content);
      }
      return `Written ${content.length} bytes to ${resolved} (${mode})`;
    },
  });
}

/**
 * Tool-input schema for a single mitigation, matching the Python `Mitigation`
 * pydantic in sandboxed_file.py (NOT the looser domain MitigationSchema in
 * @threatforest/types). attack_step_id / technique_id / mitigation_text /
 * implementation_guidance / remediation_type / priority / evidence are required;
 * control_candidates / selected_control_id / also_applies_to default to empty.
 */
export const EvidenceToolSchema = z.object({
  source_type: z.string(),
  source_ref: z.string(),
  excerpt: z.string(),
  relevance: z.string(),
});

export const MitigationToolSchema = z.object({
  attack_step_id: z.string(),
  technique_id: z.string(),
  mitigation_text: z.string(),
  implementation_guidance: z.string(),
  remediation_type: RemediationType,
  // Python types this as list[dict] with no nested schema; keep it permissive.
  control_candidates: z.array(z.record(z.string(), z.unknown())).default([]),
  selected_control_id: z.string().default(''),
  priority: z.number().int(),
  evidence: z.array(EvidenceToolSchema),
  also_applies_to: z.array(z.string()).default([]),
});
export type MitigationToolInput = z.infer<typeof MitigationToolSchema>;

const StoreMitigationsInputSchema = z.object({
  mitigations: z
    .array(MitigationToolSchema)
    .describe('List of mitigation objects. Every field is required and validated.'),
});

/** Create a store_mitigations tool that validates and writes mitigations. */
export function makeStoreMitigations(outputPath: string) {
  return tool({
    name: 'store_mitigations',
    description:
      'Store all mitigations at once. Each mitigation is validated against a schema before writing.',
    inputSchema: StoreMitigationsInputSchema,
    callback: (input: z.infer<typeof StoreMitigationsInputSchema>): string => {
      const { mitigations } = input;
      mkdirSync(dirname(outputPath), { recursive: true });
      // Strands validates via Zod then passes plain objects, mirroring Python's
      // pydantic-validate-then-model_dump path; persist as {"mitigations":[...]}.
      const data = { mitigations };
      writeFileSync(outputPath, JSON.stringify(data, null, 2));
      return `Stored ${mitigations.length} mitigations to ${outputPath}`;
    },
  });
}

// Exported for reuse by the structural analyzer (mirrors Python's import of _validate_path).
export { validatePath as _validatePath };
