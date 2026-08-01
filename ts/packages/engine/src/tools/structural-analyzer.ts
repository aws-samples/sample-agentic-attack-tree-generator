/**
 * Structural Analyzer — shared read-only tool for repo exploration.
 *
 * Port of `src/threatforest/tools/structural_analyzer.py`, which sandboxes
 * `read_only_editor` (src/threatforest/modules/tools/read_only_editor.py) to the
 * target repo. The Python `read_only_editor` delegates to strands_tools.editor's
 * `view` / `find_line` commands and returns `{status, content:[{text}]}`.
 *
 * Parity notes:
 * - We reimplement ONLY the read-only `view` / `find_line` behavior of
 *   strands_tools.editor (the full editor's rich-console rendering is irrelevant
 *   to the returned dict). The returned `result` text strings match the Python
 *   editor byte-for-byte:
 *     view (file):   "File content displayed in console.\nContent: {content}"
 *     view (dir):    "Directory structure displayed in console.\nDirectory tree: {path}"
 *     find_line hit: "Line found in file.\nFile: {path}\nLine number: {n}"  (1-based)
 *     find_line miss / dir-not-found / unknown-cmd -> the same status/text the
 *     Python wrapper returns.
 * - view_range uses editor semantics: 1-based inclusive [start, end] over
 *   "\n"-split lines (start clamped to >=1 via max(0, start-1), end clamped to
 *   len(lines)).
 * - find_line is exact-substring, non-fuzzy (the analyzer never passes fuzzy);
 *   returns the 0-based first match converted to 1-based in the message.
 * - Path is sandboxed through `_validatePath([repoPath])` before any read, then
 *   the resolved real path is used for the actual file/dir access.
 */
import { existsSync, statSync, readFileSync } from 'node:fs';
import { tool } from '@strands-agents/sdk';
import { z } from 'zod';
import { _validatePath } from './sandboxed-file.js';

interface EditorResult {
  status: 'success' | 'error';
  content: { text: string }[];
}

const ALLOWED_COMMANDS = ['view', 'find_line'];

/** Mirror strands_tools.editor.find_context_line (non-fuzzy): 0-based or -1. */
function findContextLine(content: string, searchText: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i]!.includes(searchText)) return i;
  }
  return -1;
}

/** Read-only editor port: only `view` and `find_line`; returns editor-shaped dict. */
function readOnlyEditor(
  command: string,
  resolvedPath: string,
  searchText: string | null,
  viewRange: number[] | null,
): EditorResult {
  // read_only_editor whitelists only view/find_line; anything else is an error.
  if (!ALLOWED_COMMANDS.includes(command)) {
    return {
      status: 'error',
      content: [
        {
          text:
            `❌ Command '${command}' is not allowed in read-only mode.\n\n` +
            `This tool only supports read operations to prevent accidental file modifications.\n\n` +
            `Allowed commands: ${ALLOWED_COMMANDS.join(', ')}\n` +
            `Blocked commands: create, str_replace, pattern_replace, insert, undo_edit`,
        },
      ],
    };
  }

  try {
    if (command === 'view') {
      if (existsSync(resolvedPath) && statSync(resolvedPath).isFile()) {
        let content = readFileSync(resolvedPath, 'utf-8');
        if (viewRange) {
          const lines = content.split('\n');
          const start = Math.max(0, viewRange[0]! - 1);
          const end = Math.min(lines.length, viewRange[1]!);
          content = lines.slice(start, end).join('\n');
        }
        return {
          status: 'success',
          content: [{ text: `File content displayed in console.\nContent: ${content}` }],
        };
      }
      if (existsSync(resolvedPath) && statSync(resolvedPath).isDirectory()) {
        return {
          status: 'success',
          content: [
            {
              text: `Directory structure displayed in console.\nDirectory tree: ${resolvedPath}`,
            },
          ],
        };
      }
      throw new Error(`Path ${resolvedPath} does not exist`);
    }

    // command === 'find_line'
    if (!searchText) {
      throw new Error('search_text is required for find_line command');
    }
    const content = readFileSync(resolvedPath, 'utf-8');
    const lineNum = findContextLine(content, searchText);
    if (lineNum === -1) {
      return {
        status: 'success',
        content: [
          {
            text:
              `Note: Could not find '${searchText}' in ${resolvedPath} while using editor tool, ` +
              `to correct next step, here's the current content of file:\n${content}\n`,
          },
        ],
      };
    }
    return {
      status: 'success',
      content: [
        { text: `Line found in file.\nFile: ${resolvedPath}\nLine number: ${lineNum + 1}` },
      ],
    };
  } catch (e) {
    return {
      status: 'error',
      content: [{ text: `Error: ${e instanceof Error ? e.message : String(e)}` }],
    };
  }
}

const InputSchema = z.object({
  command: z.string().describe('"view" to read file/directory, "find_line" to search text.'),
  path: z.string().describe('Path to file or directory within the target repository.'),
  search_text: z
    .string()
    .default('')
    .describe('Text to search for (find_line command only).'),
  view_range: z
    .array(z.number().int())
    .nullable()
    .default(null)
    .describe('Line range [start, end] for view command.'),
});

/** Create a structural analyzer tool scoped to a specific repo. */
export function makeStructuralAnalyzer(repoPath: string) {
  return tool({
    name: 'structural_analyzer',
    description:
      'Explore repository structure and read files — read-only, scoped to target repo. ' +
      'command "view" reads a file/directory, "find_line" searches for text.',
    inputSchema: InputSchema,
    callback: (input: z.infer<typeof InputSchema>) => {
      const { command, path, search_text, view_range } = input;
      // Sandbox + resolve against the target repo (raises on out-of-bounds access).
      const resolved = _validatePath(path, [repoPath]);
      return readOnlyEditor(command, resolved, search_text || null, view_range ?? null);
    },
  });
}
