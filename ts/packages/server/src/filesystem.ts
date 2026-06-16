/**
 * Filesystem browser for safe server-side directory listing.
 * Port of `src/server/filesystem.py`.
 *
 * Backs `GET /api/filesystem`. All paths are resolved (symlinks followed)
 * before validation so symbolic-link tricks cannot escape the allowed roots.
 */
import { lstatSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import type { DirectoryEntry, DirectoryListing } from '@threatforest/types';

/** Raised when a path escapes the allowed roots. */
export class PathTraversalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathTraversalError';
  }
}

/** Raised when a requested path does not exist. */
export class PathNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathNotFoundError';
  }
}

/** Raised when a path exists but is not a directory. */
export class NotADirectoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotADirectoryError';
  }
}

/**
 * Resolve a path the way Python's `Path.resolve()` does: follow symlinks for
 * the parts that exist, and lexically resolve the rest. `realpathSync` throws
 * for non-existent paths, so we fall back to a lexical `resolve()`.
 */
function resolveStrictLike(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function pathExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Provides safe directory listing constrained to a set of allowed root paths.
 */
export class FilesystemBrowser {
  readonly allowedRoots: string[];

  constructor(allowedRoots: string[]) {
    this.allowedRoots = allowedRoots.map((root) => resolveStrictLike(root));
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------

  /**
   * Return `true` when `path` exists and lives under an allowed root.
   * Symlinks are resolved before the check.
   *
   * @throws PathNotFoundError if the resolved path does not exist.
   * @throws PathTraversalError if the resolved path is outside the roots.
   */
  validatePath(path: string): boolean {
    const resolved = resolveStrictLike(path);

    if (!pathExists(resolved)) {
      throw new PathNotFoundError(`Path does not exist: ${path}`);
    }

    if (!this.isUnderAllowedRoot(resolved)) {
      throw new PathTraversalError(`Path is outside allowed roots: ${path}`);
    }

    return true;
  }

  /**
   * Return a `DirectoryListing` for the given directory.
   *
   * @throws PathNotFoundError if the path does not exist.
   * @throws PathTraversalError if the path is outside the allowed roots.
   * @throws NotADirectoryError if the path exists but is not a directory.
   */
  listDirectory(path: string): DirectoryListing {
    const resolved = resolveStrictLike(path);

    // Validate the path first.
    this.validatePath(path);

    let isDir = false;
    try {
      isDir = statSync(resolved).isDirectory();
    } catch {
      isDir = false;
    }
    if (!isDir) {
      throw new NotADirectoryError(`Path is not a directory: ${path}`);
    }

    const entries: DirectoryEntry[] = [];
    const childNames = readdirSync(resolved).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    for (const name of childNames) {
      let entry: DirectoryEntry;
      try {
        entry = FilesystemBrowser.buildEntry(join(resolved, name), name);
      } catch {
        // Skip entries we cannot stat.
        continue;
      }
      entries.push(entry);
    }

    const parentPath = this.computeParent(resolved);

    return {
      current_path: resolved,
      parent_path: parentPath,
      entries,
    };
  }

  // ------------------------------------------------------------------
  // Internal helpers
  // ------------------------------------------------------------------

  /** Check whether `resolved` equals or is a child of any allowed root. */
  private isUnderAllowedRoot(resolved: string): boolean {
    for (const root of this.allowedRoots) {
      if (isRelativeTo(resolved, root)) return true;
    }
    return false;
  }

  /** Return the parent path string, or null if already at an allowed root. */
  private computeParent(resolved: string): string | null {
    const parent = dirname(resolved);
    if (parent === resolved) {
      // Filesystem root — no parent.
      return null;
    }
    if (this.isUnderAllowedRoot(parent)) {
      return parent;
    }
    // Parent is outside allowed roots — treat current as a root.
    return null;
  }

  /** Create a DirectoryEntry from a filesystem path. */
  private static buildEntry(childPath: string, name: string): DirectoryEntry {
    const st = statSync(childPath);
    const modified = new Date(st.mtimeMs).toISOString();

    if (st.isDirectory()) {
      return {
        name,
        entry_type: 'directory',
        size: null,
        modified,
      };
    }

    return {
      name,
      entry_type: 'file',
      size: st.size,
      modified,
    };
  }
}

/**
 * Equivalent of Python `Path.relative_to` success: is `child` equal to or
 * nested under `root`? Compares normalized absolute paths segment-wise so a
 * sibling like `/foo-bar` is not treated as under `/foo`.
 */
function isRelativeTo(child: string, root: string): boolean {
  if (child === root) return true;
  const rootWithSep = root.endsWith(sep) ? root : root + sep;
  return child.startsWith(rootWithSep);
}
