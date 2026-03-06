"""Filesystem browser for safe server-side directory listing."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from server.models import DirectoryEntry, DirectoryListing


class PathTraversalError(Exception):
    """Raised when a path escapes the allowed roots."""


class PathNotFoundError(Exception):
    """Raised when a requested path does not exist."""


class FilesystemBrowser:
    """Provides safe directory listing constrained to allowed root paths.

    All paths are resolved (symlinks followed) before validation so that
    symbolic-link tricks cannot escape the allowed roots.
    """

    def __init__(self, allowed_roots: list[Path]) -> None:
        self.allowed_roots: list[Path] = [
            root.resolve() for root in allowed_roots
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_path(self, path: Path) -> bool:
        """Return True when *path* exists and lives under an allowed root.

        Symlinks are resolved before the check so that a symlink pointing
        outside the allowed roots is correctly rejected.

        Raises
        ------
        PathNotFoundError
            If the resolved path does not exist on disk.
        PathTraversalError
            If the resolved path is not under any allowed root.
        """
        resolved = path.resolve()

        if not resolved.exists():
            raise PathNotFoundError(f"Path does not exist: {path}")

        if not self._is_under_allowed_root(resolved):
            raise PathTraversalError(
                f"Path is outside allowed roots: {path}"
            )

        return True

    def list_directory(self, path: Path) -> DirectoryListing:
        """Return a :class:`DirectoryListing` for the given directory.

        Raises
        ------
        PathNotFoundError
            If the path does not exist.
        PathTraversalError
            If the path is outside the allowed roots.
        NotADirectoryError
            If the path exists but is not a directory.
        """
        resolved = path.resolve()

        # Validate the path first
        self.validate_path(path)

        if not resolved.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path}")

        entries: list[DirectoryEntry] = []
        for child in sorted(resolved.iterdir(), key=lambda p: p.name):
            try:
                entry = self._build_entry(child)
            except (PermissionError, OSError):
                # Skip entries we cannot stat
                continue
            entries.append(entry)

        parent_path = self._compute_parent(resolved)

        return DirectoryListing(
            current_path=str(resolved),
            parent_path=parent_path,
            entries=entries,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_under_allowed_root(self, resolved: Path) -> bool:
        """Check whether *resolved* is equal to or a child of any allowed root."""
        for root in self.allowed_roots:
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    def _compute_parent(self, resolved: Path) -> str | None:
        """Return the parent path string, or None if already at an allowed root."""
        parent = resolved.parent
        if parent == resolved:
            # Filesystem root — no parent
            return None
        if self._is_under_allowed_root(parent):
            return str(parent)
        # Parent is outside allowed roots — treat current as a root
        return None

    @staticmethod
    def _build_entry(child: Path) -> DirectoryEntry:
        """Create a DirectoryEntry from a filesystem path."""
        stat = child.stat()
        modified = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat()

        if child.is_dir():
            return DirectoryEntry(
                name=child.name,
                entry_type="directory",
                modified=modified,
            )

        return DirectoryEntry(
            name=child.name,
            entry_type="file",
            size=stat.st_size,
            modified=modified,
        )
