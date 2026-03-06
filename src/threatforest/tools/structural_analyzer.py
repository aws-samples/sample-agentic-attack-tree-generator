"""Structural Analyzer — shared read-only tool for repo exploration.

Wraps file_read + read_only_editor with path sandboxing so agents
can explore the target repo without accessing anything outside it.
"""

from strands import tool

from .sandboxed_file import _validate_path


def make_structural_analyzer(repo_path: str):
    """Create a structural analyzer tool scoped to a specific repo."""

    @tool
    def structural_analyzer(
        command: str,
        path: str,
        search_text: str = "",
        view_range: list[int] | None = None,
    ) -> dict:
        """Explore repository structure and read files — read-only, scoped to target repo.

        Args:
            command: "view" to read file/directory, "find_line" to search text.
            path: Path to file or directory within the target repository.
            search_text: Text to search for (find_line command only).
            view_range: Line range [start, end] for view command.
        """
        _validate_path(path, [repo_path])

        from threatforest.modules.tools.read_only_editor import read_only_editor

        return read_only_editor(
            command=command,
            path=path,
            search_text=search_text or None,
            view_range=view_range,
        )

    return structural_analyzer
