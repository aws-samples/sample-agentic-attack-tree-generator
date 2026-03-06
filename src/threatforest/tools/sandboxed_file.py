"""Sandboxed file read/write tools with per-agent path restrictions."""

from pathlib import Path

from strands import tool


def _validate_path(path: str, allowed_prefixes: list[str]) -> Path:
    """Resolve path and check it falls within allowed prefixes."""
    resolved = Path(path).resolve()
    for prefix in allowed_prefixes:
        if resolved.is_relative_to(Path(prefix).resolve()):
            return resolved
    raise PermissionError(f"Access denied: {resolved} is outside allowed paths")


def make_sandboxed_file_read(allowed_read_paths: list[str]):
    """Create a file_read tool restricted to specific paths."""

    @tool
    def sandboxed_file_read(path: str, mode: str = "view") -> str:
        """Read file content — restricted to allowed paths for this agent.

        Args:
            path: Path to the file to read.
            mode: "view" to read entire file.
        """
        resolved = _validate_path(path, allowed_read_paths)
        if resolved.is_dir():
            entries = [p.name for p in sorted(resolved.iterdir())]
            return "\n".join(entries)
        return resolved.read_text()

    return sandboxed_file_read


def make_sandboxed_file_write(allowed_write_paths: list[str]):
    """Create a file_write tool restricted to specific paths."""

    @tool
    def sandboxed_file_write(path: str, content: str, mode: str = "overwrite") -> str:
        """Write file content — restricted to allowed paths for this agent.

        Args:
            path: Path to the file to write.
            content: Content to write.
            mode: "overwrite" (default) replaces file, "append" adds to end.
        """
        resolved = _validate_path(path, allowed_write_paths)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        if mode == "append":
            with resolved.open("a") as f:
                f.write(content)
        else:
            resolved.write_text(content)
        return f"Written {len(content)} bytes to {resolved} ({mode})"

    return sandboxed_file_write
