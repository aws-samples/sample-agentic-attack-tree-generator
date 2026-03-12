"""Sandboxed file read/write tools with per-agent path restrictions."""

from pathlib import Path

from strands import tool


def _validate_path(path: str, allowed_prefixes: list[str]) -> Path:
    """Resolve path and check it falls within allowed prefixes."""
    p = Path(path)
    if not p.is_absolute():
        # Resolve relative paths against each allowed prefix until one works
        for prefix in allowed_prefixes:
            candidate = (Path(prefix).resolve() / p)
            if candidate.exists():
                p = candidate
                break
        else:
            # No match found, try first directory prefix as default base
            for prefix in allowed_prefixes:
                if Path(prefix).resolve().is_dir():
                    p = Path(prefix).resolve() / p
                    break
    resolved = p.resolve()
    for prefix in allowed_prefixes:
        if resolved.is_relative_to(Path(prefix).resolve()):
            return resolved
    raise PermissionError(f"Access denied: {resolved} is outside allowed paths")


def make_sandboxed_file_read(allowed_read_paths: list[str]):
    """Create a file_read tool restricted to specific paths.

    Relative paths are automatically resolved against the allowed directories.
    """

    _cache: dict[str, str] = {}

    @tool
    def sandboxed_file_read(path: str, mode: str = "view") -> str:
        """Read file content — restricted to allowed paths for this agent.

        Args:
            path: Path to the file to read (can be relative to the project root).
            mode: "view" to read entire file.
        """
        resolved = _validate_path(path, allowed_read_paths)
        key = str(resolved)
        if key in _cache:
            return f"[CACHED — already read this file]\n{_cache[key]}"
        if resolved.is_dir():
            entries = [p.name for p in sorted(resolved.iterdir())]
            result = "\n".join(entries)
        else:
            result = resolved.read_text()
        _cache[key] = result
        return result

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
