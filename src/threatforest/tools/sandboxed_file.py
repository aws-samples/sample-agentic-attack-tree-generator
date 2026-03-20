"""Sandboxed file read/write tools with per-agent path restrictions."""

import json
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from strands import tool


class Evidence(BaseModel):
    source_type: str
    source_ref: str
    excerpt: str
    relevance: str


class Mitigation(BaseModel):
    attack_step_id: str
    technique_id: str
    mitigation_text: str
    implementation_guidance: str
    remediation_type: Literal["quick_win", "short_term", "medium_term", "long_term", "monitoring"]
    control_candidates: list[dict] = []
    selected_control_id: str = ""
    priority: int
    evidence: list[Evidence]
    also_applies_to: list[str] = []

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"}
MAX_FILE_SIZE = 200_000  # ~200KB / ~50K tokens — prevent giant files from flooding the context


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

    _cache: dict[str, object] = {}

    @tool
    def sandboxed_file_read(path: str, offset: int = 0, limit: int = 0):
        """Read file content — restricted to allowed paths for this agent.

        For large files, only the first portion is returned. Use offset/limit to read specific sections.

        Args:
            path: Path to the file to read (can be relative to the project root).
            offset: Line number to start reading from (0-based, default: start of file).
            limit: Maximum number of lines to return (default: 0 = up to the size cap).
        """
        resolved = _validate_path(path, allowed_read_paths)
        # For ranged reads, use a cache key that includes the range
        cache_key = f"{resolved}:{offset}:{limit}"
        if cache_key in _cache:
            cached = _cache[cache_key]
            if isinstance(cached, dict):
                return cached
            return f"[CACHED — already read this range]\n{cached}"
        if resolved.is_dir():
            entries = [p.name for p in sorted(resolved.iterdir())]
            result = "\n".join(entries)
            _cache[cache_key] = result
            return result
        if resolved.suffix.lower() in DOCUMENT_EXTENSIONS:
            fmt = resolved.suffix.lower().lstrip(".")
            name = f"{resolved.stem}-{uuid.uuid4().hex[:8]}"
            content_bytes = resolved.read_bytes()
            doc_result = {
                "status": "success",
                "content": [
                    {"document": {"name": name, "format": fmt, "source": {"bytes": content_bytes}}},
                    {"text": f"Document loaded: {resolved.name} ({len(content_bytes)} bytes, format: {fmt})"},
                ],
            }
            _cache[cache_key] = doc_result
            return doc_result
        content = resolved.read_text()
        lines = content.splitlines(keepends=True)
        total_lines = len(lines)
        file_size = resolved.stat().st_size

        # Ranged read — agent is drilling into a specific section
        if offset > 0 or limit > 0:
            sliced = lines[offset:]
            if limit > 0:
                sliced = sliced[:limit]
            result = "".join(sliced)
            if len(result) > MAX_FILE_SIZE:
                result = result[:MAX_FILE_SIZE]
                shown = result.count("\n")
                result += (
                    f"\n\n[TRUNCATED at {MAX_FILE_SIZE // 1000}KB — showing ~{shown} lines "
                    f"starting at line {offset}. Use offset={offset + shown} to continue.]"
                )
            else:
                result += f"\n\n[Lines {offset}-{offset + len(sliced)} of {total_lines}]"
            _cache[cache_key] = result
            return result

        # Full read — small files return as-is
        if file_size <= MAX_FILE_SIZE:
            result = content
            _cache[cache_key] = result
            return result

        # Large file — return a smart preview (head + tail + metadata)
        HEAD_LINES = 100
        TAIL_LINES = 20
        head = "".join(lines[:HEAD_LINES])
        tail = "".join(lines[-TAIL_LINES:])
        result = (
            f"[LARGE FILE: {file_size:,} bytes, {total_lines} lines — showing preview]\n"
            f"--- First {HEAD_LINES} lines ---\n"
            f"{head}\n"
            f"--- Last {TAIL_LINES} lines ---\n"
            f"{tail}\n"
            f"[Use offset and limit to read specific sections, e.g. offset=100 limit=200]"
        )
        _cache[cache_key] = result
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


def make_store_mitigations(output_path: str):
    """Create a store_mitigations tool that validates and writes mitigations."""

    @tool
    def store_mitigations(mitigations: list[Mitigation]) -> str:
        """Store all mitigations at once. Each mitigation is validated against a schema before writing.

        Args:
            mitigations: List of mitigation objects. Every field is required and validated.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        # strands validates via Pydantic then calls model_dump(), so items arrive as dicts
        data = {"mitigations": list(mitigations)}
        out.write_text(json.dumps(data, indent=2))
        return f"Stored {len(mitigations)} mitigations to {out}"

    return store_mitigations
