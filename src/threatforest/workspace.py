"""Workspace abstraction for per-run state and output files.

Today ThreatForest persists every agent's intermediate JSON under a
timestamped directory on local disk (`<runs_root>/<project>/<ts>/state/*.json`
plus `output/` and `pause_state.json`). That works for `uv run` but breaks
on Fargate, where the filesystem is ephemeral and the engine needs to read
and write to S3.

This module introduces a narrow `Workspace` protocol that every agent uses
instead of direct `Path.read_text` / `Path.write_text`. A single local
implementation (`LocalFilesystemWorkspace`) preserves the existing on-disk
layout so behavior is unchanged for `uv run`. An S3-backed implementation
lives in a separate module and is loaded when `THREATFOREST_BACKEND=aws`.

Only per-run state (`state/`, `output/`, `pause_state.json`) routes through
the Workspace. Project-repo reads and packaged data (STIX bundles, prompts)
stay on local disk in every backend.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable


@runtime_checkable
class Workspace(Protocol):
    """Per-run storage for agent state and output files.

    Keys are forward-slash relative paths (e.g. `"state/threats.json"`,
    `"output/threatforest_data.json"`, `"pause_state.json"`). Implementations
    may back keys with local files, S3 objects, or anything else.
    """

    def read_bytes(self, key: str) -> bytes: ...

    def write_bytes(self, key: str, data: bytes) -> None: ...

    def read_text(self, key: str) -> str: ...

    def write_text(self, key: str, data: str) -> None: ...

    def read_json(self, key: str) -> Any: ...

    def write_json(self, key: str, obj: Any) -> None: ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> bool:
        """Remove a key. Returns True if something was removed."""
        ...

    def list_keys(self, prefix: str = "") -> Iterable[str]:
        """Yield every key with the given prefix. Empty prefix yields all keys."""
        ...

    def local_path(self, key: str) -> Path | None:
        """Return a local filesystem path for a key if one exists.

        Some callers (e.g. legacy tools that shell out to subprocesses) need a
        real path. Implementations that can't produce one return `None`; the
        caller is expected to fall back to `read_bytes` + a tempfile.
        """
        ...


class LocalFilesystemWorkspace:
    """Workspace backed by a directory on local disk.

    The directory is the existing per-run directory used by `uv run`:
    `<runs_root>/<project>/<timestamp>/`. Keys map to files beneath it.
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    @property
    def root(self) -> Path:
        return self._root

    def _path(self, key: str) -> Path:
        if not key or key.startswith("/") or ".." in Path(key).parts:
            raise ValueError(f"Invalid workspace key: {key!r}")
        return self._root / key

    def read_bytes(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def write_bytes(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def read_text(self, key: str) -> str:
        return self._path(key).read_text(encoding="utf-8")

    def write_text(self, key: str, data: str) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")

    def read_json(self, key: str) -> Any:
        return json.loads(self.read_text(key))

    def write_json(self, key: str, obj: Any) -> None:
        self.write_text(key, json.dumps(obj, indent=2, ensure_ascii=False))

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if not path.exists():
            return False
        path.unlink()
        return True

    def list_keys(self, prefix: str = "") -> Iterable[str]:
        base = self._path(prefix) if prefix else self._root
        if not base.exists():
            return
        if base.is_file():
            yield base.relative_to(self._root).as_posix()
            return
        for path in sorted(base.rglob("*")):
            if path.is_file():
                yield path.relative_to(self._root).as_posix()

    def local_path(self, key: str) -> Path:
        return self._path(key)
