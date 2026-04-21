"""Tests for ``ApplicationRegistry.get_versions`` user-friendly display names.

Ensures timestamped run folders under ``.threatforest/runs/<app>/`` are
labelled ``Version N`` in chronological order (newest = highest N), so the
UI can render friendly version numbers without breaking the filesystem
lookup key (``version.id`` remains the raw ``YYYYMMDD_HHMMSS`` folder name).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.registry import ApplicationRegistry, slugify  # noqa: E402


def _seed_run(project_dir: Path, timestamp: str) -> None:
    """Create a fake timestamped run folder with the expected layout."""
    run_dir = project_dir / timestamp
    (run_dir / "state").mkdir(parents=True, exist_ok=True)
    (run_dir / "output").mkdir(parents=True, exist_ok=True)
    (run_dir / "output" / "threatforest_data.json").write_text(
        json.dumps({"threat_count": 0, "categories": []}),
        encoding="utf-8",
    )


@pytest.fixture()
def registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ApplicationRegistry:
    """Registry rooted at an isolated ``runs_root`` under ``tmp_path``."""
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    reg = ApplicationRegistry()
    reg.runs_root = runs_root
    return reg


def test_get_versions_assigns_sequential_display_names(
    registry: ApplicationRegistry,
) -> None:
    """Three runs → newest is Version 3, oldest is Version 1."""
    project = registry.runs_root / "sampleapp"
    project.mkdir()
    (project / "metadata.json").write_text(
        json.dumps({"name": "sampleapp", "path": "/x"}), encoding="utf-8"
    )

    _seed_run(project, "20260101_010101")  # oldest
    _seed_run(project, "20260202_020202")
    _seed_run(project, "20260303_030303")  # newest

    versions = registry.get_versions(slugify("sampleapp"))

    assert [v.id for v in versions] == [
        "20260303_030303",
        "20260202_020202",
        "20260101_010101",
    ]
    # Newest-first, so the first element is the highest number.
    assert [v.display_name for v in versions] == [
        "Version 3",
        "Version 2",
        "Version 1",
    ]


def test_get_versions_single_run_is_version_1(
    registry: ApplicationRegistry,
) -> None:
    project = registry.runs_root / "solo"
    project.mkdir()
    (project / "metadata.json").write_text(
        json.dumps({"name": "solo", "path": "/x"}), encoding="utf-8"
    )
    _seed_run(project, "20260101_010101")

    versions = registry.get_versions(slugify("solo"))

    assert len(versions) == 1
    assert versions[0].display_name == "Version 1"
    # id remains the raw timestamp so filesystem lookup still works.
    assert versions[0].id == "20260101_010101"


def test_get_versions_no_runs_returns_empty(
    registry: ApplicationRegistry,
) -> None:
    project = registry.runs_root / "empty"
    project.mkdir()
    (project / "metadata.json").write_text(
        json.dumps({"name": "empty", "path": "/x"}), encoding="utf-8"
    )

    assert registry.get_versions(slugify("empty")) == []
