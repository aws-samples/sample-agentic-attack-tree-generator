"""Tests for the business-context → scanner_context.json seeding.

Covers the helper ``_seed_scanner_context`` in the executor and the
``_save_pause_state`` round-trip of ``app_id`` through ``pause_state.json``.
The executor's full orchestration is integration-level; here we focus on the
deterministic, file-shape pieces that the v2 UX depends on.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.executor import _save_pause_state, _seed_scanner_context  # noqa: E402
from server.models import (  # noqa: E402
    Application,
    BusinessContext,
    RunConfig,
)


def _make_app(
    *,
    description: str = "A healthcare app storing patient records.",
    frameworks: list[str] | None = None,
    sensitivity: str = "phi",
    cia: str = "confidentiality",
) -> Application:
    return Application(
        id="app_test123",
        name="Test App",
        slug="test-app",
        project_path="/tmp/does-not-matter",
        business_context=BusinessContext(
            description=description,
            regulatory_frameworks=frameworks or ["HIPAA", "SOC2"],
            data_sensitivity=sensitivity,  # type: ignore[arg-type]
            main_cia_risk=cia,  # type: ignore[arg-type]
        ),
        created_at="2026-04-17T00:00:00+00:00",
        updated_at="2026-04-17T00:00:00+00:00",
        run_dir_name="test-app",
    )


def test_seed_writes_scanner_context(tmp_path: Path) -> None:
    app = _make_app()
    _seed_scanner_context(tmp_path, app)

    state_file = tmp_path / "state" / "scanner_context.json"
    assert state_file.is_file()

    data = json.loads(state_file.read_text())
    assert data["business_context"] == {
        "description": app.business_context.description,
        "regulatory_frameworks": ["HIPAA", "SOC2"],
        "data_sensitivity": "phi",
        "main_cia_risk": "confidentiality",
    }


def test_seed_mirrors_top_level_fields(tmp_path: Path) -> None:
    """Top-level ``compliance_requirements``, ``data_sensitivity`` and
    ``main_cia_risk`` mirror the nested block so existing scanner/interviewer
    enrichment and the threat agent can read them without extra indirection."""
    app = _make_app(frameworks=["SOC2", "PCI-DSS"], sensitivity="pii", cia="integrity")
    _seed_scanner_context(tmp_path, app)

    data = json.loads((tmp_path / "state" / "scanner_context.json").read_text())
    assert data["compliance_requirements"] == ["SOC2", "PCI-DSS"]
    assert data["data_sensitivity"] == "pii"
    assert data["main_cia_risk"] == "integrity"


def test_seed_leaves_existing_file_untouched(tmp_path: Path) -> None:
    """Resume flows re-enter with state already written. We must never clobber
    a pre-existing scanner_context.json — past progress belongs to the run."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    existing = {"sentinel": "do not overwrite", "cloud_provider": "AWS"}
    (state_dir / "scanner_context.json").write_text(json.dumps(existing))

    _seed_scanner_context(tmp_path, _make_app())

    data = json.loads((state_dir / "scanner_context.json").read_text())
    assert data == existing


def test_seed_creates_state_dir_if_missing(tmp_path: Path) -> None:
    # run_dir might be fresh and not yet have a state/ subdir when resume is
    # false but create_run_directory wasn't called yet — guard against it.
    target = tmp_path / "fresh-run"
    target.mkdir()
    _seed_scanner_context(target, _make_app())
    assert (target / "state" / "scanner_context.json").is_file()


def test_pause_state_preserves_app_id(tmp_path: Path) -> None:
    """``app_id`` must survive pause → resume so the resumed run keeps its
    link to the persistent Application record."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    config = RunConfig(
        project_path="/tmp/p",
        threat_source="auto",
        app_id="app_abc123",
    )
    _save_pause_state(run_dir, completed_nodes=["scanner"], intent="pause", config=config)

    pause = json.loads((run_dir / "pause_state.json").read_text())
    assert pause["config"]["app_id"] == "app_abc123"


def test_pause_state_survives_missing_app_id(tmp_path: Path) -> None:
    """Legacy / resume configs without app_id serialise cleanly as None."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    config = RunConfig(project_path="/tmp/p", threat_source="auto")
    _save_pause_state(run_dir, completed_nodes=[], intent="stop", config=config)

    pause = json.loads((run_dir / "pause_state.json").read_text())
    assert pause["config"]["app_id"] is None
