"""Tests for ``server.report_bundle.build_report_bundle``."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.applications import ApplicationRepository  # noqa: E402
from server.models import (  # noqa: E402
    ApplicationCreateRequest,
    BusinessContext,
)
from server.registry import ApplicationRegistry  # noqa: E402
from server.report_bundle import (  # noqa: E402
    MANIFEST_FILENAME,
    SCHEMA_VERSION,
    ReportBundleError,
    build_report_bundle,
)


# ─── helpers ──────────────────────────────────────────────────────


def _seed_run(
    project_dir: Path,
    timestamp: str,
    *,
    with_scanner_context: bool = True,
    with_overrides: bool = False,
) -> Path:
    """Lay down a minimal but realistic run folder under *project_dir*."""
    run_dir = project_dir / timestamp
    (run_dir / "state").mkdir(parents=True, exist_ok=True)
    (run_dir / "output").mkdir(parents=True, exist_ok=True)
    (run_dir / "output" / "threatforest_data.json").write_text(
        json.dumps({"threat_count": 2, "categories": ["spoofing"]}),
        encoding="utf-8",
    )
    (run_dir / "output" / "threat_model_report.md").write_text(
        "# Report", encoding="utf-8"
    )
    (run_dir / "output" / "attack_trees_dashboard.html").write_text(
        "<html></html>", encoding="utf-8"
    )
    (run_dir / "state" / "threats.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "attack_trees.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "ttp_mappings.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "mitigations.json").write_text("[]", encoding="utf-8")
    if with_scanner_context:
        (run_dir / "state" / "scanner_context.json").write_text(
            json.dumps({"files": ["src/secret.py"]}),
            encoding="utf-8",
        )
    if with_overrides:
        (run_dir / "mitigation_overrides.json").write_text(
            json.dumps({"version": 1, "overrides": {}}),
            encoding="utf-8",
        )
    return run_dir


@pytest.fixture()
def registry(tmp_path: Path) -> ApplicationRegistry:
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    reg = ApplicationRegistry()
    reg.runs_root = runs_root
    return reg


@pytest.fixture()
def repo(tmp_path: Path) -> ApplicationRepository:
    return ApplicationRepository(store_path=tmp_path / "applications.json")


def _seed_project(registry: ApplicationRegistry, slug: str, name: str) -> Path:
    project_dir = registry.runs_root / slug
    project_dir.mkdir()
    (project_dir / "metadata.json").write_text(
        json.dumps({"name": name, "path": "/orig/source", "description": "demo"}),
        encoding="utf-8",
    )
    return project_dir


# ─── tests ────────────────────────────────────────────────────────


def test_bundle_round_trip_single_version(registry: ApplicationRegistry) -> None:
    project_dir = _seed_project(registry, "demo", "Demo App")
    _seed_run(project_dir, "20260101_120000")

    payload = build_report_bundle(
        folder_id="demo",
        version_ids=["20260101_120000"],
        include_scanner_context=True,
        registry=registry,
    )

    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read(MANIFEST_FILENAME))

    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["scope"] == "single-version"
    assert manifest["versions"] == ["20260101_120000"]
    assert manifest["source_app_slug"] == "demo"
    assert manifest["source_app_name"] == "Demo App"
    assert manifest["include_scanner_context"] is True

    # Must include the standard run artefacts.
    assert "versions/20260101_120000/output/threatforest_data.json" in names
    assert "versions/20260101_120000/output/threat_model_report.md" in names
    assert "versions/20260101_120000/output/attack_trees_dashboard.html" in names
    assert "versions/20260101_120000/state/threats.json" in names
    assert "versions/20260101_120000/state/scanner_context.json" in names
    assert "application/metadata.json" in names


def test_bundle_excludes_scanner_context_when_disabled(
    registry: ApplicationRegistry,
) -> None:
    project_dir = _seed_project(registry, "demo", "Demo App")
    _seed_run(project_dir, "20260101_120000")

    payload = build_report_bundle(
        folder_id="demo",
        version_ids=["20260101_120000"],
        include_scanner_context=False,
        registry=registry,
    )
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read(MANIFEST_FILENAME))

    assert "versions/20260101_120000/state/scanner_context.json" not in names
    # Other state files still flow through unaffected.
    assert "versions/20260101_120000/state/threats.json" in names
    assert manifest["include_scanner_context"] is False


def test_bundle_full_application_includes_every_version(
    registry: ApplicationRegistry,
) -> None:
    project_dir = _seed_project(registry, "multi", "Multi App")
    _seed_run(project_dir, "20260101_010000")
    _seed_run(project_dir, "20260202_020000")

    payload = build_report_bundle(
        folder_id="multi",
        version_ids=["20260101_010000", "20260202_020000"],
        include_scanner_context=True,
        registry=registry,
    )

    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        manifest = json.loads(zf.read(MANIFEST_FILENAME))
        names = set(zf.namelist())

    assert manifest["scope"] == "full-application"
    assert manifest["versions"] == ["20260101_010000", "20260202_020000"]
    assert "versions/20260101_010000/output/threatforest_data.json" in names
    assert "versions/20260202_020000/output/threatforest_data.json" in names


def test_bundle_includes_business_context_for_v2_app(
    registry: ApplicationRegistry,
    repo: ApplicationRepository,
    tmp_path: Path,
) -> None:
    project = tmp_path / "src-tree"
    project.mkdir()
    app = repo.create_application(
        ApplicationCreateRequest(
            name="Sales Portal",
            project_path=str(project),
            business_context=BusinessContext(
                description="customer-facing sales portal",
                regulatory_frameworks=["PCI"],
                data_sensitivity="pii",
                cia_priority=["confidentiality", "integrity", "availability"],
            ),
        )
    )

    project_dir = _seed_project(registry, app.run_dir_name, app.name)
    _seed_run(project_dir, "20260101_120000")

    payload = build_report_bundle(
        folder_id=app.run_dir_name,
        version_ids=["20260101_120000"],
        include_scanner_context=True,
        registry=registry,
        app_repository=repo,
    )

    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        bc = json.loads(zf.read("application/business_context.json"))
        manifest = json.loads(zf.read(MANIFEST_FILENAME))

    assert bc["regulatory_frameworks"] == ["PCI"]
    assert manifest["source_app_id"] == app.id
    assert manifest["source_app_name"] == "Sales Portal"


def test_bundle_strips_path_from_application_metadata(
    registry: ApplicationRegistry,
) -> None:
    project_dir = _seed_project(registry, "leaky", "Leaky App")
    _seed_run(project_dir, "20260101_120000")

    payload = build_report_bundle(
        folder_id="leaky",
        version_ids=["20260101_120000"],
        include_scanner_context=False,
        registry=registry,
    )

    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        meta = json.loads(zf.read("application/metadata.json"))

    assert "path" not in meta  # never leak originator's filesystem layout
    assert meta["name"] == "Leaky App"


def test_bundle_raises_when_version_has_no_output(
    registry: ApplicationRegistry,
) -> None:
    project_dir = _seed_project(registry, "incomplete", "Incomplete")
    run_dir = project_dir / "20260101_120000"
    run_dir.mkdir()
    (run_dir / "state").mkdir()
    # No output/ dir → cannot bundle.

    with pytest.raises(ReportBundleError):
        build_report_bundle(
            folder_id="incomplete",
            version_ids=["20260101_120000"],
            include_scanner_context=True,
            registry=registry,
        )


def test_bundle_raises_for_unknown_folder(registry: ApplicationRegistry) -> None:
    with pytest.raises(ReportBundleError):
        build_report_bundle(
            folder_id="does-not-exist",
            version_ids=["20260101_120000"],
            include_scanner_context=True,
            registry=registry,
        )


def test_bundle_raises_for_empty_version_list(
    registry: ApplicationRegistry,
) -> None:
    _seed_project(registry, "demo", "Demo")
    with pytest.raises(ReportBundleError):
        build_report_bundle(
            folder_id="demo",
            version_ids=[],
            include_scanner_context=True,
            registry=registry,
        )
