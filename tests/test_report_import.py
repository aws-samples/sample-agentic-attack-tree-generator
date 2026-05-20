"""Tests for ``server.report_import.process_pending_imports``.

Covers the round-trip path (build a bundle → drop it in imports/ → run the
processor → assert the app appears under runs/), collision handling, the
single-version merge case, and the malicious-zip rejection path.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.registry import ApplicationRegistry, slugify  # noqa: E402
from server.report_bundle import (  # noqa: E402
    MANIFEST_FILENAME,
    build_report_bundle,
)
from server.report_import import (  # noqa: E402
    ensure_imports_dir,
    process_pending_imports,
)


# ─── helpers ──────────────────────────────────────────────────────


def _seed_run(project_dir: Path, timestamp: str) -> Path:
    run_dir = project_dir / timestamp
    (run_dir / "state").mkdir(parents=True, exist_ok=True)
    (run_dir / "output").mkdir(parents=True, exist_ok=True)
    (run_dir / "output" / "threatforest_data.json").write_text(
        json.dumps({"threat_count": 1, "categories": []}),
        encoding="utf-8",
    )
    (run_dir / "state" / "threats.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "attack_trees.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "ttp_mappings.json").write_text("[]", encoding="utf-8")
    (run_dir / "state" / "mitigations.json").write_text("[]", encoding="utf-8")
    return run_dir


def _seed_project(registry: ApplicationRegistry, slug: str, name: str) -> Path:
    project_dir = registry.runs_root / slug
    project_dir.mkdir()
    (project_dir / "metadata.json").write_text(
        json.dumps({"name": name, "path": "/orig", "description": ""}),
        encoding="utf-8",
    )
    return project_dir


@pytest.fixture()
def origin_registry(tmp_path: Path) -> ApplicationRegistry:
    """A populated registry standing in for the export-side install."""
    runs_root = tmp_path / "origin" / "runs"
    runs_root.mkdir(parents=True)
    reg = ApplicationRegistry()
    reg.runs_root = runs_root
    return reg


@pytest.fixture()
def target_registry(tmp_path: Path) -> ApplicationRegistry:
    """An empty registry standing in for the import-side install."""
    runs_root = tmp_path / "target" / "runs"
    runs_root.mkdir(parents=True)
    reg = ApplicationRegistry()
    reg.runs_root = runs_root
    return reg


@pytest.fixture()
def imports_dir(tmp_path: Path) -> Path:
    d = tmp_path / "target" / "imports"
    d.mkdir(parents=True)
    return d


def _bundle_to_disk(
    *,
    origin: ApplicationRegistry,
    folder_id: str,
    version_ids: list[str],
    imports_dir: Path,
    filename: str,
) -> Path:
    payload = build_report_bundle(
        folder_id=folder_id,
        version_ids=version_ids,
        include_scanner_context=True,
        registry=origin,
    )
    bundle_path = imports_dir / filename
    bundle_path.write_bytes(payload)
    return bundle_path


# ─── round-trip ───────────────────────────────────────────────────


def test_round_trip_single_version(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    project = _seed_project(origin_registry, "demo", "Demo App")
    _seed_run(project, "20260101_120000")
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo.tfreport",
    )

    results = process_pending_imports(imports_dir, target_registry)

    assert len(results) == 1
    assert results[0].status == "imported"
    assert results[0].versions_added == ["20260101_120000"]
    assert results[0].folder_name == "demo"
    # Bundle is moved to processed/.
    assert (imports_dir / "processed" / "demo.tfreport").exists()
    assert not (imports_dir / "demo.tfreport").exists()

    # Imported app shows up in the registry.
    apps = target_registry.discover_applications()
    assert len(apps) == 1
    assert apps[0].name == "Demo App"
    assert apps[0].imported is True
    assert apps[0].imported_from == "Demo App"

    versions = target_registry.get_versions(slugify("demo"))
    assert [v.id for v in versions] == ["20260101_120000"]
    assert versions[0].status == "complete"


def test_business_context_is_preserved_through_import(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
    tmp_path: Path,
) -> None:
    """A v2 export's business_context.json reaches the recipient's registry."""
    from server.applications import ApplicationRepository
    from server.models import ApplicationCreateRequest, BusinessContext
    from server.report_bundle import build_report_bundle as _build

    # Origin side: full v2 app with a populated BusinessContext.
    origin_repo = ApplicationRepository(
        store_path=tmp_path / "origin-applications.json"
    )
    project_path = tmp_path / "origin" / "src"
    project_path.mkdir(parents=True)
    origin_app = origin_repo.create_application(
        ApplicationCreateRequest(
            name="Sales Portal",
            project_path=str(project_path),
            business_context=BusinessContext(
                description="customer-facing portal",
                regulatory_frameworks=["PCI", "SOC2"],
                data_sensitivity="pii",
                cia_priority=["confidentiality", "integrity", "availability"],
            ),
        )
    )
    project_dir = origin_registry.runs_root / origin_app.run_dir_name
    project_dir.mkdir()
    (project_dir / "metadata.json").write_text(
        json.dumps({"name": origin_app.name, "path": str(project_path)}),
        encoding="utf-8",
    )
    _seed_run(project_dir, "20260101_120000")

    payload = _build(
        folder_id=origin_app.run_dir_name,
        version_ids=["20260101_120000"],
        include_scanner_context=True,
        registry=origin_registry,
        app_repository=origin_repo,
    )
    (imports_dir / "demo.tfreport").write_bytes(payload)

    process_pending_imports(imports_dir, target_registry)

    apps = target_registry.discover_applications()
    assert len(apps) == 1
    assert apps[0].imported is True
    bc = apps[0].business_context
    assert bc is not None
    assert bc.description == "customer-facing portal"
    assert bc.regulatory_frameworks == ["PCI", "SOC2"]
    assert bc.data_sensitivity == "pii"


def test_metadata_strips_path_for_read_only_marker(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    project = _seed_project(origin_registry, "demo", "Demo")
    _seed_run(project, "20260101_120000")
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo.tfreport",
    )

    process_pending_imports(imports_dir, target_registry)

    meta = json.loads(
        (target_registry.runs_root / "demo" / "metadata.json").read_text()
    )
    assert "path" not in meta  # absence is the "imported / read-only" signal
    assert meta["imported_from_app_id"] == "demo"
    assert meta["imported_from_app_name"] == "Demo"


# ─── collision handling ───────────────────────────────────────────


def test_slug_collision_with_local_app_uses_imported_suffix(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    # Target already has a locally-scanned app with this slug.
    _seed_project(target_registry, "demo", "Local Demo")

    # Origin exports an app with the same slug.
    project = _seed_project(origin_registry, "demo", "Origin Demo")
    _seed_run(project, "20260101_120000")
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo.tfreport",
    )

    results = process_pending_imports(imports_dir, target_registry)
    assert results[0].status == "imported"
    assert results[0].folder_name == "demo--imported"
    # Local app untouched.
    assert (target_registry.runs_root / "demo").exists()
    assert (target_registry.runs_root / "demo--imported").exists()


def test_full_app_reimport_creates_imported_2(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    # First import — full-app bundle with two versions.
    project = _seed_project(origin_registry, "demo", "Demo")
    _seed_run(project, "20260101_120000")
    _seed_run(project, "20260202_120000")
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000", "20260202_120000"],
        imports_dir=imports_dir,
        filename="demo-1.tfreport",
    )
    process_pending_imports(imports_dir, target_registry)

    # Second import — re-export the same full-app bundle.
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000", "20260202_120000"],
        imports_dir=imports_dir,
        filename="demo-2.tfreport",
    )
    results = process_pending_imports(imports_dir, target_registry)

    assert results[0].status == "imported"
    # Full-app re-import never merges; it goes to a fresh folder.
    assert results[0].folder_name == "demo--imported"


# ─── single-version merge ─────────────────────────────────────────


def test_single_version_reimport_merges_into_existing_imported_app(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    # Origin: app with two versions in its own history.
    project = _seed_project(origin_registry, "demo", "Demo")
    _seed_run(project, "20260101_120000")
    _seed_run(project, "20260202_120000")

    # First bundle: just the older version.
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo-v1.tfreport",
    )
    first = process_pending_imports(imports_dir, target_registry)
    assert first[0].status == "imported"
    folder_name = first[0].folder_name

    # Second bundle: the newer version, dropped in later.
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260202_120000"],
        imports_dir=imports_dir,
        filename="demo-v2.tfreport",
    )
    second = process_pending_imports(imports_dir, target_registry)

    assert second[0].status == "merged"
    assert second[0].folder_name == folder_name
    assert second[0].versions_added == ["20260202_120000"]

    # Both versions live under the same folder now.
    versions = target_registry.get_versions(slugify(folder_name))
    assert sorted(v.id for v in versions) == [
        "20260101_120000",
        "20260202_120000",
    ]


def test_same_version_reimport_is_skipped(
    origin_registry: ApplicationRegistry,
    target_registry: ApplicationRegistry,
    imports_dir: Path,
) -> None:
    project = _seed_project(origin_registry, "demo", "Demo")
    _seed_run(project, "20260101_120000")

    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo-1.tfreport",
    )
    process_pending_imports(imports_dir, target_registry)

    # Re-import the same bundle.
    _bundle_to_disk(
        origin=origin_registry,
        folder_id="demo",
        version_ids=["20260101_120000"],
        imports_dir=imports_dir,
        filename="demo-2.tfreport",
    )
    results = process_pending_imports(imports_dir, target_registry)

    assert results[0].status == "skipped"
    assert results[0].versions_added == []
    assert results[0].versions_skipped == ["20260101_120000"]


# ─── malformed / malicious bundles ────────────────────────────────


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    path.write_bytes(buf.getvalue())


def test_missing_manifest_is_failed(
    target_registry: ApplicationRegistry, imports_dir: Path
) -> None:
    bad = imports_dir / "broken.tfreport"
    _write_zip(bad, {"random.txt": b"hi"})

    results = process_pending_imports(imports_dir, target_registry)
    assert results[0].status == "failed"
    assert "missing" in (results[0].error or "").lower()
    assert (imports_dir / "failed" / "broken.tfreport").exists()
    assert (imports_dir / "failed" / "broken.tfreport.error.txt").exists()


def test_unsupported_schema_version_is_failed(
    target_registry: ApplicationRegistry, imports_dir: Path
) -> None:
    bad = imports_dir / "future.tfreport"
    _write_zip(
        bad,
        {
            MANIFEST_FILENAME: json.dumps(
                {
                    "schema_version": 999,
                    "source_app_slug": "x",
                    "versions": ["20260101_120000"],
                }
            ).encode("utf-8"),
        },
    )

    results = process_pending_imports(imports_dir, target_registry)
    assert results[0].status == "failed"
    assert "schema" in (results[0].error or "").lower()


def test_zip_slip_attempt_is_rejected(
    target_registry: ApplicationRegistry, imports_dir: Path
) -> None:
    bad = imports_dir / "evil.tfreport"
    _write_zip(
        bad,
        {
            MANIFEST_FILENAME: json.dumps(
                {
                    "schema_version": 1,
                    "source_app_slug": "evil",
                    "scope": "single-version",
                    "versions": ["20260101_120000"],
                }
            ).encode("utf-8"),
            "../etc/passwd": b"haha",
        },
    )

    results = process_pending_imports(imports_dir, target_registry)
    assert results[0].status == "failed"
    assert "parent" in (results[0].error or "").lower()


def test_corrupted_zip_is_failed(
    target_registry: ApplicationRegistry, imports_dir: Path
) -> None:
    bad = imports_dir / "corrupt.tfreport"
    bad.write_bytes(b"not a zip")

    results = process_pending_imports(imports_dir, target_registry)
    assert results[0].status == "failed"
    assert (imports_dir / "failed" / "corrupt.tfreport").exists()


# ─── ensure_imports_dir ───────────────────────────────────────────


def test_ensure_imports_dir_creates_readme(tmp_path: Path) -> None:
    target = tmp_path / "imports"
    ensure_imports_dir(target)
    assert (target / "README.md").is_file()
    body = (target / "README.md").read_text(encoding="utf-8")
    assert ".tfreport" in body
    assert "read-only" in body


def test_ensure_imports_dir_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "imports"
    ensure_imports_dir(target)
    (target / "README.md").write_text("custom note", encoding="utf-8")
    # Second call must not overwrite a customised README.
    ensure_imports_dir(target)
    assert (target / "README.md").read_text() == "custom note"
