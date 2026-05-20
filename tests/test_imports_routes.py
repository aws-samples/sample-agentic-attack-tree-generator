"""API tests for the upload-side import endpoints."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.registry import ApplicationRegistry  # noqa: E402
from server.report_bundle import (  # noqa: E402
    MANIFEST_FILENAME,
    build_report_bundle,
)
from server.routes.applications import set_registry  # noqa: E402
from server.routes.imports import router as imports_router  # noqa: E402


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
    """Registry with a populated run we can export from."""
    runs_root = tmp_path / "origin" / "runs"
    runs_root.mkdir(parents=True)
    reg = ApplicationRegistry()
    reg.runs_root = runs_root
    project = _seed_project(reg, "demo", "Demo App")
    _seed_run(project, "20260101_120000")
    return reg


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    """FastAPI client backed by an empty registry under tmp_path."""
    runs_root = tmp_path / "target" / "runs"
    runs_root.mkdir(parents=True)
    target = ApplicationRegistry()
    target.runs_root = runs_root
    set_registry(target)

    app = FastAPI()
    app.include_router(imports_router, prefix="/api")
    return TestClient(app)


def _bundle_bytes(origin: ApplicationRegistry) -> bytes:
    return build_report_bundle(
        folder_id="demo",
        version_ids=["20260101_120000"],
        include_scanner_context=True,
        registry=origin,
    )


# ─── upload happy path ────────────────────────────────────────────


def test_upload_imports_bundle_inline(
    client: TestClient, origin_registry: ApplicationRegistry, tmp_path: Path
) -> None:
    payload = _bundle_bytes(origin_registry)
    response = client.post(
        "/api/imports/tfreport",
        files={"file": ("demo.tfreport", payload, "application/zip")},
    )
    assert response.status_code == 200, response.text

    body = response.json()
    assert body["result"]["status"] == "imported"
    assert body["result"]["folder_name"] == "demo"
    assert body["result"]["versions_added"] == ["20260101_120000"]

    # Bundle moved to processed/.
    target_imports = (tmp_path / "target" / "imports").resolve()
    assert (target_imports / "processed" / "demo.tfreport").exists()
    assert not (target_imports / "demo.tfreport").exists()


def test_upload_returns_merged_for_same_source_app(
    client: TestClient, origin_registry: ApplicationRegistry, tmp_path: Path
) -> None:
    # First upload — single version v1.
    payload = _bundle_bytes(origin_registry)
    first = client.post(
        "/api/imports/tfreport",
        files={"file": ("demo-1.tfreport", payload, "application/zip")},
    )
    assert first.json()["result"]["status"] == "imported"

    # Add a newer version on the origin side and re-export.
    _seed_run(origin_registry.runs_root / "demo", "20260202_120000")
    payload2 = build_report_bundle(
        folder_id="demo",
        version_ids=["20260202_120000"],
        include_scanner_context=True,
        registry=origin_registry,
    )
    second = client.post(
        "/api/imports/tfreport",
        files={"file": ("demo-2.tfreport", payload2, "application/zip")},
    )
    body = second.json()
    assert body["result"]["status"] == "merged"
    assert body["result"]["folder_name"] == "demo"
    assert body["result"]["versions_added"] == ["20260202_120000"]


# ─── validation errors ────────────────────────────────────────────


def test_upload_rejects_non_tfreport_filename(client: TestClient) -> None:
    response = client.post(
        "/api/imports/tfreport",
        files={"file": ("demo.zip", b"x", "application/zip")},
    )
    assert response.status_code == 400
    assert ".tfreport" in response.json()["detail"]


def test_upload_rejects_path_separators(client: TestClient) -> None:
    response = client.post(
        "/api/imports/tfreport",
        files={"file": ("../evil.tfreport", b"x", "application/zip")},
    )
    assert response.status_code == 400
    assert "separator" in response.json()["detail"].lower()


def test_upload_rejects_duplicate_pending_filename(
    client: TestClient, tmp_path: Path
) -> None:
    imports_dir = tmp_path / "target" / "imports"
    imports_dir.mkdir(parents=True, exist_ok=True)
    (imports_dir / "demo.tfreport").write_bytes(b"already here")

    response = client.post(
        "/api/imports/tfreport",
        files={"file": ("demo.tfreport", b"new payload", "application/zip")},
    )
    assert response.status_code == 409


def test_upload_failed_bundle_returns_failed_status(
    client: TestClient,
) -> None:
    """A malformed bundle still yields a 200 with status=failed."""
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("not-a-manifest.txt", b"hi")
    response = client.post(
        "/api/imports/tfreport",
        files={
            "file": ("broken.tfreport", bad.getvalue(), "application/zip"),
        },
    )
    # We deliberately don't 4xx on import-level failures — the request
    # itself succeeded and we have a structured outcome to surface.
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["status"] == "failed"
    assert "missing" in body["result"]["error"].lower()


# ─── info endpoint ────────────────────────────────────────────────


def test_imports_info_returns_directory_path(
    client: TestClient, tmp_path: Path
) -> None:
    response = client.get("/api/imports/info")
    assert response.status_code == 200
    body = response.json()
    assert body["imports_dir"].endswith("imports")
    # The endpoint also seeds the README.
    assert (Path(body["imports_dir"]) / "README.md").is_file()
    # Empty install — no processed/failed yet.
    assert body["processed"] == []
    assert body["failed"] == []


def test_imports_info_lists_processed_after_upload(
    client: TestClient, origin_registry: ApplicationRegistry
) -> None:
    payload = _bundle_bytes(origin_registry)
    client.post(
        "/api/imports/tfreport",
        files={"file": ("demo.tfreport", payload, "application/zip")},
    )
    info = client.get("/api/imports/info").json()
    assert any(
        entry["name"] == "demo.tfreport" for entry in info["processed"]
    )
