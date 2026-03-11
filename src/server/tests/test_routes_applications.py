"""Unit tests for the application API endpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.registry import ApplicationRegistry
from server.routes.applications import set_registry


def _create_app_tree(root: Path, app_name: str, versions: list[dict] | None = None) -> Path:
    """Create a minimal ThreatForest application directory structure.

    Returns the project directory path.
    """
    project_dir = root / app_name
    attack_trees = project_dir / ".threatforest" / "output"
    attack_trees.mkdir(parents=True)

    metadata = {
        "name": app_name,
        "description": f"Description for {app_name}",
        "threat_count": 5,
        "categories": ["spoofing", "tampering"],
    }
    (attack_trees / "threatforest_data.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )

    if versions:
        for v in versions:
            vdir = attack_trees / v["name"]
            vdir.mkdir()
            if "metadata" in v:
                (vdir / "threatforest_data.json").write_text(
                    json.dumps(v["metadata"]), encoding="utf-8"
                )

    return project_dir


@pytest.fixture()
def scan_root(tmp_path: Path) -> Path:
    """Return a temporary scan root directory."""
    return tmp_path


@pytest.fixture()
def client(scan_root: Path):
    """TestClient wired to an ApplicationRegistry rooted at scan_root."""
    set_registry(ApplicationRegistry(scan_paths=[scan_root]))
    yield TestClient(app)


class TestListApplications:
    def test_empty_when_no_apps(self, client: TestClient) -> None:
        resp = client.get("/api/applications")
        assert resp.status_code == 200
        data = resp.json()
        assert data["applications"] == []

    def test_returns_discovered_apps(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(scan_root, "MyProject", versions=[{"name": "2024-01-15"}])
        resp = client.get("/api/applications")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["applications"]) == 1
        app_data = data["applications"][0]
        assert app_data["id"] == "myproject"
        assert app_data["name"] == "MyProject"
        assert app_data["description"] == "Description for MyProject"
        assert app_data["version_count"] == 1

    def test_returns_multiple_apps(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(scan_root, "Alpha", versions=[{"name": "2024-01-01"}])
        _create_app_tree(scan_root, "Beta", versions=[{"name": "2024-02-01"}])
        resp = client.get("/api/applications")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["applications"]) == 2
        ids = {a["id"] for a in data["applications"]}
        assert ids == {"alpha", "beta"}

    def test_response_shape(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(scan_root, "TestApp", versions=[{"name": "2024-06-01"}])
        resp = client.get("/api/applications")
        data = resp.json()
        app_data = data["applications"][0]
        assert "id" in app_data
        assert "name" in app_data
        assert "description" in app_data
        assert "version_count" in app_data
        assert "last_run_date" in app_data


class TestListVersions:
    def test_returns_versions_for_valid_app(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(
            scan_root,
            "MyProject",
            versions=[
                {"name": "2024-01-10", "metadata": {"threat_count": 3, "categories": ["spoofing"], "status": "complete"}},
                {"name": "2024-03-20", "metadata": {"threat_count": 7, "categories": ["tampering"], "status": "complete"}},
            ],
        )
        resp = client.get("/api/applications/myproject/versions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["versions"]) == 2

    def test_versions_sorted_descending(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(
            scan_root,
            "MyProject",
            versions=[
                {"name": "2024-01-10"},
                {"name": "2024-06-15"},
                {"name": "2024-03-20"},
            ],
        )
        resp = client.get("/api/applications/myproject/versions")
        data = resp.json()
        dates = [v["run_date"] for v in data["versions"]]
        assert dates == sorted(dates, reverse=True)

    def test_404_for_unknown_app(self, client: TestClient) -> None:
        resp = client.get("/api/applications/nonexistent/versions")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_version_response_shape(self, client: TestClient, scan_root: Path) -> None:
        _create_app_tree(
            scan_root,
            "MyProject",
            versions=[
                {"name": "2024-05-01", "metadata": {"threat_count": 4, "categories": ["elevation"], "status": "complete"}},
            ],
        )
        resp = client.get("/api/applications/myproject/versions")
        data = resp.json()
        v = data["versions"][0]
        assert "id" in v
        assert "run_date" in v
        assert "status" in v
        assert "threat_count" in v
        assert "categories" in v

    def test_flat_layout_versions_for_app_with_no_version_dirs(self, client: TestClient, scan_root: Path) -> None:
        """Flat layout app (no version dirs) returns single 'latest' version."""
        _create_app_tree(scan_root, "EmptyApp", versions=[])
        resp = client.get("/api/applications/emptyapp/versions")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["versions"]) == 1
        assert data["versions"][0]["id"] == "latest"
