"""Unit tests for the GET /api/filesystem/browse endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.app import app
from server.filesystem import FilesystemBrowser
from server.routes.filesystem import set_browser


@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    """Create a small directory tree for testing.

    Structure:
        root/
            file_a.txt   (11 bytes)
            subdir/
                nested.md (7 bytes)
    """
    (tmp_path / "file_a.txt").write_text("hello world")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested.md").write_text("# title")
    return tmp_path


@pytest.fixture()
def client(sample_tree: Path):
    """TestClient wired to a FilesystemBrowser rooted at sample_tree."""
    set_browser(FilesystemBrowser(allowed_roots=[sample_tree]))
    yield TestClient(app)


class TestBrowseEndpoint:
    def test_browse_valid_directory(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree)})
        assert resp.status_code == 200
        data = resp.json()
        assert data["current_path"] == str(sample_tree.resolve())
        names = {e["name"] for e in data["entries"]}
        assert "file_a.txt" in names
        assert "subdir" in names

    def test_browse_subdirectory(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree / "subdir")})
        assert resp.status_code == 200
        data = resp.json()
        names = {e["name"] for e in data["entries"]}
        assert names == {"nested.md"}

    def test_browse_returns_parent_path(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree / "subdir")})
        data = resp.json()
        assert data["parent_path"] == str(sample_tree.resolve())

    def test_404_for_nonexistent_path(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree / "nope")})
        assert resp.status_code == 404

    def test_403_for_path_traversal(self, client: TestClient, sample_tree: Path) -> None:
        outside = str(sample_tree / ".." / "..")
        resp = client.get("/api/filesystem/browse", params={"path": outside})
        assert resp.status_code == 403

    def test_400_for_file_path(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree / "file_a.txt")})
        assert resp.status_code == 400

    def test_missing_path_param_returns_422(self, client: TestClient) -> None:
        resp = client.get("/api/filesystem/browse")
        assert resp.status_code == 422

    def test_response_entry_types(self, client: TestClient, sample_tree: Path) -> None:
        resp = client.get("/api/filesystem/browse", params={"path": str(sample_tree)})
        data = resp.json()
        types = {e["name"]: e["entry_type"] for e in data["entries"]}
        assert types["file_a.txt"] == "file"
        assert types["subdir"] == "directory"
