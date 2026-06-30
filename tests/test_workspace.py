"""Tests for the Workspace abstraction and its local filesystem backend."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatforest.workspace import LocalFilesystemWorkspace, Workspace


@pytest.fixture
def workspace(tmp_path: Path) -> LocalFilesystemWorkspace:
    return LocalFilesystemWorkspace(tmp_path / "run")


def test_satisfies_workspace_protocol(workspace: LocalFilesystemWorkspace) -> None:
    assert isinstance(workspace, Workspace)


def test_round_trip_text(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_text("state/scanner_context.json", "hello")
    assert workspace.read_text("state/scanner_context.json") == "hello"


def test_round_trip_bytes(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_bytes("output/report.pdf", b"\x00PDF\xff")
    assert workspace.read_bytes("output/report.pdf") == b"\x00PDF\xff"


def test_round_trip_json(workspace: LocalFilesystemWorkspace) -> None:
    payload = {"threats": [{"id": "T1", "title": "t"}], "version": 1}
    workspace.write_json("state/threats.json", payload)
    assert workspace.read_json("state/threats.json") == payload


def test_write_creates_parent_dirs(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_text("state/nested/deep/file.json", "{}")
    assert workspace.exists("state/nested/deep/file.json")


def test_exists(workspace: LocalFilesystemWorkspace) -> None:
    assert not workspace.exists("state/threats.json")
    workspace.write_text("state/threats.json", "[]")
    assert workspace.exists("state/threats.json")


def test_delete_returns_false_for_missing_key(workspace: LocalFilesystemWorkspace) -> None:
    assert workspace.delete("state/does-not-exist.json") is False


def test_delete_removes_file(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_text("pause_state.json", "{}")
    assert workspace.delete("pause_state.json") is True
    assert not workspace.exists("pause_state.json")


def test_list_keys_returns_all_when_prefix_empty(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_text("state/a.json", "{}")
    workspace.write_text("state/b.json", "{}")
    workspace.write_text("output/c.json", "{}")
    assert sorted(workspace.list_keys()) == ["output/c.json", "state/a.json", "state/b.json"]


def test_list_keys_filters_by_prefix(workspace: LocalFilesystemWorkspace) -> None:
    workspace.write_text("state/a.json", "{}")
    workspace.write_text("state/b.json", "{}")
    workspace.write_text("output/c.json", "{}")
    assert sorted(workspace.list_keys("state")) == ["state/a.json", "state/b.json"]


def test_list_keys_for_single_file_yields_that_key(
    workspace: LocalFilesystemWorkspace,
) -> None:
    workspace.write_text("pause_state.json", "{}")
    assert list(workspace.list_keys("pause_state.json")) == ["pause_state.json"]


def test_list_keys_missing_prefix_yields_nothing(
    workspace: LocalFilesystemWorkspace,
) -> None:
    assert list(workspace.list_keys("state")) == []


def test_local_path_returns_real_filesystem_path(
    tmp_path: Path, workspace: LocalFilesystemWorkspace
) -> None:
    path = workspace.local_path("state/threats.json")
    assert path is not None
    assert path == (tmp_path / "run" / "state" / "threats.json")


def test_rejects_empty_key(workspace: LocalFilesystemWorkspace) -> None:
    with pytest.raises(ValueError):
        workspace.write_text("", "hi")


def test_rejects_absolute_key(workspace: LocalFilesystemWorkspace) -> None:
    with pytest.raises(ValueError):
        workspace.write_text("/etc/passwd", "hi")


def test_rejects_parent_traversal(workspace: LocalFilesystemWorkspace) -> None:
    with pytest.raises(ValueError):
        workspace.write_text("../escape.json", "hi")


def test_root_property_exposes_configured_directory(tmp_path: Path) -> None:
    workspace = LocalFilesystemWorkspace(tmp_path / "custom-root")
    assert workspace.root == tmp_path / "custom-root"
