"""Unit tests for ApplicationRegistry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from server.registry import ApplicationRegistry, slugify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ATTACK_TREES = Path(".threatforest") / "output"


def _make_app(
    root: Path,
    name: str,
    *,
    metadata: dict | None = None,
    versions: list[str] | None = None,
) -> Path:
    """Create a project directory with the expected ThreatForest structure.

    Returns the project directory path.
    """
    project = root / name
    at_dir = project / ATTACK_TREES
    at_dir.mkdir(parents=True)

    meta = metadata or {"name": name, "description": f"Desc for {name}"}
    (at_dir / "threatforest_data.json").write_text(
        json.dumps(meta), encoding="utf-8"
    )

    for v in versions or []:
        ver_dir = at_dir / v
        ver_dir.mkdir()

    return project


# ---------------------------------------------------------------------------
# slugify
# ---------------------------------------------------------------------------


class TestSlugify:
    def test_lowercase(self) -> None:
        assert slugify("MyProject") == "myproject"

    def test_spaces_to_hyphens(self) -> None:
        assert slugify("My Project") == "my-project"

    def test_special_chars(self) -> None:
        assert slugify("app@v2.0!") == "app-v2-0"

    def test_strips_leading_trailing_hyphens(self) -> None:
        assert slugify("--hello--") == "hello"

    def test_empty_string(self) -> None:
        assert slugify("") == ""

    def test_already_slug(self) -> None:
        assert slugify("my-app") == "my-app"


# ---------------------------------------------------------------------------
# discover_applications
# ---------------------------------------------------------------------------


class TestDiscoverApplications:
    def test_no_scan_paths(self) -> None:
        registry = ApplicationRegistry(scan_paths=[])
        assert registry.discover_applications() == []

    def test_nonexistent_scan_path(self, tmp_path: Path) -> None:
        registry = ApplicationRegistry(
            scan_paths=[tmp_path / "does_not_exist"]
        )
        assert registry.discover_applications() == []

    def test_empty_scan_path(self, tmp_path: Path) -> None:
        registry = ApplicationRegistry(scan_paths=[tmp_path])
        assert registry.discover_applications() == []

    def test_single_application(self, tmp_path: Path) -> None:
        _make_app(tmp_path, "MyApp", versions=["2024-01-15"])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert len(apps) == 1
        assert apps[0].id == "myapp"
        assert apps[0].name == "MyApp"
        assert apps[0].version_count == 1

    def test_multiple_applications(self, tmp_path: Path) -> None:
        _make_app(tmp_path, "Alpha", versions=["2024-01-01"])
        _make_app(tmp_path, "Beta", versions=["2024-02-01", "2024-03-01"])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert len(apps) == 2
        ids = {a.id for a in apps}
        assert ids == {"alpha", "beta"}

    def test_version_count_reflects_directories(self, tmp_path: Path) -> None:
        _make_app(tmp_path, "App", versions=["v1", "v2", "v3"])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].version_count == 3

    def test_skips_project_without_metadata(self, tmp_path: Path) -> None:
        """A project dir without threatforest_data.json is ignored."""
        project = tmp_path / "NoMeta"
        (project / ATTACK_TREES).mkdir(parents=True)
        # No JSON file created

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        assert registry.discover_applications() == []

    def test_skips_malformed_json(self, tmp_path: Path) -> None:
        project = tmp_path / "BadJson"
        at_dir = project / ATTACK_TREES
        at_dir.mkdir(parents=True)
        (at_dir / "threatforest_data.json").write_text(
            "NOT VALID JSON", encoding="utf-8"
        )

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        assert registry.discover_applications() == []

    def test_description_from_metadata(self, tmp_path: Path) -> None:
        _make_app(
            tmp_path,
            "Described",
            metadata={"name": "Described", "description": "A cool app"},
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].description == "A cool app"

    def test_name_falls_back_to_dir_name(self, tmp_path: Path) -> None:
        """If metadata has no 'name' key, use the directory name."""
        _make_app(
            tmp_path,
            "FallbackName",
            metadata={"description": "no name key"},
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].name == "FallbackName"

    def test_last_run_date_is_most_recent(self, tmp_path: Path) -> None:
        _make_app(
            tmp_path,
            "Dated",
            versions=["2024-01-01", "2024-06-15", "2024-03-10"],
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert "2024-06-15" in apps[0].last_run_date

    def test_no_versions_flat_layout(self, tmp_path: Path) -> None:
        """App with no version dirs but metadata = flat layout (version_count=1)."""
        _make_app(tmp_path, "NoVersions", versions=[])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].version_count == 1
        assert apps[0].last_run_date != ""

    def test_multiple_scan_paths(self, tmp_path: Path) -> None:
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        _make_app(root_a, "AppA", versions=["v1"])
        _make_app(root_b, "AppB", versions=["v1"])

        registry = ApplicationRegistry(scan_paths=[root_a, root_b])
        apps = registry.discover_applications()
        assert len(apps) == 2

    def test_duplicate_app_id_across_scan_paths(self, tmp_path: Path) -> None:
        """If the same slug appears in two scan paths, only the first wins."""
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        _make_app(root_a, "SameApp", versions=["v1"])
        _make_app(root_b, "SameApp", versions=["v1", "v2"])

        registry = ApplicationRegistry(scan_paths=[root_a, root_b])
        apps = registry.discover_applications()
        assert len(apps) == 1
        # First scan path wins — version_count == 1
        assert apps[0].version_count == 1

    def test_files_in_scan_path_are_ignored(self, tmp_path: Path) -> None:
        """Non-directory entries in the scan path should be skipped."""
        (tmp_path / "random_file.txt").write_text("hi")
        _make_app(tmp_path, "RealApp", versions=["v1"])

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        apps = registry.discover_applications()
        assert len(apps) == 1


# ---------------------------------------------------------------------------
# get_versions
# ---------------------------------------------------------------------------


class TestGetVersions:
    def test_returns_empty_for_unknown_app(self, tmp_path: Path) -> None:
        registry = ApplicationRegistry(scan_paths=[tmp_path])
        assert registry.get_versions("nonexistent") == []

    def test_returns_versions_sorted_descending(self, tmp_path: Path) -> None:
        _make_app(
            tmp_path,
            "App",
            versions=["2024-01-01", "2024-06-15", "2024-03-10"],
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        versions = registry.get_versions("app")
        dates = [v.run_date for v in versions]
        assert dates == sorted(dates, reverse=True)

    def test_version_id_is_dir_name(self, tmp_path: Path) -> None:
        _make_app(tmp_path, "App", versions=["v1", "v2"])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        versions = registry.get_versions("app")
        ids = {v.id for v in versions}
        assert ids == {"v1", "v2"}

    def test_version_metadata_from_version_dir(self, tmp_path: Path) -> None:
        """If a version dir has its own threatforest_data.json, use it."""
        project = _make_app(tmp_path, "App", versions=["2024-01-01"])
        ver_dir = project / ATTACK_TREES / "2024-01-01"
        (ver_dir / "threatforest_data.json").write_text(
            json.dumps({
                "threat_count": 42,
                "categories": ["injection", "xss"],
                "status": "complete",
            }),
            encoding="utf-8",
        )

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        versions = registry.get_versions("app")
        assert len(versions) == 1
        assert versions[0].threat_count == 42
        assert versions[0].categories == ["injection", "xss"]
        assert versions[0].status == "complete"

    def test_version_metadata_falls_back_to_parent(self, tmp_path: Path) -> None:
        """Without per-version metadata, fall back to the parent JSON."""
        _make_app(
            tmp_path,
            "App",
            metadata={
                "name": "App",
                "description": "d",
                "threat_count": 10,
                "categories": ["dos"],
            },
            versions=["2024-01-01"],
        )

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        versions = registry.get_versions("app")
        assert versions[0].threat_count == 10
        assert versions[0].categories == ["dos"]

    def test_version_defaults_when_no_metadata(self, tmp_path: Path) -> None:
        """When no metadata is available, defaults are used."""
        _make_app(tmp_path, "App", versions=["v1"])
        # Remove the parent metadata file
        meta_file = tmp_path / "App" / ATTACK_TREES / "threatforest_data.json"
        meta_file.unlink()
        # Re-create it so discover still works but with minimal data
        meta_file.write_text(json.dumps({"name": "App"}), encoding="utf-8")

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        versions = registry.get_versions("app")
        assert versions[0].threat_count == 0
        assert versions[0].categories == []
        assert versions[0].status == "complete"

    def test_non_directory_children_ignored(self, tmp_path: Path) -> None:
        """Files inside attack_trees/ (like the JSON) are not versions."""
        _make_app(tmp_path, "App", versions=["v1"])
        # The JSON file already exists; add another stray file
        at_dir = tmp_path / "App" / ATTACK_TREES
        (at_dir / "notes.txt").write_text("stray file")

        registry = ApplicationRegistry(scan_paths=[tmp_path])
        versions = registry.get_versions("app")
        assert len(versions) == 1
        assert versions[0].id == "v1"

    def test_flat_layout_returns_latest_version(self, tmp_path: Path) -> None:
        """Flat layout (no version dirs, metadata exists) returns single 'latest' version."""
        _make_app(tmp_path, "App", versions=[])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        versions = registry.get_versions("app")
        assert len(versions) == 1
        assert versions[0].id == "latest"
        assert versions[0].status == "complete"


# ---------------------------------------------------------------------------
# Flat layout tests
# ---------------------------------------------------------------------------


def _make_flat_app(
    root: Path,
    name: str,
    *,
    metadata: dict | None = None,
    include_dashboard: bool = False,
) -> Path:
    """Create a flat-layout project (no version subdirs under attack_trees/).

    Returns the project directory path.
    """
    project = root / name
    at_dir = project / ATTACK_TREES
    at_dir.mkdir(parents=True)

    meta = metadata or {"name": name, "description": f"Desc for {name}"}
    (at_dir / "threatforest_data.json").write_text(
        json.dumps(meta), encoding="utf-8"
    )

    if include_dashboard:
        (at_dir / "attack_trees_dashboard.html").write_text(
            "<html><body>Dashboard</body></html>", encoding="utf-8"
        )

    return project


class TestFlatLayoutDiscovery:
    """Tests for flat layout application discovery (no version subdirs)."""

    def test_flat_layout_version_count_is_one(self, tmp_path: Path) -> None:
        _make_flat_app(tmp_path, "FlatApp")
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert len(apps) == 1
        assert apps[0].version_count == 1

    def test_flat_layout_has_run_date(self, tmp_path: Path) -> None:
        _make_flat_app(tmp_path, "FlatApp")
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].last_run_date != ""

    def test_flat_layout_with_dashboard(self, tmp_path: Path) -> None:
        _make_flat_app(tmp_path, "FlatApp", include_dashboard=True)
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].dashboard_path is not None
        assert "attack_trees_dashboard.html" in apps[0].dashboard_path

    def test_flat_layout_without_dashboard(self, tmp_path: Path) -> None:
        _make_flat_app(tmp_path, "FlatApp", include_dashboard=False)
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].dashboard_path is None

    def test_versioned_app_has_no_dashboard_path(self, tmp_path: Path) -> None:
        """Versioned layout apps should not get a dashboard_path."""
        _make_app(tmp_path, "VersionedApp", versions=["v1", "v2"])
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert apps[0].dashboard_path is None

    def test_mixed_versioned_and_flat(self, tmp_path: Path) -> None:
        """Scan path with both versioned and flat layout apps."""
        _make_app(tmp_path, "VersionedApp", versions=["v1"])
        _make_flat_app(tmp_path, "FlatApp", include_dashboard=True)
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        apps = registry.discover_applications()
        assert len(apps) == 2
        flat = next(a for a in apps if a.id == "flatapp")
        versioned = next(a for a in apps if a.id == "versionedapp")
        assert flat.version_count == 1
        assert flat.dashboard_path is not None
        assert versioned.version_count == 1
        assert versioned.dashboard_path is None


class TestFlatLayoutVersions:
    """Tests for get_versions() with flat layout."""

    def test_flat_layout_returns_single_latest(self, tmp_path: Path) -> None:
        _make_flat_app(
            tmp_path,
            "FlatApp",
            metadata={
                "name": "FlatApp",
                "description": "d",
                "threat_count": 5,
                "categories": ["spoofing"],
                "status": "complete",
            },
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        versions = registry.get_versions("flatapp")
        assert len(versions) == 1
        assert versions[0].id == "latest"
        assert versions[0].threat_count == 5
        assert versions[0].categories == ["spoofing"]
        assert versions[0].status == "complete"
        assert versions[0].run_date != ""

    def test_flat_layout_defaults_when_metadata_minimal(self, tmp_path: Path) -> None:
        _make_flat_app(
            tmp_path,
            "FlatApp",
            metadata={"name": "FlatApp"},
        )
        registry = ApplicationRegistry(scan_paths=[tmp_path])

        versions = registry.get_versions("flatapp")
        assert len(versions) == 1
        assert versions[0].id == "latest"
        assert versions[0].threat_count == 0
        assert versions[0].categories == []
        assert versions[0].status == "complete"
