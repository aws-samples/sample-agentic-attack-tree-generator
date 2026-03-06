"""Property-based tests for ApplicationRegistry.

Uses Hypothesis to verify correctness properties across randomly generated
project directory structures.
"""

from __future__ import annotations

import json
import string
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import hypothesis
from hypothesis import given, settings, HealthCheck, assume
from hypothesis import strategies as st

from server.registry import ApplicationRegistry, slugify

# ---------------------------------------------------------------------------
# Hypothesis settings — minimum 100 examples per property
# ---------------------------------------------------------------------------

PBT_SETTINGS = settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACK_TREES_REL = Path("threatforest") / "attack_trees"
METADATA_FILE = "threatforest_data.json"

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Safe directory names: lowercase alphanumeric + hyphens/underscores
_SAFE_CHARS = string.ascii_lowercase + string.digits + "_-"

safe_name = st.text(
    alphabet=_SAFE_CHARS,
    min_size=1,
    max_size=12,
).filter(lambda n: n not in (".", "..") and not n.startswith("."))

# Strategy for generating unique project names (sets guarantee no dupes)
project_name_sets = st.frozensets(safe_name, min_size=0, max_size=8)

# Date-format version directory names
date_version_name = st.dates(
    min_value=datetime(2020, 1, 1).date(),
    max_value=datetime(2030, 12, 31).date(),
).map(lambda d: d.strftime("%Y-%m-%d"))

# Compact date format (YYYYMMDD)
compact_date_version_name = st.dates(
    min_value=datetime(2020, 1, 1).date(),
    max_value=datetime(2030, 12, 31).date(),
).map(lambda d: d.strftime("%Y%m%d"))

# Non-date version names that will fall back to mtime
non_date_version_name = st.text(
    alphabet=string.ascii_lowercase + string.digits,
    min_size=1,
    max_size=8,
).filter(lambda n: n not in (".", "..") and not n.startswith("."))

# Mixed version name strategy
version_name = st.one_of(date_version_name, compact_date_version_name, non_date_version_name)


@st.composite
def valid_project_set(draw: st.DrawFn):
    """Generate a temp directory containing a random set of valid ThreatForest
    project directories, each with the required marker file.

    Returns (tmp_dir, set_of_project_names) where each project name has the
    full threatforest/attack_trees/threatforest_data.json structure.
    """
    tmp_dir = Path(tempfile.mkdtemp())
    names = draw(project_name_sets)

    for name in names:
        project_dir = tmp_dir / name
        at_dir = project_dir / ATTACK_TREES_REL
        at_dir.mkdir(parents=True)
        metadata = {"name": name, "description": f"Desc for {name}"}
        (at_dir / METADATA_FILE).write_text(
            json.dumps(metadata), encoding="utf-8"
        )

    return tmp_dir, names


@st.composite
def mixed_project_directory(draw: st.DrawFn):
    """Generate a temp directory with a mix of valid projects, invalid projects
    (missing metadata), and plain files.

    Returns (tmp_dir, set_of_valid_project_names).
    """
    tmp_dir = Path(tempfile.mkdtemp())

    valid_names = draw(st.frozensets(safe_name, min_size=0, max_size=6))
    invalid_names = draw(
        st.frozensets(safe_name, min_size=0, max_size=4).filter(
            lambda s: s.isdisjoint(valid_names)
        )
    )
    file_names = draw(
        st.frozensets(safe_name, min_size=0, max_size=3).filter(
            lambda s: s.isdisjoint(valid_names | invalid_names)
        )
    )

    # Create valid projects with metadata
    for name in valid_names:
        project_dir = tmp_dir / name
        at_dir = project_dir / ATTACK_TREES_REL
        at_dir.mkdir(parents=True)
        metadata = {"name": name, "description": f"Desc for {name}"}
        (at_dir / METADATA_FILE).write_text(
            json.dumps(metadata), encoding="utf-8"
        )

    # Create invalid projects (directory structure but no metadata file)
    for name in invalid_names:
        project_dir = tmp_dir / name
        at_dir = project_dir / ATTACK_TREES_REL
        at_dir.mkdir(parents=True)
        # No metadata file

    # Create plain files (not directories)
    for name in file_names:
        (tmp_dir / name).write_text("not a project", encoding="utf-8")

    return tmp_dir, valid_names


@st.composite
def app_with_versions(draw: st.DrawFn):
    """Generate a temp directory with a single application containing
    multiple version directories with various date-format names.

    Returns (tmp_dir, app_name, list_of_version_dir_names).
    """
    tmp_dir = Path(tempfile.mkdtemp())
    app_name = draw(safe_name)

    # Generate unique version names
    num_versions = draw(st.integers(min_value=1, max_value=10))
    version_names_set: set[str] = set()
    for _ in range(num_versions):
        vname = draw(version_name)
        version_names_set.add(vname)

    version_names = sorted(version_names_set)  # deterministic order for creation

    project_dir = tmp_dir / app_name
    at_dir = project_dir / ATTACK_TREES_REL
    at_dir.mkdir(parents=True)

    metadata = {"name": app_name, "description": f"Desc for {app_name}"}
    (at_dir / METADATA_FILE).write_text(
        json.dumps(metadata), encoding="utf-8"
    )

    for vname in version_names:
        (at_dir / vname).mkdir(exist_ok=True)

    return tmp_dir, app_name, list(version_names_set)


# ---------------------------------------------------------------------------
# Property 1: Application discovery completeness
# ---------------------------------------------------------------------------
# Feature: threatforest-landing-page, Property 1: Application discovery completeness
# For any set of project directories containing a `threatforest/attack_trees/`
# subdirectory with a `threatforest_data.json` file, the GET /api/applications
# endpoint SHALL return an application entry for each such directory, with no
# omissions and no duplicates.
# Validates: Requirements 2.1


class TestProperty1ApplicationDiscoveryCompleteness:
    """Property 1: Application discovery completeness."""

    @given(data=valid_project_set())
    @PBT_SETTINGS
    def test_discovers_all_valid_projects(
        self,
        data: tuple[Path, frozenset[str]],
    ) -> None:
        """For any set of valid project directories, discover_applications
        returns exactly one entry per project with no omissions."""
        tmp_dir, project_names = data

        try:
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            apps = registry.discover_applications()

            expected_ids = {slugify(name) for name in project_names}
            actual_ids = {app.id for app in apps}

            assert actual_ids == expected_ids, (
                f"Mismatch:\n"
                f"  Missing: {expected_ids - actual_ids}\n"
                f"  Extra:   {actual_ids - expected_ids}"
            )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=valid_project_set())
    @PBT_SETTINGS
    def test_no_duplicate_entries(
        self,
        data: tuple[Path, frozenset[str]],
    ) -> None:
        """For any set of valid project directories, discover_applications
        returns no duplicate application IDs."""
        tmp_dir, project_names = data

        try:
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            apps = registry.discover_applications()

            ids = [app.id for app in apps]
            assert len(ids) == len(set(ids)), (
                f"Duplicate IDs found: {ids}"
            )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=mixed_project_directory())
    @PBT_SETTINGS
    def test_only_valid_projects_discovered(
        self,
        data: tuple[Path, frozenset[str]],
    ) -> None:
        """Only directories with the full marker structure are discovered;
        invalid projects and plain files are excluded."""
        tmp_dir, valid_names = data

        try:
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            apps = registry.discover_applications()

            expected_ids = {slugify(name) for name in valid_names}
            actual_ids = {app.id for app in apps}

            assert actual_ids == expected_ids, (
                f"Mismatch:\n"
                f"  Missing: {expected_ids - actual_ids}\n"
                f"  Extra:   {actual_ids - expected_ids}"
            )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=valid_project_set())
    @PBT_SETTINGS
    def test_app_count_matches_project_count(
        self,
        data: tuple[Path, frozenset[str]],
    ) -> None:
        """The number of discovered applications equals the number of valid
        project directories (accounting for slug collisions)."""
        tmp_dir, project_names = data

        try:
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            apps = registry.discover_applications()

            # Unique slugs may be fewer than project names if slugify
            # produces collisions
            expected_unique_slugs = {slugify(name) for name in project_names}
            assert len(apps) == len(expected_unique_slugs)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Property 2: Version sorting invariant
# ---------------------------------------------------------------------------
# Feature: threatforest-landing-page, Property 2: Version sorting invariant
# For any application with multiple threat model versions, the
# GET /api/applications/{app_id}/versions endpoint SHALL return versions such
# that for every consecutive pair (v[i], v[i+1]), the run_date of v[i] is
# greater than or equal to the run_date of v[i+1].
# Validates: Requirements 2.2


class TestProperty2VersionSortingInvariant:
    """Property 2: Version sorting invariant."""

    @given(data=app_with_versions())
    @PBT_SETTINGS
    def test_versions_sorted_descending_by_run_date(
        self,
        data: tuple[Path, str, list[str]],
    ) -> None:
        """For any application with multiple versions, get_versions returns
        them sorted by run_date descending: for every consecutive pair
        (v[i], v[i+1]), run_date of v[i] >= run_date of v[i+1]."""
        tmp_dir, app_name, version_names = data

        try:
            app_id = slugify(app_name)
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            versions = registry.get_versions(app_id)

            # Verify the sorting invariant on consecutive pairs
            for i in range(len(versions) - 1):
                assert versions[i].run_date >= versions[i + 1].run_date, (
                    f"Sorting violation at index {i}: "
                    f"v[{i}].run_date={versions[i].run_date!r} < "
                    f"v[{i+1}].run_date={versions[i+1].run_date!r}"
                )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=app_with_versions())
    @PBT_SETTINGS
    def test_all_version_dirs_are_returned(
        self,
        data: tuple[Path, str, list[str]],
    ) -> None:
        """get_versions returns one entry per version directory — no
        omissions."""
        tmp_dir, app_name, version_names = data

        try:
            app_id = slugify(app_name)
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            versions = registry.get_versions(app_id)

            actual_ids = {v.id for v in versions}
            expected_ids = set(version_names)

            assert actual_ids == expected_ids, (
                f"Mismatch:\n"
                f"  Missing: {expected_ids - actual_ids}\n"
                f"  Extra:   {actual_ids - expected_ids}"
            )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=app_with_versions())
    @PBT_SETTINGS
    def test_run_dates_are_valid_iso_format(
        self,
        data: tuple[Path, str, list[str]],
    ) -> None:
        """Every version's run_date is a valid ISO-format datetime string."""
        tmp_dir, app_name, version_names = data

        try:
            app_id = slugify(app_name)
            registry = ApplicationRegistry(scan_paths=[tmp_dir])
            versions = registry.get_versions(app_id)

            for v in versions:
                try:
                    datetime.fromisoformat(v.run_date)
                except ValueError:
                    raise AssertionError(
                        f"Version {v.id!r} has invalid ISO date: {v.run_date!r}"
                    )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
