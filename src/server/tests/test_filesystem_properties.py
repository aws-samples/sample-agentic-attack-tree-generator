"""Property-based tests for FilesystemBrowser.

Uses Hypothesis to verify correctness properties across randomly generated
directory structures and paths.
"""

from __future__ import annotations

import os
import string
import tempfile
from pathlib import Path

import hypothesis
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from server.filesystem import (
    FilesystemBrowser,
    PathNotFoundError,
    PathTraversalError,
)

# ---------------------------------------------------------------------------
# Hypothesis settings — minimum 100 examples per property
# ---------------------------------------------------------------------------

PBT_SETTINGS = settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid filesystem-safe names: 1-20 chars, alphanumeric + underscore/hyphen/dot
# Avoids names that are problematic on various OSes.
_SAFE_CHARS = string.ascii_lowercase + string.digits + "_-"

safe_name = st.text(
    alphabet=_SAFE_CHARS,
    min_size=1,
    max_size=12,
).filter(lambda n: n not in (".", "..") and not n.startswith("."))

# File content: small random bytes
file_content = st.binary(min_size=0, max_size=64)

# File extension
file_ext = st.sampled_from([".txt", ".json", ".md", ".yaml", ".py", ""])


def _name_with_ext(name: str, ext: str) -> str:
    """Combine a base name with an extension, ensuring uniqueness."""
    return f"{name}{ext}" if ext else name


# Strategy that builds a random directory tree inside a given root.
# Returns (root_path, expected_entries_at_root) where expected_entries_at_root
# is a set of (name, type) tuples.
@st.composite
def random_directory_tree(draw: st.DrawFn):
    """Create a temporary directory with random files and subdirectories.

    Returns (tmp_dir_path, set_of_entry_tuples) where each tuple is
    (name: str, entry_type: "file" | "directory").
    """
    tmp_dir = Path(tempfile.mkdtemp())

    # Draw a list of file entries
    num_files = draw(st.integers(min_value=0, max_value=8))
    num_dirs = draw(st.integers(min_value=0, max_value=5))

    used_names: set[str] = set()
    expected: set[tuple[str, str]] = set()

    # Create files
    for _ in range(num_files):
        base = draw(safe_name)
        ext = draw(file_ext)
        name = _name_with_ext(base, ext)
        if name in used_names:
            continue
        used_names.add(name)
        content = draw(file_content)
        (tmp_dir / name).write_bytes(content)
        expected.add((name, "file"))

    # Create subdirectories
    for _ in range(num_dirs):
        name = draw(safe_name)
        if name in used_names:
            continue
        used_names.add(name)
        (tmp_dir / name).mkdir(exist_ok=True)
        expected.add((name, "directory"))

    return tmp_dir, expected


@st.composite
def nonexistent_path_under(draw: st.DrawFn, root: Path):
    """Generate a path that does NOT exist under root."""
    segments = draw(st.lists(safe_name, min_size=1, max_size=4))
    candidate = root
    for seg in segments:
        candidate = candidate / seg
    # Ensure it truly doesn't exist by appending a unique suffix
    candidate = candidate.parent / (candidate.name + "_nonexistent_xyz")
    hypothesis.assume(not candidate.exists())
    return candidate


# ---------------------------------------------------------------------------
# Property 3: Filesystem browse correctness
# ---------------------------------------------------------------------------
# Feature: threatforest-landing-page, Property 3: Filesystem browse correctness
# For any valid directory path on the server, the GET /api/filesystem/browse
# endpoint SHALL return a DirectoryListing whose entries match exactly the
# files and subdirectories present in that directory (no missing entries,
# no phantom entries).
# Validates: Requirements 2.4


class TestProperty3FilesystemBrowseCorrectness:
    """Property 3: Filesystem browse correctness."""

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_listing_matches_actual_directory_contents(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """For any random directory tree, list_directory returns entries
        matching exactly the files and subdirectories present."""
        tmp_dir, expected_entries = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            listing = browser.list_directory(tmp_dir)

            # Build the set of (name, entry_type) from the listing
            actual_entries = {
                (e.name, e.entry_type) for e in listing.entries
            }

            # No missing entries, no phantom entries
            assert actual_entries == expected_entries, (
                f"Mismatch:\n"
                f"  Missing from listing: {expected_entries - actual_entries}\n"
                f"  Phantom in listing:   {actual_entries - expected_entries}"
            )
        finally:
            # Cleanup temp directory
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_entry_types_are_correct(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """Each entry's type field correctly reflects whether it is a file
        or directory on disk."""
        tmp_dir, _ = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            listing = browser.list_directory(tmp_dir)

            for entry in listing.entries:
                full_path = Path(listing.current_path) / entry.name
                if entry.entry_type == "file":
                    assert full_path.is_file(), (
                        f"{entry.name} marked as file but is not a file on disk"
                    )
                elif entry.entry_type == "directory":
                    assert full_path.is_dir(), (
                        f"{entry.name} marked as directory but is not a dir on disk"
                    )
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_current_path_matches_resolved_input(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """The current_path in the listing matches the resolved input path."""
        tmp_dir, _ = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            listing = browser.list_directory(tmp_dir)

            assert listing.current_path == str(tmp_dir.resolve())
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_file_entries_have_size(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """File entries have a non-negative size; directory entries have None."""
        tmp_dir, _ = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            listing = browser.list_directory(tmp_dir)

            for entry in listing.entries:
                if entry.entry_type == "file":
                    assert entry.size is not None and entry.size >= 0
                else:
                    assert entry.size is None
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Property 4: Run config path validation
# ---------------------------------------------------------------------------
# Feature: threatforest-landing-page, Property 4: Run config path validation
# For any string submitted as project_path to POST /api/runs, if the path
# does not exist on the filesystem or is not a directory, the endpoint SHALL
# return HTTP 400. If the path exists and is a directory, the endpoint SHALL
# accept the request.
# Validates: Requirements 2.5, 2.6


class TestProperty4RunConfigPathValidation:
    """Property 4: Run config path validation."""

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_valid_directory_is_accepted(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """A path that exists and is a directory under allowed roots
        is accepted by validate_path."""
        tmp_dir, _ = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            result = browser.validate_path(tmp_dir)
            assert result is True
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_nonexistent_path_is_rejected(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """A path that does not exist raises PathNotFoundError."""
        tmp_dir, _ = data

        try:
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])
            fake_path = tmp_dir / "this_path_does_not_exist_abc123"
            hypothesis.assume(not fake_path.exists())

            with __import__("pytest").raises(PathNotFoundError):
                browser.validate_path(fake_path)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(data=random_directory_tree())
    @PBT_SETTINGS
    def test_file_path_is_accepted_but_not_a_directory(
        self,
        data: tuple[Path, set[tuple[str, str]]],
    ) -> None:
        """validate_path accepts files (they exist), but list_directory
        rejects them since they are not directories. This models the
        two-step validation: path must exist AND be a directory."""
        tmp_dir, expected_entries = data

        try:
            # Find a file entry if one exists
            file_entries = [
                name for name, etype in expected_entries if etype == "file"
            ]
            if not file_entries:
                return  # Skip if no files were generated

            file_path = tmp_dir / file_entries[0]
            browser = FilesystemBrowser(allowed_roots=[tmp_dir])

            # validate_path accepts it (it exists and is under allowed root)
            assert browser.validate_path(file_path) is True

            # But list_directory rejects it (not a directory)
            with __import__("pytest").raises(NotADirectoryError):
                browser.list_directory(file_path)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(
        suffix=st.text(
            alphabet=string.ascii_lowercase + string.digits,
            min_size=1,
            max_size=10,
        )
    )
    @PBT_SETTINGS
    def test_path_outside_allowed_roots_is_rejected(
        self,
        suffix: str,
    ) -> None:
        """A path outside the allowed roots raises PathTraversalError."""
        tmp_dir = Path(tempfile.mkdtemp())
        allowed = tmp_dir / "allowed"
        outside = tmp_dir / "outside"
        allowed.mkdir()
        outside.mkdir()

        try:
            browser = FilesystemBrowser(allowed_roots=[allowed])

            with __import__("pytest").raises(PathTraversalError):
                browser.validate_path(outside)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @given(
        segments=st.lists(
            st.text(
                alphabet=string.ascii_lowercase,
                min_size=1,
                max_size=6,
            ),
            min_size=1,
            max_size=3,
        )
    )
    @PBT_SETTINGS
    def test_traversal_via_dotdot_is_rejected(
        self,
        segments: list[str],
    ) -> None:
        """Paths using '..' to escape allowed roots are rejected."""
        tmp_dir = Path(tempfile.mkdtemp())
        allowed = tmp_dir / "allowed"
        allowed.mkdir()

        try:
            browser = FilesystemBrowser(allowed_roots=[allowed])

            # Build a path that tries to escape via ..
            escape_path = allowed
            for _ in range(len(segments) + 2):
                escape_path = escape_path / ".."

            # The resolved path should be outside allowed roots
            resolved = escape_path.resolve()
            if resolved.exists() and not any(
                True
                for root in browser.allowed_roots
                if str(resolved).startswith(str(root))
            ):
                with __import__("pytest").raises(
                    (PathTraversalError, PathNotFoundError)
                ):
                    browser.validate_path(escape_path)
        finally:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
