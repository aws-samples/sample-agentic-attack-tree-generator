"""Unit tests for FilesystemBrowser."""

from __future__ import annotations

from pathlib import Path

import pytest

from server.filesystem import (
    FilesystemBrowser,
    PathNotFoundError,
    PathTraversalError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_tree(tmp_path: Path) -> Path:
    """Create a small directory tree for testing.

    Structure:
        root/
            file_a.txt   (11 bytes)
            file_b.json  (2 bytes)
            subdir/
                nested.md (7 bytes)
    """
    (tmp_path / "file_a.txt").write_text("hello world")
    (tmp_path / "file_b.json").write_text("{}")
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "nested.md").write_text("# title")
    return tmp_path


@pytest.fixture()
def browser(sample_tree: Path) -> FilesystemBrowser:
    return FilesystemBrowser(allowed_roots=[sample_tree])


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


class TestValidatePath:
    def test_valid_directory(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        assert browser.validate_path(sample_tree) is True

    def test_valid_file(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        assert browser.validate_path(sample_tree / "file_a.txt") is True

    def test_valid_nested(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        assert browser.validate_path(sample_tree / "subdir" / "nested.md") is True

    def test_nonexistent_path_raises(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        with pytest.raises(PathNotFoundError):
            browser.validate_path(sample_tree / "nope")

    def test_traversal_with_dotdot_raises(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        outside = sample_tree / ".." / ".."
        with pytest.raises(PathTraversalError):
            browser.validate_path(outside)

    def test_traversal_absolute_path_raises(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        browser = FilesystemBrowser(allowed_roots=[allowed])
        with pytest.raises(PathTraversalError):
            browser.validate_path(outside)

    def test_symlink_escape_raises(self, tmp_path: Path) -> None:
        """A symlink inside the allowed root that points outside must be rejected."""
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside_dir"
        outside.mkdir()
        link = allowed / "sneaky_link"
        link.symlink_to(outside)
        browser = FilesystemBrowser(allowed_roots=[allowed])
        with pytest.raises(PathTraversalError):
            browser.validate_path(link)


# ---------------------------------------------------------------------------
# list_directory
# ---------------------------------------------------------------------------


class TestListDirectory:
    def test_lists_root_entries(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        names = {e.name for e in listing.entries}
        assert names == {"file_a.txt", "file_b.json", "subdir"}

    def test_current_path_is_resolved(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        assert listing.current_path == str(sample_tree.resolve())

    def test_parent_path_at_root(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        """At the allowed root, parent_path should be None."""
        listing = browser.list_directory(sample_tree)
        assert listing.parent_path is None

    def test_parent_path_in_subdir(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree / "subdir")
        assert listing.parent_path == str(sample_tree.resolve())

    def test_entry_types(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        types = {e.name: e.entry_type for e in listing.entries}
        assert types["file_a.txt"] == "file"
        assert types["subdir"] == "directory"

    def test_file_sizes(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        sizes = {e.name: e.size for e in listing.entries}
        assert sizes["file_a.txt"] == 11
        assert sizes["file_b.json"] == 2
        # Directories don't have a size
        assert sizes["subdir"] is None

    def test_modification_dates_present(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        for entry in listing.entries:
            assert entry.modified is not None

    def test_empty_directory(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        browser = FilesystemBrowser(allowed_roots=[tmp_path])
        listing = browser.list_directory(empty)
        assert listing.entries == []

    def test_not_a_directory_raises(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        with pytest.raises(NotADirectoryError):
            browser.list_directory(sample_tree / "file_a.txt")

    def test_nonexistent_raises(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        with pytest.raises(PathNotFoundError):
            browser.list_directory(sample_tree / "ghost")

    def test_traversal_raises(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        with pytest.raises(PathTraversalError):
            browser.list_directory(sample_tree / ".." / "..")

    def test_entries_sorted_by_name(self, browser: FilesystemBrowser, sample_tree: Path) -> None:
        listing = browser.list_directory(sample_tree)
        names = [e.name for e in listing.entries]
        assert names == sorted(names)

    def test_multiple_allowed_roots(self, tmp_path: Path) -> None:
        root_a = tmp_path / "a"
        root_b = tmp_path / "b"
        root_a.mkdir()
        root_b.mkdir()
        (root_a / "fa.txt").write_text("a")
        (root_b / "fb.txt").write_text("b")
        browser = FilesystemBrowser(allowed_roots=[root_a, root_b])
        listing_a = browser.list_directory(root_a)
        listing_b = browser.list_directory(root_b)
        assert {e.name for e in listing_a.entries} == {"fa.txt"}
        assert {e.name for e in listing_b.entries} == {"fb.txt"}
