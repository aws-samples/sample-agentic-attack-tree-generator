"""Tests for sandboxed file tools — path validation and access control."""

import os
import tempfile

import pytest

from threatforest.tools.sandboxed_file import _validate_path


class TestValidatePath:
    def test_allowed_path_passes(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = _validate_path(str(f), [str(tmp_path)])
        assert result == f.resolve()

    def test_disallowed_path_raises(self, tmp_path):
        with pytest.raises(PermissionError, match="Access denied"):
            _validate_path("/etc/passwd", [str(tmp_path)])

    def test_traversal_blocked(self, tmp_path):
        evil_path = str(tmp_path / ".." / ".." / "etc" / "passwd")
        with pytest.raises(PermissionError, match="Access denied"):
            _validate_path(evil_path, [str(tmp_path)])

    def test_symlink_resolved(self, tmp_path):
        """Symlink inside allowed dir pointing outside should be rejected."""
        target = tempfile.mktemp()  # path outside tmp_path
        with open(target, "w") as f:
            f.write("secret")
        try:
            link = tmp_path / "sneaky_link"
            link.symlink_to(target)
            with pytest.raises(PermissionError, match="Access denied"):
                _validate_path(str(link), [str(tmp_path)])
        finally:
            os.unlink(target)

    def test_multiple_allowed_prefixes(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        f = dir_b / "file.txt"
        f.write_text("ok")
        result = _validate_path(str(f), [str(dir_a), str(dir_b)])
        assert result == f.resolve()

    def test_subdirectory_allowed(self, tmp_path):
        sub = tmp_path / "deep" / "nested"
        sub.mkdir(parents=True)
        f = sub / "file.txt"
        f.write_text("ok")
        result = _validate_path(str(f), [str(tmp_path)])
        assert result == f.resolve()
