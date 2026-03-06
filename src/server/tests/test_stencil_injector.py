"""Unit tests for the Stencil CDN injector."""

from __future__ import annotations

from pathlib import Path

import pytest

from server.stencil_injector import (
    STENCIL_CSS_URL,
    STENCIL_ESM_JS_URL,
    STENCIL_JS_URL,
    THREATFOREST_CSS_PROPERTIES,
    build_stencil_snippet,
    inject_stencil_references,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_HTML = (
    "<!DOCTYPE html>\n"
    "<html><head><title>Dashboard</title></head>"
    "<body><h1>Hello</h1></body></html>"
)

MINIMAL_HTML_UPPER_HEAD = (
    "<!DOCTYPE html>\n"
    "<html><HEAD><title>Dashboard</title></HEAD>"
    "<body><h1>Hello</h1></body></html>"
)

NO_HEAD_HTML = "<html><body><h1>No head tag</h1></body></html>"


def _write_html(tmp_path: Path, content: str, name: str = "dashboard.html") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# build_stencil_snippet
# ---------------------------------------------------------------------------


class TestBuildStencilSnippet:
    def test_contains_stencil_css_link(self) -> None:
        snippet = build_stencil_snippet()
        assert f'href="{STENCIL_CSS_URL}"' in snippet

    def test_contains_esm_script(self) -> None:
        snippet = build_stencil_snippet()
        assert f'src="{STENCIL_ESM_JS_URL}"' in snippet

    def test_contains_nomodule_script(self) -> None:
        snippet = build_stencil_snippet()
        assert f'src="{STENCIL_JS_URL}"' in snippet
        assert "nomodule" in snippet

    def test_contains_threatforest_css_properties(self) -> None:
        snippet = build_stencil_snippet()
        assert "--tf-primary:" in snippet
        assert "--tf-primary-dark:" in snippet
        assert "--tf-accent:" in snippet
        assert "--tf-bg:" in snippet
        assert "--tf-surface:" in snippet
        assert "--tf-text:" in snippet
        assert "--tf-border:" in snippet


# ---------------------------------------------------------------------------
# inject_stencil_references — success cases
# ---------------------------------------------------------------------------


class TestInjectSuccess:
    def test_injects_into_minimal_html(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML)
        result = inject_stencil_references(p)
        assert result is True

        html = p.read_text(encoding="utf-8")
        assert STENCIL_CSS_URL in html
        assert STENCIL_ESM_JS_URL in html
        assert STENCIL_JS_URL in html
        assert "--tf-primary:" in html

    def test_snippet_appears_before_head_close(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML)
        inject_stencil_references(p)

        html = p.read_text(encoding="utf-8")
        css_pos = html.find(STENCIL_CSS_URL)
        head_close_pos = html.lower().find("</head>")
        assert css_pos < head_close_pos

    def test_case_insensitive_head_tag(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML_UPPER_HEAD)
        result = inject_stencil_references(p)
        assert result is True

        html = p.read_text(encoding="utf-8")
        assert STENCIL_CSS_URL in html

    def test_preserves_existing_content(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML)
        inject_stencil_references(p)

        html = p.read_text(encoding="utf-8")
        assert "<title>Dashboard</title>" in html
        assert "<h1>Hello</h1>" in html

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML)
        result = inject_stencil_references(str(p))
        assert result is True

    def test_idempotent_no_duplicate_injection(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, MINIMAL_HTML)
        inject_stencil_references(p)
        first_html = p.read_text(encoding="utf-8")

        inject_stencil_references(p)
        second_html = p.read_text(encoding="utf-8")

        assert first_html == second_html
        assert second_html.count(STENCIL_CSS_URL) == 1


# ---------------------------------------------------------------------------
# inject_stencil_references — failure / skip cases
# ---------------------------------------------------------------------------


class TestInjectFailures:
    def test_returns_false_for_missing_file(self, tmp_path: Path) -> None:
        result = inject_stencil_references(tmp_path / "nonexistent.html")
        assert result is False

    def test_returns_false_for_no_head_tag(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, NO_HEAD_HTML)
        result = inject_stencil_references(p)
        assert result is False

    def test_no_head_tag_file_unchanged(self, tmp_path: Path) -> None:
        p = _write_html(tmp_path, NO_HEAD_HTML)
        inject_stencil_references(p)
        assert p.read_text(encoding="utf-8") == NO_HEAD_HTML


# ---------------------------------------------------------------------------
# Integration with RunManager
# ---------------------------------------------------------------------------


class TestRunManagerIntegration:
    """Verify that RunManager calls inject_stencil_references after a run."""

    def test_dashboard_gets_stencil_injected(self, tmp_path: Path) -> None:
        """End-to-end: executor returns a dashboard path, RunManager injects Stencil."""
        import time
        from typing import Callable

        from server.models import RunConfig
        from server.run_manager import ProgressEvent, RunManager

        # Create a real HTML file the executor will "produce"
        dashboard = tmp_path / "output" / "attack_trees_dashboard.html"
        dashboard.parent.mkdir(parents=True)
        dashboard.write_text(MINIMAL_HTML, encoding="utf-8")

        project_dir = tmp_path / "project"
        project_dir.mkdir()

        def executor(
            config: RunConfig,
            progress_callback: Callable[[ProgressEvent], None],
        ) -> dict[str, str]:
            return {
                "output_dir": str(dashboard.parent),
                "dashboard_path": str(dashboard),
            }

        mgr = RunManager(executor=executor)
        config = RunConfig(project_path=str(project_dir), threat_source="auto")
        mgr.start_run(config)

        # Wait for background thread
        time.sleep(0.5)

        html = dashboard.read_text(encoding="utf-8")
        assert STENCIL_CSS_URL in html
        assert STENCIL_ESM_JS_URL in html
        assert "--tf-primary:" in html
