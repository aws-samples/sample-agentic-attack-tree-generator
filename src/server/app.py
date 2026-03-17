"""ThreatForest FastAPI application."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server.executor import create_orchestrator_executor
from server.routes.applications import router as applications_router, set_registry
from server.routes.config import router as config_router
from server.routes.filesystem import router as filesystem_router
from server.routes.runs import router as runs_router, set_run_manager
from server.run_manager import RunManager

app = FastAPI(title="ThreatForest Server")

# CORS middleware — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(applications_router, prefix="/api")
app.include_router(config_router, prefix="/api")
app.include_router(filesystem_router, prefix="/api")
app.include_router(runs_router, prefix="/api")

# WebSocket routes (no /api prefix) — the runs router also registers
# the WebSocket endpoint, so we include it at root level too.
from server.routes.runs import ws_router as runs_ws_router  # noqa: E402

app.include_router(runs_ws_router)

# ---------------------------------------------------------------------------
# Resolve the repo / project root.
#
# When installed via pipx (non-editable), __file__ points into the pipx venv
# so we can't walk up from it.  Instead we try, in order:
#   1. cwd — the user runs `threatforest` from the repo root
#   2. __file__-based — works during development (editable install / PYTHONPATH)
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """Return the best-guess repo root directory."""
    # __file__-based resolution: src/server/app.py -> repo root
    file_based = Path(__file__).resolve().parent.parent.parent
    if (file_based / ".threatforest").is_dir() or (file_based / "src").is_dir():
        return file_based
    # Fall back to cwd
    cwd = Path.cwd()
    if (cwd / "src").is_dir() or (cwd / "sample-applications").is_dir():
        return cwd
    return file_based

repo_root = _find_repo_root()
executor = create_orchestrator_executor(repo_root)
set_run_manager(RunManager(executor=executor))

# Configure application registry — uses centralized .threatforest/runs/
from server.registry import ApplicationRegistry

set_registry(ApplicationRegistry())

sample_apps_dir = repo_root / "sample-applications"
if sample_apps_dir.is_dir():
    app.mount(
        "/dashboards",
        StaticFiles(directory=str(sample_apps_dir)),
        name="dashboards",
    )

# Mount console-ui at root — use bundled package data, fall back to repo-level dir
# When installed via pipx, the files live inside the threatforest package.
# During development, they may also be at repo_root/console-ui.
import threatforest.console_ui as _console_ui_pkg

_bundled_console_ui = Path(_console_ui_pkg.__file__).parent
_repo_console_ui = repo_root / "console-ui"

if _bundled_console_ui.is_dir() and (_bundled_console_ui / "index.html").is_file():
    console_ui_dir = _bundled_console_ui
elif _repo_console_ui.is_dir():
    console_ui_dir = _repo_console_ui
else:
    console_ui_dir = None

if console_ui_dir is not None:
    # SPA fallback — serve index.html for any route that doesn't match
    # an API endpoint or a real static file.  This is required because React
    # Router uses client-side routing (e.g. /applications/:id/versions/:v)
    # and a full-page navigation to those paths must return index.html
    # so the JS bundle can boot and render the correct page.
    from fastapi.responses import HTMLResponse, FileResponse as _FileResponse

    _index_html_path = console_ui_dir / "index.html"
    _index_html_content: str | None = None

    if _index_html_path.is_file():
        _index_html_content = _index_html_path.read_text(encoding="utf-8")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """Serve static files or index.html for SPA client-side routing."""
        if full_path.startswith("api/") or full_path.startswith("ws/"):
            # Should not reach here — API/WS routes are registered first
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Not found")

        # Serve a real static file if it exists
        candidate = console_ui_dir / full_path
        if full_path and candidate.is_file():
            # Guess content type for common static assets
            import mimetypes
            content_type, _ = mimetypes.guess_type(str(candidate))
            return _FileResponse(str(candidate), media_type=content_type)

        # Otherwise return index.html for client-side routing
        if _index_html_content:
            return HTMLResponse(content=_index_html_content)
        return _FileResponse(str(_index_html_path), media_type="text/html")
