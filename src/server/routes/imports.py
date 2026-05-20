"""Routes for ThreatForest report imports.

The drop-folder workflow (``.threatforest/imports/<file>.tfreport`` picked
up on the next applications-list refresh) still works — this module just
adds an HTTP path so the UI can offer "Import a report" without users
having to know the absolute path to the imports directory.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from server.report_import import (
    ImportResult,
    ensure_imports_dir,
    process_pending_imports,
)
from server.routes.applications import get_registry

logger = logging.getLogger(__name__)

router = APIRouter()


# Conservative ceiling — a healthy bundle with a year of runs is well under
# 50MB; anything larger is almost certainly a mistake. Bumped if a real
# customer hits the wall.
MAX_BUNDLE_BYTES = 200 * 1024 * 1024


def _imports_dir() -> Path:
    """Resolve the imports drop-folder.

    Anchored to the active registry's ``runs_root`` rather than the
    process-wide one so tests that swap in an isolated registry under
    ``tmp_path`` see the same imports directory the upload writes into.
    """
    return get_registry().runs_root.parent / "imports"


def _result_payload(result: ImportResult) -> dict:
    """Shape an ``ImportResult`` for the JSON response."""
    return {
        "bundle": result.bundle,
        "status": result.status,
        "folder_name": result.folder_name,
        "versions_added": list(result.versions_added),
        "versions_skipped": list(result.versions_skipped),
        "error": result.error,
    }


@router.get("/imports/info")
async def imports_info() -> dict:
    """Return the absolute path of the imports drop-folder.

    Lets the UI render a "drop files here" hint with a copy-able path so
    users don't have to guess. Also surfaces the seeded README and any
    bundles currently parked in ``processed/`` or ``failed/`` for the
    history popover (only filename + size — no contents).
    """
    imports_dir = _imports_dir()
    ensure_imports_dir(imports_dir)

    def _list(sub: str) -> list[dict]:
        path = imports_dir / sub
        if not path.is_dir():
            return []
        out: list[dict] = []
        for entry in sorted(path.iterdir()):
            if entry.is_file():
                out.append({"name": entry.name, "size": entry.stat().st_size})
        return out

    return {
        "imports_dir": str(imports_dir),
        "processed": _list("processed"),
        "failed": _list("failed"),
    }


@router.post("/imports/tfreport")
async def upload_tfreport(file: UploadFile = File(...)) -> dict:
    """Upload a ``.tfreport`` bundle and run the importer inline.

    The body is a multipart/form-data POST with a single ``file`` field.
    The handler:

    1. Validates filename + size.
    2. Streams the upload into ``imports/`` (chunked write to avoid loading
       the whole bundle into memory for very large exports).
    3. Calls ``process_pending_imports`` so the UI can show the result
       without waiting for the next applications-list refresh.

    The processor moves the bundle into ``processed/`` or ``failed/``
    itself, so we don't have to clean up the original drop on either path.
    """
    if not file.filename or not file.filename.endswith(".tfreport"):
        raise HTTPException(
            status_code=400,
            detail="Filename must end with .tfreport.",
        )
    # Guard against directory traversal — UploadFile.filename is whatever
    # the client sent; sanitise to the basename.
    safe_name = Path(file.filename).name
    if safe_name != file.filename or "/" in file.filename or "\\" in file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename contains path separators.",
        )

    imports_dir = _imports_dir()
    ensure_imports_dir(imports_dir)

    # Avoid clobbering a pending bundle of the same name.
    target = imports_dir / safe_name
    if target.exists():
        raise HTTPException(
            status_code=409,
            detail=(
                f"A bundle named '{safe_name}' is already pending in the "
                f"imports directory. Rename your file and try again."
            ),
        )

    # Stream-to-disk with a running size check rather than calling
    # file.read() once — keeps memory bounded even on huge bundles.
    bytes_written = 0
    chunk_size = 1024 * 1024
    try:
        with target.open("wb") as out:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                bytes_written += len(chunk)
                if bytes_written > MAX_BUNDLE_BYTES:
                    out.close()
                    target.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Bundle exceeds the {MAX_BUNDLE_BYTES // (1024*1024)} MB "
                            f"limit."
                        ),
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save uploaded file: {exc}",
        )

    # Run the import processor immediately so the UI can display the
    # outcome rather than waiting for the next applications-list refresh.
    results = process_pending_imports(imports_dir, get_registry())
    # Find the ImportResult that corresponds to *this* upload — there could
    # be other pending bundles in the directory that the user dropped in
    # manually, so we filter by filename.
    own = next((r for r in results if r.bundle == safe_name), None)
    if own is None:
        # The processor didn't touch our file — most likely the directory
        # listing race-skipped it. Surface a generic error so the user
        # can retry.
        raise HTTPException(
            status_code=500,
            detail=(
                "Upload saved but import did not run. Reload the "
                "Applications page to retry."
            ),
        )

    return {"result": _result_payload(own)}
