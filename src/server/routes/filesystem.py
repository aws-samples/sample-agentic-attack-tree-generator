"""Filesystem browse API route."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from server.filesystem import (
    FilesystemBrowser,
    PathNotFoundError,
    PathTraversalError,
)
from server.models import DirectoryListing

router = APIRouter()

# Default allowed roots — configurable via environment or startup
_browser = FilesystemBrowser(allowed_roots=[Path.home(), Path.cwd()])


def get_browser() -> FilesystemBrowser:
    """Return the module-level FilesystemBrowser instance."""
    return _browser


def set_browser(browser: FilesystemBrowser) -> None:
    """Replace the module-level FilesystemBrowser (useful for testing)."""
    global _browser
    _browser = browser


@router.get("/filesystem/browse", response_model=DirectoryListing)
async def browse_filesystem(
    path: str = Query(..., description="Absolute directory path to browse"),
) -> DirectoryListing:
    """Browse a server-side directory for the File Picker component.

    Returns the directory listing with files and subdirectories.

    - **404** if the path does not exist
    - **403** if the path attempts to escape allowed roots
    - **400** if the path is not a directory
    """
    browser = get_browser()
    try:
        return browser.list_directory(Path(path))
    except PathNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PathTraversalError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except NotADirectoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
