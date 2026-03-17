"""Filesystem browse API route."""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

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


class PickerResponse(BaseModel):
    path: str | None


def _native_pick_directory() -> str | None:
    """Open the OS-native directory picker and return the selected path."""
    system = platform.system()
    try:
        if system == "Darwin":
            result = subprocess.run(
                ["osascript", "-e", 'POSIX path of (choose folder with prompt "Select project directory")'],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return result.stdout.strip().rstrip("/")
        elif system == "Linux":
            for cmd in [
                ["zenity", "--file-selection", "--directory", "--title=Select project directory"],
                ["kdialog", "--getexistingdirectory", str(Path.home()), "--title", "Select project directory"],
            ]:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if result.returncode == 0:
                        return result.stdout.strip()
                except FileNotFoundError:
                    continue
        elif system == "Windows":
            ps_script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                "$d.Description = 'Select project directory'; "
                "if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


@router.post("/filesystem/pick-directory", response_model=PickerResponse)
async def pick_directory() -> PickerResponse:
    """Open the OS-native directory picker dialog.

    Returns the selected path or null if the user cancelled.
    This runs synchronously (blocks until the user picks or cancels).
    """
    import asyncio
    path = await asyncio.to_thread(_native_pick_directory)
    return PickerResponse(path=path)
