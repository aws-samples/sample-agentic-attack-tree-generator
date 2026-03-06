#!/usr/bin/env python3
"""Build the React/Cloudscape console UI and sync output into the Python package.

Usage:
    python build_ui.py          # build + sync
    python build_ui.py --clean  # remove old files first

This script:
1. Runs `npm install` and `npm run build` inside console-ui/
2. Copies the Vite dist/ output into src/threatforest/console_ui/
   so that `pipx install .` bundles the pre-built UI.
"""

import argparse
import os
import signal
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONSOLE_UI_SRC = ROOT / "console-ui"
DIST_DIR = CONSOLE_UI_SRC / "dist"
PACKAGE_UI_DIR = ROOT / "src" / "threatforest" / "console_ui"


def kill_running_server() -> None:
    """Kill any running threatforest/uvicorn server on port 8000."""
    try:
        result = subprocess.run(
            ["lsof", "-ti", ":8000"], capture_output=True, text=True
        )
        pids = result.stdout.strip().split()
        if pids:
            for pid in pids:
                pid = pid.strip()
                if pid:
                    print(f"  → Killing server process {pid} on port 8000")
                    os.kill(int(pid), signal.SIGTERM)
            print("  ✓ Server stopped")
        else:
            print("  ℹ No server running on port 8000")
    except Exception:
        pass


def run(cmd: list[str], cwd: Path) -> None:
    print(f"  → {' '.join(cmd)}  (in {cwd})")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"ERROR: command failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)


def clean_package_ui() -> None:
    """Remove everything in the package UI dir except __init__.py."""
    if not PACKAGE_UI_DIR.is_dir():
        return
    for item in PACKAGE_UI_DIR.iterdir():
        if item.name in ("__init__.py", "__pycache__"):
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    print(f"  ✓ Cleaned {PACKAGE_UI_DIR}")


def clean_vite_cache() -> None:
    """Remove Vite's dependency pre-bundling cache and old dist to force a fresh build."""
    vite_cache = CONSOLE_UI_SRC / "node_modules" / ".vite"
    if vite_cache.is_dir():
        shutil.rmtree(vite_cache)
        print(f"  ✓ Cleared Vite cache: {vite_cache}")
    if DIST_DIR.is_dir():
        shutil.rmtree(DIST_DIR)
        print(f"  ✓ Cleared old dist: {DIST_DIR}")


def build_ui() -> None:
    """Run npm install + npm run build."""
    print("Building console UI…")
    clean_vite_cache()
    run(["npm", "install"], cwd=CONSOLE_UI_SRC)
    run(["npm", "run", "build"], cwd=CONSOLE_UI_SRC)
    if not DIST_DIR.is_dir():
        print(f"ERROR: expected build output at {DIST_DIR} but it doesn't exist", file=sys.stderr)
        sys.exit(1)
    print(f"  ✓ Build output at {DIST_DIR}")


def sync_to_package() -> None:
    """Copy dist/ contents into the Python package directory."""
    print("Syncing build output to Python package…")
    clean_package_ui()

    for item in DIST_DIR.rglob("*"):
        rel = item.relative_to(DIST_DIR)
        dest = PACKAGE_UI_DIR / rel
        if item.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest)

    print(f"  ✓ Synced to {PACKAGE_UI_DIR}")

    # Also sync to uv tool environment if it exists
    uv_console_ui = (
        Path.home()
        / ".local/share/uv/tools/threatforest"
    )
    # Find the site-packages console_ui dir (any python version)
    for sp in uv_console_ui.glob("lib/python*/site-packages/threatforest/console_ui"):
        if sp.is_dir():
            print(f"  → Also syncing to uv tool env: {sp}")
            # Clean old files (keep __init__.py and __pycache__)
            for old in sp.iterdir():
                if old.name in ("__init__.py", "__pycache__"):
                    continue
                if old.is_dir():
                    shutil.rmtree(old)
                else:
                    old.unlink()
            # Copy new files
            for item in DIST_DIR.rglob("*"):
                rel = item.relative_to(DIST_DIR)
                dest = sp / rel
                if item.is_dir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest)
            print(f"  ✓ uv tool env updated")


def sync_python_source() -> None:
    """Sync Python source (server + engine) to the uv tool environment.

    The uv tool install is not editable, so local changes to server/ or
    threatforest/ source files are not picked up until we copy them over.
    """
    uv_tools_root = Path.home() / ".local/share/uv/tools/threatforest"
    if not uv_tools_root.is_dir():
        return

    src_modules = [
        (ROOT / "src" / "server", "server"),
        (ROOT / "src" / "threatforest", "threatforest"),
    ]

    for sp_dir in uv_tools_root.glob("lib/python*/site-packages"):
        if not sp_dir.is_dir():
            continue
        for local_src, pkg_name in src_modules:
            dest = sp_dir / pkg_name
            if not dest.is_dir() or not local_src.is_dir():
                continue
            print(f"  → Syncing {pkg_name}/ to {dest}")
            # Copy .py files, preserving directory structure
            count = 0
            for py_file in local_src.rglob("*.py"):
                rel = py_file.relative_to(local_src)
                dst_file = dest / rel
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(py_file, dst_file)
                count += 1
            # Also sync prompt .md files for the engine
            for md_file in local_src.rglob("prompts/*.md"):
                rel = md_file.relative_to(local_src)
                dst_file = dest / rel
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(md_file, dst_file)
                count += 1
            print(f"  ✓ {pkg_name}: {count} files synced")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and bundle the ThreatForest console UI")
    parser.add_argument("--clean", action="store_true", help="Clean package UI dir without rebuilding")
    parser.add_argument("--no-kill", action="store_true", help="Don't kill running server")
    args = parser.parse_args()

    if args.clean:
        clean_package_ui()
        return

    if not args.no_kill:
        kill_running_server()

    build_ui()
    sync_to_package()
    sync_python_source()
    print("\nDone! Run: threatforest console")


if __name__ == "__main__":
    main()
