"""Build ``.tfreport`` bundles for export.

A ``.tfreport`` is a plain zip with this layout::

    threatforest_report.json          ← manifest (always at root)
    application/
      metadata.json                   ← name + description, ``path`` stripped
      business_context.json           ← only when a v2 record exists
    versions/
      <YYYYMMDD_HHMMSS>/
        output/
          threatforest_data.json
          threat_model_report.md
          attack_trees_dashboard.html
        state/
          threats.json
          attack_trees.json
          ttp_mappings.json
          mitigations.json
          scanner_context.json        ← only when include_scanner_context=True
        mitigation_overrides.json     ← if present
        run_metadata.json             ← if present

The bundle is built fully in-memory and returned as ``bytes`` so the route
can stream it without touching the disk again.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from server.applications import ApplicationRepository
    from server.registry import ApplicationRegistry


SCHEMA_VERSION = 1
MANIFEST_FILENAME = "threatforest_report.json"

# Files always copied verbatim from the run directory when present.
_OUTPUT_FILES = (
    "threatforest_data.json",
    "threat_model_report.md",
    "attack_trees_dashboard.html",
)
_STATE_FILES = (
    "threats.json",
    "attack_trees.json",
    "ttp_mappings.json",
    "mitigations.json",
)
_RUN_DIR_FILES = (
    "mitigation_overrides.json",
    "run_metadata.json",
)


class ReportBundleError(Exception):
    """Raised when a bundle cannot be built (e.g. missing run output)."""


def build_report_bundle(
    *,
    folder_id: str,
    version_ids: list[str],
    include_scanner_context: bool,
    registry: "ApplicationRegistry",
    app_repository: "ApplicationRepository | None" = None,
    threatforest_version: str = "",
) -> bytes:
    """Build a ``.tfreport`` zip and return its bytes.

    Parameters
    ----------
    folder_id
        On-disk folder name under ``.threatforest/runs/``. The route layer
        resolves opaque ``app_id`` URLs to this before calling.
    version_ids
        Timestamped run folders to include. Order is preserved in the
        manifest so the recipient sees them in the same order on import.
    include_scanner_context
        When True, ``state/scanner_context.json`` is included for each
        version. Default for the public API is True (intra-team handoff)
        but the parameter is kept explicit to avoid silent leaks.
    registry
        ``ApplicationRegistry`` used to resolve run directories.
    app_repository
        Optional ``ApplicationRepository`` — when present and a v2 record
        exists for *folder_id*, business context is included alongside
        metadata. v1 folder-only apps still bundle correctly.
    threatforest_version
        Version string written into the manifest (``exported_by_threatforest``)
        so the import side can flag bundles built by older/newer engines.

    Raises
    ------
    ReportBundleError
        If *folder_id* doesn't resolve, no versions are supplied, or a
        requested version has no completed output (no ``threatforest_data.json``).
    """
    if not version_ids:
        raise ReportBundleError("At least one version_id is required.")

    project_dir = registry.get_project_dir(folder_id)
    if project_dir is None:
        raise ReportBundleError(f"Application folder '{folder_id}' not found.")

    project_meta = _load_json(project_dir / "metadata.json") or {}

    # Resolve persistent record (if any) for richer manifest + business context.
    persistent_app = None
    if app_repository is not None:
        persistent_app = app_repository.find_by_run_dir_name(folder_id)

    source_app_id = persistent_app.id if persistent_app else folder_id
    source_app_name = (
        persistent_app.name
        if persistent_app
        else project_meta.get("name", folder_id)
    )

    buffer = io.BytesIO()
    # ZIP_DEFLATED on the JSON/MD payloads cuts bundle size meaningfully on
    # the common case (verbose threatforest_data.json blobs compress ~5×).
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # ─── manifest ──────────────────────────────────────────
        scope = "single-version" if len(version_ids) == 1 else "full-application"
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "exported_at": datetime.now(tz=timezone.utc).isoformat(),
            "exported_by_threatforest": threatforest_version,
            "source_app_id": source_app_id,
            "source_app_name": source_app_name,
            "source_app_slug": folder_id,
            "include_scanner_context": include_scanner_context,
            "scope": scope,
            "versions": list(version_ids),
        }
        zf.writestr(
            MANIFEST_FILENAME,
            json.dumps(manifest, indent=2, sort_keys=True),
        )

        # ─── application/ ──────────────────────────────────────
        # Strip ``path`` so the recipient never sees the originator's
        # filesystem layout. Keep description + name so the UI has
        # something to render.
        app_metadata = {
            "name": source_app_name,
            "description": project_meta.get("description", ""),
            "created_at": project_meta.get("created_at", ""),
        }
        zf.writestr(
            "application/metadata.json",
            json.dumps(app_metadata, indent=2, sort_keys=True),
        )
        if persistent_app is not None:
            zf.writestr(
                "application/business_context.json",
                json.dumps(
                    persistent_app.business_context.model_dump(),
                    indent=2,
                    sort_keys=True,
                ),
            )

        # ─── versions/ ─────────────────────────────────────────
        for version_id in version_ids:
            run_dir = registry.get_version_run_dir(folder_id, version_id)
            if run_dir is None:
                raise ReportBundleError(
                    f"Version '{version_id}' not found for application "
                    f"'{folder_id}'."
                )
            data_file = run_dir / "output" / "threatforest_data.json"
            if not data_file.is_file():
                raise ReportBundleError(
                    f"Version '{version_id}' has no completed output and "
                    f"cannot be exported."
                )

            base = f"versions/{version_id}"

            # output/
            for fname in _OUTPUT_FILES:
                src = run_dir / "output" / fname
                if src.is_file():
                    zf.write(src, f"{base}/output/{fname}")

            # state/
            for fname in _STATE_FILES:
                src = run_dir / "state" / fname
                if src.is_file():
                    zf.write(src, f"{base}/state/{fname}")

            if include_scanner_context:
                ctx = run_dir / "state" / "scanner_context.json"
                if ctx.is_file():
                    zf.write(ctx, f"{base}/state/scanner_context.json")

            # run-dir-level files (overrides, run_metadata)
            for fname in _RUN_DIR_FILES:
                src = run_dir / fname
                if src.is_file():
                    zf.write(src, f"{base}/{fname}")

    return buffer.getvalue()


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
