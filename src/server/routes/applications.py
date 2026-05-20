"""Application discovery and version listing API routes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, Response

from server.applications import (
    ApplicationNameConflictError,
    ApplicationNotFoundError,
    ApplicationPathConflictError,
    ApplicationRepository,
)
from server.applications import get_repository as _default_repository
from server.models import (
    Application,
    ApplicationCreateRequest,
    ApplicationSummary,
    ApplicationUpdateRequest,
    MitigationOverride,
    MitigationOverrideRequest,
    VersionSummary,
)
from server.registry import ApplicationRegistry

router = APIRouter()


def _active_runs_for_folder(folder_id: str) -> dict[str, str]:
    """Return a map of ``version_folder_basename -> run_id`` for live runs.

    Queries the run manager for runs that are still pending or running and
    whose ScanControl points at a timestamped subdirectory under *folder_id*.
    The frontend uses the run_id to route the user to the progress page
    instead of a dashboard that hasn't been rendered yet.
    """
    # Imported here to avoid a circular import between the routes modules and
    # the run manager (which is configured by ``app.py`` at startup).
    from server.routes.runs import get_run_manager

    manager = get_run_manager()
    active: dict[str, str] = {}
    for run_id, state in list(manager.active_runs.items()):
        if state.status not in ("pending", "running"):
            continue
        control = manager._controls.get(run_id)
        run_dir = control.run_dir if control else None
        if not run_dir:
            continue
        run_dir_path = Path(run_dir)
        # Match by parent folder name — the project folder under
        # ``.threatforest/runs/`` — so we don't accidentally associate a
        # run with another app's version directory.
        if run_dir_path.parent.name != folder_id:
            continue
        active[run_dir_path.name] = run_id
    return active

# Default registry — will be reconfigured by app.py at startup
_registry = ApplicationRegistry()

# The persistent application repository (v2 UX). Initialised lazily so tests
# can swap it in via ``set_app_repository`` before the first request hits.
_app_repository: ApplicationRepository | None = None


def get_registry() -> ApplicationRegistry:
    """Return the module-level ApplicationRegistry instance."""
    return _registry


def set_registry(registry: ApplicationRegistry) -> None:
    """Replace the module-level ApplicationRegistry (called by app.py at startup)."""
    global _registry
    _registry = registry


def get_app_repository() -> ApplicationRepository:
    """Return the module-level ``ApplicationRepository`` instance."""
    global _app_repository
    if _app_repository is None:
        _app_repository = _default_repository()
    return _app_repository


def set_app_repository(repository: ApplicationRepository) -> None:
    """Replace the module-level ``ApplicationRepository`` (used by tests)."""
    global _app_repository
    _app_repository = repository


def _resolve_folder_id(app_id: str) -> str:
    """Translate a route ``app_id`` param to the on-disk folder name.

    URLs can carry two flavours of identifier:

    - The v2 persistent Application ID (e.g. ``app_abc123``) — the frontend
      always uses this one for its navigation. We need to look up the
      record and return its ``run_dir_name`` so registry calls target the
      correct folder under ``.threatforest/runs/``.
    - A legacy folder-derived slug (e.g. ``lams-m2m``) — used by older
      clients / direct links. Pass it through unchanged.

    If the persistent lookup fails we return the raw ``app_id`` so callers
    can still hit folder-derived routes. The registry will 404 naturally
    if neither resolution finds anything.
    """
    try:
        app = get_app_repository().get_application(app_id)
    except ApplicationNotFoundError:
        return app_id
    return app.run_dir_name


@router.get("/applications", response_model=dict)
async def list_applications() -> dict:
    """Return all ThreatForest applications.

    Merges two sources:

    - Persistent records from ``applications.json`` (v2 — user-created apps
      with business context).
    - Folder-derived records discovered under ``.threatforest/runs/`` (v1 —
      legacy apps whose identity is the run-folder name).

    When both sources describe the same application, the persistent record
    wins. Response shape: ``{ "applications": [ ApplicationSummary, ... ] }``.
    """
    registry = get_registry()
    folder_apps = registry.discover_applications()

    repo = get_app_repository()
    persistent = repo.list_applications()
    persistent_run_dirs = {app.run_dir_name for app in persistent}

    # Start with persistent records as summaries, keyed by run_dir_name so we
    # can merge in version counts / last-run-date from the folder scan.
    merged: list[ApplicationSummary] = []
    for app in persistent:
        versions = registry.get_versions(
            app.run_dir_name,
            active_run_ids=_active_runs_for_folder(app.run_dir_name),
        )
        merged.append(
            ApplicationSummary(
                id=app.id,
                name=app.name,
                description=app.business_context.description,
                version_count=len(versions),
                last_run_date=versions[0].run_date if versions else "",
                business_context=app.business_context,
            )
        )

    # Append any folder-derived apps that don't have a persistent record yet.
    for folder_app in folder_apps:
        if folder_app.id in persistent_run_dirs:
            continue
        merged.append(folder_app)

    return {"applications": [app.model_dump() for app in merged]}


@router.post("/applications", response_model=dict, status_code=201)
async def create_application(body: ApplicationCreateRequest) -> dict:
    """Create a new application with a user-chosen name and business context.

    - **409** if another application has the same name (case-insensitive) or
      is already registered for the given ``project_path``.
    """
    repo = get_app_repository()
    try:
        app = repo.create_application(body)
    except ApplicationNameConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ApplicationPathConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return app.model_dump()


@router.get("/applications/by-id/{app_id}", response_model=dict)
async def get_application(app_id: str) -> dict:
    """Return the full persistent record for a single application.

    Uses ``/by-id/{app_id}`` rather than ``/{app_id}`` so it does not collide
    with the folder-derived routes (e.g. ``/applications/{app_id}/versions``)
    that accept a folder-style identifier.

    Accepts either the opaque v2 ``app_id`` (e.g. ``app_abc123``) or the
    folder-derived ``run_dir_name`` (e.g. ``lams-m2m``) so callers that only
    have a URL slug can still resolve back to the persistent record.

    - **404** if no application matches either identifier.
    """
    repo = get_app_repository()
    try:
        app = repo.get_application(app_id)
    except ApplicationNotFoundError:
        # Fall back to run-dir-name lookup for folder-slug URLs.
        app = repo.find_by_run_dir_name(app_id)
        if app is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown application: {app_id}",
            )
    return app.model_dump()


@router.patch("/applications/by-id/{app_id}", response_model=dict)
async def update_application(app_id: str, body: ApplicationUpdateRequest) -> dict:
    """Apply a partial update (name, business_context, and/or project_path) to an application.

    ``project_path`` is freely editable at any point so users can track folder
    renames or moves; the stable ``run_dir_name`` keeps the on-disk version
    history attached to the application regardless.

    - **404** if no application with this ID exists.
    - **409** if the new name collides with another application or if the
      new ``project_path`` is already registered to a different application.
    """
    repo = get_app_repository()

    try:
        app = repo.update_application(app_id, body)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ApplicationNameConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ApplicationPathConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return app.model_dump()


@router.delete("/applications/by-id/{app_id}", status_code=200)
async def delete_application_record(app_id: str) -> dict:
    """Delete the persistent application record and its on-disk run artefacts.

    Removes both the entry in ``applications.json`` and the matching folder
    under ``.threatforest/runs/{run_dir_name}/`` (if one exists). The on-disk
    cleanup is best-effort: if the folder is missing we proceed silently,
    and if ``shutil.rmtree`` fails we surface a 500 so the caller knows the
    disk was left in an inconsistent state.

    - **404** if no application with this ID exists.
    - **500** if the on-disk folder cleanup fails.
    """
    repo = get_app_repository()
    try:
        app = repo.get_application(app_id)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    registry = get_registry()
    project_dir = registry.get_project_dir(app.run_dir_name)

    try:
        repo.delete_application(app_id)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    if project_dir is not None and project_dir.is_dir():
        try:
            shutil.rmtree(str(project_dir))
        except OSError as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Application record deleted, but on-disk folder "
                    f"{project_dir} could not be removed: {exc}"
                ),
            )

    return {"success": True, "message": f"Application '{app_id}' deleted"}


@router.get("/applications/{app_id}/versions", response_model=dict)
async def list_versions(app_id: str) -> dict:
    """Return threat model versions for a specific application.

    Returns versions sorted by run date descending. Accepts either a v2
    persistent ``app_id`` or a legacy folder-derived slug — both resolve
    to the same folder under ``.threatforest/runs/``.

    - **404** if the application is not found and has no runs on disk
    """
    registry = get_registry()
    folder_id = _resolve_folder_id(app_id)
    versions = registry.get_versions(
        folder_id,
        active_run_ids=_active_runs_for_folder(folder_id),
    )
    if not versions:
        # Before 404-ing, confirm no record exists under either identifier —
        # a freshly created v2 app legitimately has zero runs and should
        # still return an empty list rather than a 404.
        try:
            get_app_repository().get_application(app_id)
            return {"versions": []}
        except ApplicationNotFoundError:
            pass
        apps = registry.discover_applications()
        app_ids = {app.id for app in apps}
        if folder_id not in app_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Application '{app_id}' not found",
            )
    return {"versions": [v.model_dump() for v in versions]}


@router.delete("/applications/{app_id}/versions/{version_id}")
async def delete_version(app_id: str, version_id: str) -> dict:
    """Delete a single threat-model version (timestamped run folder).

    Accepts either a v2 persistent ``app_id`` or a legacy folder-derived
    slug. Refuses to delete a version that's currently the target of a live
    run — the user should cancel or wait for completion instead, otherwise
    the in-flight pipeline would error out mid-write.

    - **400** if the version is still the target of an active run.
    - **404** if the application or version is not found.
    - **500** if the on-disk folder removal fails.
    """
    registry = get_registry()
    folder_id = _resolve_folder_id(app_id)

    active = _active_runs_for_folder(folder_id)
    if version_id in active:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Version '{version_id}' is currently running "
                f"(run_id={active[version_id]}). Cancel the run before "
                f"deleting."
            ),
        )

    try:
        deleted = registry.delete_version(folder_id, version_id)
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete version '{version_id}': {exc}",
        )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Version '{version_id}' not found for application "
                f"'{app_id}'"
            ),
        )

    return {"success": True, "message": f"Version '{version_id}' deleted"}


@router.delete("/applications/{app_id}")
async def delete_application(app_id: str) -> dict:
    """Delete a ThreatForest application by removing its folder from .threatforest/runs/.

    - **404** if the application is not found
    - **500** if deletion fails
    """
    registry = get_registry()
    project_dir = registry.get_project_dir(app_id)

    if project_dir is None:
        raise HTTPException(status_code=404, detail=f"Application '{app_id}' not found")

    try:
        shutil.rmtree(str(project_dir))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {exc}")

    return {"success": True, "message": f"Application '{app_id}' deleted successfully"}


@router.get("/paused-runs")
async def list_paused_runs() -> dict:
    """Return applications whose most recent run is paused.

    Response: ``{ "paused_runs": [ { id, name, project_path, paused_at, ... }, ... ] }``
    """
    registry = get_registry()
    return {"paused_runs": registry.discover_paused_runs()}


@router.delete("/paused-runs/{app_id}")
async def delete_paused_run(app_id: str) -> dict:
    """Remove the pause_state.json for an application's latest run.

    This prevents the application from appearing in the paused runs list.

    - **404** if the application is not found or has no pause state
    """
    registry = get_registry()
    deleted = registry.delete_pause_state(app_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No paused run found for '{app_id}'")
    return {"success": True, "message": f"Paused run for '{app_id}' removed"}


@router.get("/applications/{app_id}/versions/{version_id}/data")
async def get_version_data(app_id: str, version_id: str) -> JSONResponse:
    """Return the raw threatforest_data.json for a specific version.

    - **404** if the application, version, or data file is not found
    - **500** if the JSON file is malformed
    """
    registry = get_registry()
    folder_id = _resolve_folder_id(app_id)
    data_file = registry.get_version_data_path(folder_id, version_id)

    if data_file is None:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{version_id}' not found for application '{app_id}'",
        )

    raw = data_file.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(
            status_code=500,
            detail="Failed to parse threat data",
        )

    # Attach run-level metadata (model, frameworks, ATT&CK version, started_at,
    # completed_at, duration_seconds) when the run-metadata sidecar exists.
    # For older runs without the sidecar, derive started_at from the run-folder
    # timestamp so the UI can still surface something useful.
    run_meta_file = data_file.parent.parent / "run_metadata.json"
    if run_meta_file.is_file():
        try:
            data["run_metadata"] = json.loads(
                run_meta_file.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, ValueError):
            pass
    else:
        folder_name = data_file.parent.parent.name  # YYYYMMDD_HHMMSS
        try:
            from datetime import datetime as _dt, timezone as _tz
            started = _dt.strptime(folder_name, "%Y%m%d_%H%M%S").replace(tzinfo=_tz.utc)
            data["run_metadata"] = {
                "model_id": "",
                "frameworks": [],
                "attack_version": "",
                "started_at": started.isoformat(),
                "completed_at": None,
                "duration_seconds": None,
            }
        except ValueError:
            pass

    # Enrich TTC mappings with mitigations from STIX bundle (if available)
    from threatforest.frameworks import technique_url as _technique_url
    for tree in data.get("attack_trees", []):
        for mapping in tree.get("ttc_mappings", []):
            technique_id = mapping.get("technique_id", "")
            if technique_id and "technique_url" not in mapping:
                url = _technique_url(technique_id)
                if url:
                    mapping["technique_url"] = url
            mapping.pop("reasoning", None)

    try:
        from threatforest.config import config
        from threatforest.modules.workflow.ttc_mappings import MitigationMapper
        from pathlib import Path as _Path

        stix_path = getattr(config, "stix_bundle_path", None)
        if stix_path and _Path(stix_path).exists():
            mapper = MitigationMapper(str(stix_path))
            for tree in data.get("attack_trees", []):
                for mapping in tree.get("ttc_mappings", []):
                    technique_id = mapping.get("technique_id", "")
                    if technique_id and "mitigations" not in mapping:
                        mits = mapper.get_mitigations(technique_id)
                        if mits:
                            mapping["mitigations"] = mits
    except Exception as _enrich_err:
        import logging
        logging.getLogger("threatforest.api").warning(
            f"Mitigation enrichment failed: {_enrich_err}"
        )

    # Merge user-edited mitigation overrides (status + comment) over the
    # immutable pipeline output. Keyed by mitigation_text — the canonical
    # name field. See _load_mitigation_overrides for storage shape.
    overrides = _load_mitigation_overrides_for_version(folder_id, version_id)
    if overrides:
        _apply_mitigation_overrides(data, overrides)

    return JSONResponse(content=data)


# ---------------------------------------------------------------------------
# ThreatForest report bundles (.tfreport)
# ---------------------------------------------------------------------------


def _slugify_for_filename(text: str) -> str:
    """Lowercase, dash-separated form safe for use in download filenames."""
    import re
    out = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return out or "threatforest"


def _bundle_filename(app_name: str, version_label: str | None) -> str:
    """Build a human-readable ``.tfreport`` filename."""
    base = _slugify_for_filename(app_name)
    if version_label:
        return f"{base}-{_slugify_for_filename(version_label)}.tfreport"
    return f"{base}-full.tfreport"


def _build_and_respond(
    *,
    folder_id: str,
    version_ids: list[str],
    include_scanner_context: bool,
    filename: str,
) -> Response:
    """Shared body for both export endpoints — build the bundle and stream it."""
    from server.report_bundle import ReportBundleError, build_report_bundle

    try:
        from threatforest import __version__ as tf_version  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        tf_version = ""

    try:
        payload = build_report_bundle(
            folder_id=folder_id,
            version_ids=version_ids,
            include_scanner_context=include_scanner_context,
            registry=get_registry(),
            app_repository=get_app_repository(),
            threatforest_version=tf_version,
        )
    except ReportBundleError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return Response(
        content=payload,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/applications/{app_id}/versions/{version_id}/report")
async def export_version_report(
    app_id: str,
    version_id: str,
    include_scanner_context: bool = Query(
        True,
        description=(
            "Include scanner_context.json (file paths and code excerpts) in "
            "the bundle. Default True for intra-team handoff; pass False to "
            "redact when sharing more broadly."
        ),
    ),
) -> Response:
    """Build and download a single-version ``.tfreport`` bundle."""
    folder_id = _resolve_folder_id(app_id)
    registry = get_registry()

    if version_id == "latest":
        # Resolve so the manifest carries a real timestamp.
        resolved = registry._resolve_latest_version(  # noqa: SLF001
            registry.get_project_dir(folder_id) or Path("/")
        )
        if resolved is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"No completed versions for application '{app_id}' to "
                    f"export."
                ),
            )
        version_id = resolved

    # Use display name when available so filenames don't carry slugs.
    app_name = folder_id
    try:
        app_name = get_app_repository().get_application(app_id).name
    except ApplicationNotFoundError:
        record = get_app_repository().find_by_run_dir_name(folder_id)
        if record is not None:
            app_name = record.name

    filename = _bundle_filename(app_name, version_id)
    return _build_and_respond(
        folder_id=folder_id,
        version_ids=[version_id],
        include_scanner_context=include_scanner_context,
        filename=filename,
    )


@router.get("/applications/{app_id}/report")
async def export_application_report(
    app_id: str,
    include_scanner_context: bool = Query(
        True,
        description=(
            "Include scanner_context.json (file paths and code excerpts) in "
            "the bundle. Default True for intra-team handoff; pass False to "
            "redact when sharing more broadly."
        ),
    ),
) -> Response:
    """Build and download a full-application ``.tfreport`` bundle.

    Includes every completed version of the application. Versions still in
    progress (no ``output/threatforest_data.json``) are filtered out — the
    bundle would fail to import them anyway.
    """
    folder_id = _resolve_folder_id(app_id)
    registry = get_registry()

    versions = registry.get_versions(folder_id)
    completed = [v.id for v in versions if v.status == "complete"]
    if not completed:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No completed versions for application '{app_id}' to export."
            ),
        )

    # Bundle versions in chronological (oldest-first) order so the
    # recipient's UI labels them ``Version 1, 2, 3...`` consistently.
    completed.reverse()

    app_name = folder_id
    try:
        app_name = get_app_repository().get_application(app_id).name
    except ApplicationNotFoundError:
        record = get_app_repository().find_by_run_dir_name(folder_id)
        if record is not None:
            app_name = record.name

    filename = _bundle_filename(app_name, None)
    return _build_and_respond(
        folder_id=folder_id,
        version_ids=completed,
        include_scanner_context=include_scanner_context,
        filename=filename,
    )


# ---------------------------------------------------------------------------
# Mitigation overrides (M3 v1)
# ---------------------------------------------------------------------------

MITIGATION_OVERRIDES_FILE = "mitigation_overrides.json"
MITIGATION_OVERRIDES_VERSION = 1


def _overrides_path(folder_id: str, version_id: str) -> Path | None:
    """Resolve the on-disk path to ``mitigation_overrides.json`` for a version."""
    registry = get_registry()
    run_dir = registry.get_version_run_dir(folder_id, version_id)
    if run_dir is None:
        return None
    return run_dir / MITIGATION_OVERRIDES_FILE


def _load_mitigation_overrides_for_version(
    folder_id: str, version_id: str
) -> dict[str, dict]:
    """Read the overrides sidecar; return ``{mitigation_text: override_record}``.

    Returns an empty dict if the file is absent or unreadable. Missing/malformed
    files are not an error — overrides are entirely optional.
    """
    path = _overrides_path(folder_id, version_id)
    if path is None or not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    overrides = raw.get("overrides") or {}
    return overrides if isinstance(overrides, dict) else {}


def _save_mitigation_overrides(
    folder_id: str, version_id: str, overrides: dict[str, dict]
) -> None:
    """Persist the full overrides dict back to disk."""
    path = _overrides_path(folder_id, version_id)
    if path is None:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{version_id}' not found for application",
        )
    payload = {"version": MITIGATION_OVERRIDES_VERSION, "overrides": overrides}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _apply_mitigation_overrides(
    data: dict, overrides: dict[str, dict]
) -> None:
    """Stitch override status/comment into every mitigation in *data*.

    Mitigations live in two places per attack tree:
      1. ``ttc_mappings[].mitigations[]``
      2. ``mitigations[]`` (tree-level)

    The match is by the mitigation's name field (``mitigation_text`` falling
    back to ``name``/``mitigation``) — the same field the aggregator uses on
    the client. Mutates *data* in place.
    """
    def _stitch(mit: dict) -> None:
        key = mit.get("mitigation_text") or mit.get("name") or mit.get("mitigation") or ""
        if not key:
            return
        record = overrides.get(key)
        if not record:
            return
        # Only attach known fields; never echo arbitrary user input back into
        # the model output namespace.
        mit["override_status"] = record.get("status")
        mit["override_comment"] = record.get("comment")
        mit["override_updated_at"] = record.get("updated_at")

    for tree in data.get("attack_trees", []):
        for mapping in tree.get("ttc_mappings", []):
            for mit in mapping.get("mitigations", []) or []:
                _stitch(mit)
        for mit in tree.get("mitigations", []) or []:
            _stitch(mit)


@router.get("/applications/{app_id}/versions/{version_id}/mitigation-overrides")
async def list_mitigation_overrides(app_id: str, version_id: str) -> dict:
    """Return all mitigation overrides recorded for a version.

    Response shape::

        {"overrides": {"<mitigation_text>": {status, comment, updated_at}}}
    """
    folder_id = _resolve_folder_id(app_id)
    overrides = _load_mitigation_overrides_for_version(folder_id, version_id)
    return {"overrides": overrides}


@router.put(
    "/applications/{app_id}/versions/{version_id}/mitigation-overrides/{mitigation_key:path}"
)
async def set_mitigation_override(
    app_id: str,
    version_id: str,
    mitigation_key: str,
    body: MitigationOverrideRequest,
) -> dict:
    """Create or update the override for a single mitigation.

    ``mitigation_key`` is the URL-encoded ``mitigation_text``. Pydantic
    validation rejects empty comments before we touch the filesystem.
    """
    folder_id = _resolve_folder_id(app_id)
    overrides = _load_mitigation_overrides_for_version(folder_id, version_id)
    record = MitigationOverride(
        status=body.status,
        comment=body.comment.strip(),
        updated_at=_iso_now(),
    )
    overrides[mitigation_key] = record.model_dump()
    _save_mitigation_overrides(folder_id, version_id, overrides)
    return {"override": overrides[mitigation_key]}


@router.delete(
    "/applications/{app_id}/versions/{version_id}/mitigation-overrides/{mitigation_key:path}"
)
async def clear_mitigation_override(
    app_id: str, version_id: str, mitigation_key: str
) -> dict:
    """Remove an override. 200 even if no override existed (idempotent)."""
    folder_id = _resolve_folder_id(app_id)
    overrides = _load_mitigation_overrides_for_version(folder_id, version_id)
    overrides.pop(mitigation_key, None)
    _save_mitigation_overrides(folder_id, version_id, overrides)
    return {"success": True}


def _iso_now() -> str:
    """ISO 8601 UTC timestamp — separated so tests can monkeypatch."""
    from datetime import datetime, timezone

    return datetime.now(tz=timezone.utc).isoformat()
