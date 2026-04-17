"""Application discovery and version listing API routes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

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
    VersionSummary,
)
from server.registry import ApplicationRegistry

router = APIRouter()

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
        versions = registry.get_versions(app.run_dir_name)
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

    - **404** if no application with this ID exists.
    """
    repo = get_app_repository()
    try:
        app = repo.get_application(app_id)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return app.model_dump()


@router.patch("/applications/by-id/{app_id}", response_model=dict)
async def update_application(app_id: str, body: ApplicationUpdateRequest) -> dict:
    """Apply a partial update (name and/or business_context) to an application.

    - **404** if no application with this ID exists.
    - **409** if the new name collides with another application.
    """
    repo = get_app_repository()
    try:
        app = repo.update_application(app_id, body)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ApplicationNameConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return app.model_dump()


@router.delete("/applications/by-id/{app_id}", status_code=200)
async def delete_application_record(app_id: str) -> dict:
    """Delete the persistent application record. Does not touch on-disk run artefacts.

    - **404** if no application with this ID exists.
    """
    repo = get_app_repository()
    try:
        repo.delete_application(app_id)
    except ApplicationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"success": True, "message": f"Application '{app_id}' deleted"}


@router.get("/applications/{app_id}/versions", response_model=dict)
async def list_versions(app_id: str) -> dict:
    """Return threat model versions for a specific application.

    Returns versions sorted by run date descending.

    - **404** if the application is not found
    """
    registry = get_registry()
    versions = registry.get_versions(app_id)
    if not versions:
        # Verify the app actually exists before returning 404
        apps = registry.discover_applications()
        app_ids = {app.id for app in apps}
        if app_id not in app_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Application '{app_id}' not found",
            )
    return {"versions": [v.model_dump() for v in versions]}


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
    data_file = registry.get_version_data_path(app_id, version_id)

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

    # Enrich TTC mappings with mitigations from STIX bundle (if available)
    for tree in data.get("attack_trees", []):
        for mapping in tree.get("ttc_mappings", []):
            technique_id = mapping.get("technique_id", "")
            if technique_id and "technique_url" not in mapping:
                tech_url_id = technique_id.replace(".", "/")
                mapping["technique_url"] = (
                    f"https://attack.mitre.org/techniques/{tech_url_id}/"
                )
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

    return JSONResponse(content=data)
