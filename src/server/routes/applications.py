"""Application discovery and version listing API routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from server.models import ApplicationSummary, VersionSummary
from server.registry import ApplicationRegistry

router = APIRouter()

# Default registry — will be reconfigured by app.py at startup
_registry = ApplicationRegistry(scan_paths=[Path.home()])


def get_registry() -> ApplicationRegistry:
    """Return the module-level ApplicationRegistry instance."""
    return _registry


def set_registry(registry: ApplicationRegistry) -> None:
    """Replace the module-level ApplicationRegistry (called by app.py at startup)."""
    global _registry
    _registry = registry


def set_registry(registry: ApplicationRegistry) -> None:
    """Replace the module-level ApplicationRegistry (useful for testing)."""
    global _registry
    _registry = registry


@router.get("/applications", response_model=dict)
async def list_applications() -> dict:
    """Return all discovered ThreatForest applications.

    Response: ``{ "applications": [ ApplicationSummary, ... ] }``
    """
    registry = get_registry()
    applications = registry.discover_applications()
    return {"applications": [app.model_dump() for app in applications]}


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
    """Delete a ThreatForest application by removing its threatforest/ directory.

    - **404** if the application is not found
    - **500** if deletion fails
    """
    import shutil

    registry = get_registry()
    attack_trees_dir, scan_path = registry._find_attack_trees_dir(app_id)

    if attack_trees_dir is None:
        raise HTTPException(status_code=404, detail=f"Application '{app_id}' not found")

    # Delete the .threatforest/ or threatforest/ directory
    # attack_trees_dir is either .threatforest/output/ or threatforest/attack_trees/
    # We want to delete the top-level threatforest dir
    if attack_trees_dir.parent.name in ("threatforest", ".threatforest"):
        target = attack_trees_dir.parent
    else:
        target = attack_trees_dir

    try:
        shutil.rmtree(str(target))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {exc}")

    return {"success": True, "message": f"Application '{app_id}' deleted successfully"}

@router.get("/applications/{app_id}/versions/{version_id}/data")
async def get_version_data(app_id: str, version_id: str) -> JSONResponse:
    """Return the raw threatforest_data.json for a specific version.

    - **404** if the application, version, or data file is not found
    - **500** if the JSON file is malformed
    """
    registry = get_registry()
    attack_trees_dir, _scan_path = registry._find_attack_trees_dir(app_id)

    if attack_trees_dir is None:
        raise HTTPException(
            status_code=404,
            detail=f"Application '{app_id}' not found",
        )

    # Resolve the version directory.
    # Versioned layout: attack_trees/{version_id}/threatforest_data.json
    # Flat layout: attack_trees/threatforest_data.json (version_id is "latest")
    version_dir = attack_trees_dir / version_id
    if version_dir.is_dir():
        data_file = version_dir / registry.METADATA_FILE
    elif version_id == "latest" or version_id == attack_trees_dir.parent.parent.name:
        # Flat layout — data file lives directly in attack_trees/
        data_file = attack_trees_dir / registry.METADATA_FILE
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{version_id}' not found for application '{app_id}'",
        )

    if not data_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Threat data unavailable for this version",
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
    # and clean up fields for the frontend
    for tree in data.get("attack_trees", []):
        for mapping in tree.get("ttc_mappings", []):
            technique_id = mapping.get("technique_id", "")
            # Add MITRE URL
            if technique_id and "technique_url" not in mapping:
                tech_url_id = technique_id.replace(".", "/")
                mapping["technique_url"] = f"https://attack.mitre.org/techniques/{tech_url_id}/"
            # Remove reasoning field (contains "Embedding similarity" which we don't want to show)
            mapping.pop("reasoning", None)

    # Try to enrich with mitigations from STIX bundle
    try:
        from threatforest.config import config
        from threatforest.modules.workflow.ttc_mappings import MitigationMapper
        from pathlib import Path as _Path

        stix_path = getattr(config, "stix_bundle_path", None)
        if stix_path and _Path(stix_path).exists():
            mapper = MitigationMapper(str(stix_path))
            enriched_count = 0
            for tree in data.get("attack_trees", []):
                for mapping in tree.get("ttc_mappings", []):
                    technique_id = mapping.get("technique_id", "")
                    if technique_id and "mitigations" not in mapping:
                        mits = mapper.get_mitigations(technique_id)
                        if mits:
                            mapping["mitigations"] = mits
                            enriched_count += 1
    except Exception as _enrich_err:
        import logging
        logging.getLogger("threatforest.api").warning(f"Mitigation enrichment failed: {_enrich_err}")

    return JSONResponse(content=data)

