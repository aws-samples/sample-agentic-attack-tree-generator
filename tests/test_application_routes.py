"""API tests for the v2 Application CRUD endpoints.

Exercises the FastAPI routes defined in ``src/server/routes/applications.py``
against an isolated ``ApplicationRepository`` backed by ``tmp_path``. Does not
touch the real ``.threatforest/applications.json`` store.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.applications import ApplicationRepository  # noqa: E402
from server.routes.applications import (  # noqa: E402
    router as applications_router,
    set_app_repository,
)


def _context_payload() -> dict:
    return {
        "description": "Routes test app",
        "regulatory_frameworks": ["SOC2"],
        "data_sensitivity": "pii",
        "main_cia_risk": "confidentiality",
    }


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    """FastAPI test client backed by a fresh, isolated repository."""
    repo = ApplicationRepository(store_path=tmp_path / "applications.json")
    set_app_repository(repo)

    app = FastAPI()
    app.include_router(applications_router, prefix="/api")
    return TestClient(app)


def _mkproject(tmp_path: Path, name: str) -> str:
    project = tmp_path / name
    project.mkdir()
    return str(project)


def test_create_application_returns_201(
    client: TestClient, tmp_path: Path
) -> None:
    response = client.post(
        "/api/applications",
        json={
            "name": "First App",
            "project_path": _mkproject(tmp_path, "first"),
            "business_context": _context_payload(),
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "First App"
    assert body["slug"] == "first-app"
    assert body["id"].startswith("app_")
    assert body["business_context"]["data_sensitivity"] == "pii"


def test_create_duplicate_name_returns_409(
    client: TestClient, tmp_path: Path
) -> None:
    client.post(
        "/api/applications",
        json={
            "name": "Shared",
            "project_path": _mkproject(tmp_path, "a"),
            "business_context": _context_payload(),
        },
    )

    clash = client.post(
        "/api/applications",
        json={
            "name": "shared",  # case-insensitive clash
            "project_path": _mkproject(tmp_path, "b"),
            "business_context": _context_payload(),
        },
    )

    assert clash.status_code == 409
    assert "already exists" in clash.json()["detail"].lower()


def test_create_duplicate_path_returns_409(
    client: TestClient, tmp_path: Path
) -> None:
    project = _mkproject(tmp_path, "same")
    client.post(
        "/api/applications",
        json={
            "name": "First",
            "project_path": project,
            "business_context": _context_payload(),
        },
    )

    clash = client.post(
        "/api/applications",
        json={
            "name": "Second",
            "project_path": project,
            "business_context": _context_payload(),
        },
    )

    assert clash.status_code == 409


def test_get_application_returns_record(
    client: TestClient, tmp_path: Path
) -> None:
    created = client.post(
        "/api/applications",
        json={
            "name": "Gettable",
            "project_path": _mkproject(tmp_path, "g"),
            "business_context": _context_payload(),
        },
    ).json()

    fetched = client.get(f"/api/applications/by-id/{created['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == created["id"]


def test_get_unknown_application_returns_404(client: TestClient) -> None:
    response = client.get("/api/applications/by-id/app_does_not_exist")
    assert response.status_code == 404


def test_get_application_by_run_dir_name_falls_back(
    client: TestClient, tmp_path: Path
) -> None:
    """``GET /applications/by-id/{x}`` must accept the folder-slug too.

    Breadcrumb-rendering pages only have a URL segment — sometimes that's
    the opaque ``app_id``, sometimes it's the folder-derived ``run_dir_name``
    (for runs created before the v2 UX or via the registry). Both forms
    must resolve to the persistent record.
    """
    created = client.post(
        "/api/applications",
        json={
            "name": "Sony SIE LAMS M2M",
            "project_path": _mkproject(tmp_path, "lams-m2m"),
            "business_context": _context_payload(),
        },
    ).json()

    # run_dir_name is derived from the name slug.
    fetched = client.get(
        f"/api/applications/by-id/{created['run_dir_name']}"
    )
    assert fetched.status_code == 200
    assert fetched.json()["id"] == created["id"]
    assert fetched.json()["name"] == "Sony SIE LAMS M2M"


def test_patch_application_updates_name(
    client: TestClient, tmp_path: Path
) -> None:
    created = client.post(
        "/api/applications",
        json={
            "name": "Original",
            "project_path": _mkproject(tmp_path, "r"),
            "business_context": _context_payload(),
        },
    ).json()

    updated = client.patch(
        f"/api/applications/by-id/{created['id']}",
        json={"name": "Renamed"},
    )

    assert updated.status_code == 200
    body = updated.json()
    assert body["name"] == "Renamed"
    assert body["slug"] == "renamed"
    # Run dir is fixed at creation time, not regenerated on rename.
    assert body["run_dir_name"] == created["run_dir_name"]


def test_patch_application_rejects_empty_body(
    client: TestClient, tmp_path: Path
) -> None:
    created = client.post(
        "/api/applications",
        json={
            "name": "Empty Patch",
            "project_path": _mkproject(tmp_path, "ep"),
            "business_context": _context_payload(),
        },
    ).json()

    response = client.patch(
        f"/api/applications/by-id/{created['id']}",
        json={},
    )
    # Pydantic validator rejects at the request-body layer.
    assert response.status_code == 422


def test_patch_name_collision_returns_409(
    client: TestClient, tmp_path: Path
) -> None:
    client.post(
        "/api/applications",
        json={
            "name": "Alpha",
            "project_path": _mkproject(tmp_path, "a"),
            "business_context": _context_payload(),
        },
    )
    second = client.post(
        "/api/applications",
        json={
            "name": "Beta",
            "project_path": _mkproject(tmp_path, "b"),
            "business_context": _context_payload(),
        },
    ).json()

    response = client.patch(
        f"/api/applications/by-id/{second['id']}",
        json={"name": "alpha"},
    )
    assert response.status_code == 409


def test_delete_application_record(
    client: TestClient, tmp_path: Path
) -> None:
    created = client.post(
        "/api/applications",
        json={
            "name": "Gone",
            "project_path": _mkproject(tmp_path, "d"),
            "business_context": _context_payload(),
        },
    ).json()

    response = client.delete(f"/api/applications/by-id/{created['id']}")
    assert response.status_code == 200

    assert client.get(
        f"/api/applications/by-id/{created['id']}"
    ).status_code == 404


def test_delete_unknown_returns_404(client: TestClient) -> None:
    response = client.delete("/api/applications/by-id/app_nope")
    assert response.status_code == 404


class _StubRegistry:
    """Minimal stand-in for ``ApplicationRegistry`` used in project-path tests.

    Only implements the ``get_versions`` / ``discover_applications`` surface
    the routes touch. Each ``run_dir_name`` can be seeded with an arbitrary
    version count so tests can simulate "zero runs" vs "has runs" without
    touching the filesystem.
    """

    def __init__(self, versions_by_dir: dict[str, int] | None = None) -> None:
        self._versions = dict(versions_by_dir or {})

    def set_version_count(self, run_dir_name: str, count: int) -> None:
        self._versions[run_dir_name] = count

    def get_versions(
        self, run_dir_name: str, active_run_ids: dict[str, str] | None = None
    ) -> list:
        # Return a list of the right length so ``len(versions)`` is accurate;
        # the routes only ever inspect length/emptiness, not content.
        return [None] * self._versions.get(run_dir_name, 0)

    def discover_applications(self) -> list:
        return []


def test_patch_project_path_before_first_run(
    client: TestClient, tmp_path: Path
) -> None:
    """Path edits succeed when no runs exist on disk."""
    from server.routes.applications import set_registry

    registry = _StubRegistry()
    set_registry(registry)

    created = client.post(
        "/api/applications",
        json={
            "name": "PathEdit",
            "project_path": _mkproject(tmp_path, "original"),
            "business_context": _context_payload(),
        },
    ).json()

    new_path = _mkproject(tmp_path, "renamed-repo")
    response = client.patch(
        f"/api/applications/by-id/{created['id']}",
        json={"project_path": new_path},
    )

    assert response.status_code == 200
    body = response.json()
    # The repo normalises to an absolute, resolved path; compare normalised.
    from server.applications import _normalise_path

    assert _normalise_path(body["project_path"]) == _normalise_path(new_path)


def test_patch_project_path_allowed_after_first_run(
    client: TestClient, tmp_path: Path
) -> None:
    """Path edits remain allowed after runs exist so users can track folder
    renames or moves. The stable run_dir_name keeps on-disk history attached
    to the application regardless of where the source lives now.
    """
    from server.routes.applications import set_registry

    registry = _StubRegistry()
    set_registry(registry)

    created = client.post(
        "/api/applications",
        json={
            "name": "Movable",
            "project_path": _mkproject(tmp_path, "original-location"),
            "business_context": _context_payload(),
        },
    ).json()

    # Simulate a run having been produced for this app.
    registry.set_version_count(created["run_dir_name"], 2)

    new_path = _mkproject(tmp_path, "new-location")
    response = client.patch(
        f"/api/applications/by-id/{created['id']}",
        json={"project_path": new_path},
    )

    assert response.status_code == 200
    from server.applications import _normalise_path

    assert _normalise_path(response.json()["project_path"]) == _normalise_path(new_path)
    # run_dir_name stays pinned so on-disk history does not drift.
    assert response.json()["run_dir_name"] == created["run_dir_name"]


def test_patch_project_path_noop_after_runs_is_allowed(
    client: TestClient, tmp_path: Path
) -> None:
    """Re-submitting the same path after runs exist must not 409.

    The lock only applies when the path would actually change.
    """
    from server.routes.applications import set_registry

    registry = _StubRegistry()
    set_registry(registry)

    original_path = _mkproject(tmp_path, "stable")
    created = client.post(
        "/api/applications",
        json={
            "name": "Stable",
            "project_path": original_path,
            "business_context": _context_payload(),
        },
    ).json()

    registry.set_version_count(created["run_dir_name"], 3)

    # Re-send the same path (possibly with a trailing slash) — it normalises
    # to the same value so the change-detection gate should let it through.
    response = client.patch(
        f"/api/applications/by-id/{created['id']}",
        json={"project_path": original_path},
    )

    assert response.status_code == 200


def test_patch_project_path_conflict_returns_409(
    client: TestClient, tmp_path: Path
) -> None:
    """Moving app B onto app A's path (before A has runs) still conflicts."""
    from server.routes.applications import set_registry

    registry = _StubRegistry()
    set_registry(registry)

    app_a = client.post(
        "/api/applications",
        json={
            "name": "A",
            "project_path": _mkproject(tmp_path, "a"),
            "business_context": _context_payload(),
        },
    ).json()
    app_b = client.post(
        "/api/applications",
        json={
            "name": "B",
            "project_path": _mkproject(tmp_path, "b"),
            "business_context": _context_payload(),
        },
    ).json()

    response = client.patch(
        f"/api/applications/by-id/{app_b['id']}",
        json={"project_path": app_a["project_path"]},
    )

    assert response.status_code == 409


class _StubRegistryWithVersions:
    """Variant of ``_StubRegistry`` that yields real ``VersionSummary``s.

    ``list_versions`` iterates versions and serializes them via
    ``.model_dump()``, so the lighter-weight ``_StubRegistry`` (which
    returns ``[None, ...]``) doesn't work for route-level tests that
    exercise the full response payload.
    """

    def __init__(self, versions_by_dir: dict[str, list] | None = None) -> None:
        self._versions = dict(versions_by_dir or {})

    def set_versions(self, run_dir_name: str, versions: list) -> None:
        self._versions[run_dir_name] = versions

    def get_versions(
        self, run_dir_name: str, active_run_ids: dict[str, str] | None = None
    ) -> list:
        return list(self._versions.get(run_dir_name, []))

    def discover_applications(self) -> list:
        return []


def test_list_versions_translates_v2_app_id_to_run_dir_name(
    client: TestClient, tmp_path: Path
) -> None:
    """GET /applications/{app_id}/versions resolves the persistent ID.

    Regression: the route used to pass the opaque v2 ``app_id`` straight
    to ``registry.get_versions``, which looks up by on-disk folder name.
    After the fix the route must translate ``app_id → run_dir_name`` so
    runs actually surface under their owning application.
    """
    from server.models import VersionSummary
    from server.routes.applications import set_registry

    created = client.post(
        "/api/applications",
        json={
            "name": "Versioned",
            "project_path": _mkproject(tmp_path, "versioned"),
            "business_context": _context_payload(),
        },
    ).json()

    # Seed one version under the app's run_dir_name (what's actually on disk)
    # — NOT under the opaque app_id.
    registry = _StubRegistryWithVersions()
    registry.set_versions(
        created["run_dir_name"],
        [
            VersionSummary(
                id="v1",
                run_date="2026-04-20T12:00:00Z",
                status="completed",
                threat_count=3,
                high_severity_count=1,
                categories=[],
            )
        ],
    )
    set_registry(registry)

    response = client.get(f"/api/applications/{created['id']}/versions")

    assert response.status_code == 200
    versions = response.json()["versions"]
    assert len(versions) == 1
    assert versions[0]["id"] == "v1"


def test_list_applications_includes_business_context(
    client: TestClient, tmp_path: Path
) -> None:
    client.post(
        "/api/applications",
        json={
            "name": "Listed",
            "project_path": _mkproject(tmp_path, "l"),
            "business_context": _context_payload(),
        },
    )

    response = client.get("/api/applications")
    assert response.status_code == 200
    apps = response.json()["applications"]
    # The persistent app should be present and carry its business context.
    by_name = {a["name"]: a for a in apps}
    assert "Listed" in by_name
    assert by_name["Listed"]["business_context"]["data_sensitivity"] == "pii"
