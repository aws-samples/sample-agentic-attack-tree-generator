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
