"""API tests for ``POST /runs`` app_id resolution.

Covers the v2 UX contract where a fresh run must reference a persisted
``Application`` via ``app_id``, and the route resolves ``project_path`` from
the stored record rather than trusting the client.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.applications import ApplicationRepository  # noqa: E402
from server.models import ApplicationCreateRequest, BusinessContext, RunConfig  # noqa: E402
from server.routes.applications import (  # noqa: E402
    router as applications_router,
    set_app_repository,
)
from server.routes.runs import router as runs_router, set_run_manager  # noqa: E402
from server.run_manager import RunManager  # noqa: E402


def _noop_executor(
    config: RunConfig,
    progress_callback: Callable[[Any], None],
    scan_control: Any | None = None,
    interaction_fn: Any | None = None,
) -> dict[str, str]:
    """Stand-in orchestrator — captures the RunConfig without doing any work."""
    _noop_executor.last_config = config  # type: ignore[attr-defined]
    return {"status": "complete", "output_dir": "", "app_id": "stub"}


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    """Test client wired to an isolated repo and a stub RunManager."""
    repo = ApplicationRepository(store_path=tmp_path / "applications.json")
    set_app_repository(repo)

    manager = RunManager(executor=_noop_executor)
    set_run_manager(manager)

    app = FastAPI()
    app.include_router(applications_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    return TestClient(app)


def _create_app(tmp_path: Path, name: str = "Runnable") -> tuple[str, str]:
    """Seed one application directly through the repository, return (id, path)."""
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    repo = ApplicationRepository(
        store_path=tmp_path / "applications.json",
    )
    set_app_repository(repo)
    app = repo.create_application(
        ApplicationCreateRequest(
            name=name,
            project_path=str(project),
            business_context=BusinessContext(
                description="d",
                regulatory_frameworks=["SOC2"],
                data_sensitivity="pii",
                main_cia_risk="confidentiality",
            ),
        )
    )
    return app.id, app.project_path


def test_create_run_without_app_id_rejected(client: TestClient, tmp_path: Path) -> None:
    # Need a project_path that exists, otherwise the later check would mask
    # the 400 we're testing for.
    project = tmp_path / "p"
    project.mkdir()

    response = client.post(
        "/api/runs",
        json={
            "project_path": str(project),
            "threat_source": "auto",
        },
    )

    assert response.status_code == 400
    assert "app_id" in response.json()["detail"].lower()


def test_create_run_with_unknown_app_id_returns_404(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/runs",
        json={
            "project_path": "/tmp/whatever",
            "threat_source": "auto",
            "app_id": "app_missing",
        },
    )
    assert response.status_code == 404


def test_create_run_resolves_project_path_from_app(
    client: TestClient, tmp_path: Path
) -> None:
    """When the client omits project_path, the route fills it from the record.

    The NewRunPage normally surfaces the stored path as (editable) default and
    submits it verbatim, but omitting the field must still work — the stored
    path is the authoritative fallback.
    """
    app_id, stored_path = _create_app(tmp_path)

    response = client.post(
        "/api/runs",
        json={
            "project_path": "",  # empty — no user edit, fall back to record
            "threat_source": "auto",
            "app_id": app_id,
        },
    )

    assert response.status_code == 202
    body = response.json()
    assert "run_id" in body

    # The executor stub captured the resolved config — verify the fallback.
    captured: RunConfig = _noop_executor.last_config  # type: ignore[attr-defined]
    assert captured.project_path == stored_path
    assert captured.app_id == app_id


def test_create_run_accepts_run_dir_name_as_app_id(
    client: TestClient, tmp_path: Path
) -> None:
    """Folder-slug URLs reach POST /runs too — must resolve to the record.

    Regression: if the UI navigated to ``/applications/<run_dir_name>`` (e.g.
    via a legacy folder-derived row) and then started a new run, the payload's
    ``app_id`` was the slug, not the opaque ID. The route used to 404 with
    'Unknown application: <slug>'; it now falls back to run-dir-name lookup
    and normalises the stored app_id on the config.
    """
    from server.applications import ApplicationRepository

    app_id, stored_path = _create_app(tmp_path)
    repo = ApplicationRepository(store_path=tmp_path / "applications.json")
    app = repo.get_application(app_id)

    response = client.post(
        "/api/runs",
        json={
            "project_path": stored_path,
            "threat_source": "auto",
            "app_id": app.run_dir_name,  # folder-slug, not opaque id
        },
    )

    assert response.status_code == 202
    captured: RunConfig = _noop_executor.last_config  # type: ignore[attr-defined]
    assert captured.project_path == stored_path
    # app_id on the config is normalised to the opaque form.
    assert captured.app_id == app_id


def test_create_run_persists_edited_project_path_back_to_app(
    client: TestClient, tmp_path: Path
) -> None:
    """Submitting a *different* project_path at run time updates the record.

    Rationale: users can rename / relocate their source tree. The NewRunPage
    surfaces the stored path as editable; if they change it the new location
    must stick so every future run (and the app overview) picks it up.
    """
    from server.applications import ApplicationRepository, _normalise_path

    app_id, original_path = _create_app(tmp_path, name="Relocatable")

    # A real, different directory that the backend can resolve.
    new_location = tmp_path / "moved"
    new_location.mkdir()

    response = client.post(
        "/api/runs",
        json={
            "project_path": str(new_location),
            "threat_source": "auto",
            "app_id": app_id,
        },
    )

    assert response.status_code == 202
    captured: RunConfig = _noop_executor.last_config  # type: ignore[attr-defined]
    assert _normalise_path(captured.project_path) == _normalise_path(str(new_location))

    # And the change is persisted.
    repo = ApplicationRepository(store_path=tmp_path / "applications.json")
    stored = repo.get_application(app_id)
    assert _normalise_path(stored.project_path) == _normalise_path(str(new_location))
    assert _normalise_path(stored.project_path) != _normalise_path(original_path)


def test_list_versions_for_v2_app_without_runs_returns_empty_list(
    client: TestClient, tmp_path: Path
) -> None:
    """Freshly-created v2 app has zero runs — route must return ``[]`` not 404.

    Regression: ``list_versions`` used to pass the raw v2 ``app_id`` token
    straight to ``registry.get_versions``, which looks up by on-disk folder
    name. A v2 app with no runs yet is a legitimate state and should render
    an empty version table on the frontend, not a 404.
    """
    app_id, _ = _create_app(tmp_path, name="Fresh App")

    response = client.get(f"/api/applications/{app_id}/versions")

    assert response.status_code == 200
    assert response.json() == {"versions": []}


def test_resume_path_does_not_require_app_id(
    client: TestClient, tmp_path: Path
) -> None:
    # When resume_run_dir is set, the route must skip the app_id check so the
    # legacy resume flow (which reconstructs RunConfig from pause_state.json)
    # still works.
    project = tmp_path / "resume"
    project.mkdir()

    response = client.post(
        "/api/runs",
        json={
            "project_path": str(project),
            "threat_source": "auto",
            "resume_run_dir": str(project),
        },
    )
    # The request reaches the RunManager, which accepts the config and spawns
    # the stub executor.
    assert response.status_code == 202
