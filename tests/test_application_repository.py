"""Unit tests for the ApplicationRepository — CRUD, uniqueness, and persistence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Add src to path so the ``server`` package is importable without install.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.applications import (  # noqa: E402
    ApplicationNameConflictError,
    ApplicationNotFoundError,
    ApplicationPathConflictError,
    ApplicationRepository,
)
from server.models import (  # noqa: E402
    ApplicationCreateRequest,
    ApplicationUpdateRequest,
    BusinessContext,
)


def _make_business_context() -> BusinessContext:
    return BusinessContext(
        description="Test app for unit tests",
        regulatory_frameworks=["SOC2"],
        data_sensitivity="pii",
        main_cia_risk="confidentiality",
    )


def _make_request(
    name: str,
    project_path: str,
    *,
    context: BusinessContext | None = None,
) -> ApplicationCreateRequest:
    return ApplicationCreateRequest(
        name=name,
        project_path=project_path,
        business_context=context or _make_business_context(),
    )


@pytest.fixture()
def repo(tmp_path: Path) -> ApplicationRepository:
    """Fresh repository writing to an isolated tmp store."""
    return ApplicationRepository(store_path=tmp_path / "applications.json")


def test_create_and_get_roundtrip(repo: ApplicationRepository, tmp_path: Path) -> None:
    project = tmp_path / "my-project"
    project.mkdir()

    app = repo.create_application(_make_request("My App", str(project)))

    assert app.id.startswith("app_")
    assert app.name == "My App"
    assert app.slug == "my-app"
    assert app.run_dir_name == "my-app"
    assert app.project_path == str(project.resolve())
    assert app.created_at == app.updated_at
    assert app.business_context.data_sensitivity == "pii"

    # Round-trip through disk
    fetched = repo.get_application(app.id)
    assert fetched == app


def test_duplicate_name_is_rejected(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    p1 = tmp_path / "p1"
    p2 = tmp_path / "p2"
    p1.mkdir()
    p2.mkdir()

    repo.create_application(_make_request("Shared Name", str(p1)))

    with pytest.raises(ApplicationNameConflictError):
        repo.create_application(_make_request("shared name", str(p2)))


def test_duplicate_project_path_is_rejected(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "only-one"
    project.mkdir()

    repo.create_application(_make_request("First", str(project)))

    with pytest.raises(ApplicationPathConflictError):
        repo.create_application(_make_request("Second", str(project)))


def test_run_dir_name_disambiguates_when_names_differ_but_slugs_match(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    p1 = tmp_path / "one"
    p2 = tmp_path / "two"
    p1.mkdir()
    p2.mkdir()

    a1 = repo.create_application(_make_request("my app", str(p1)))
    a2 = repo.create_application(_make_request("My  App!", str(p2)))

    # Names differ visually but share the slug "my-app" — run_dir_names must differ.
    assert a1.run_dir_name == "my-app"
    assert a2.run_dir_name == "my-app-2"


def test_update_name_regenerates_slug_but_not_run_dir(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "p"
    project.mkdir()

    app = repo.create_application(_make_request("Original", str(project)))
    updated = repo.update_application(
        app.id, ApplicationUpdateRequest(name="Renamed")
    )

    assert updated.id == app.id
    assert updated.name == "Renamed"
    assert updated.slug == "renamed"
    assert updated.run_dir_name == app.run_dir_name  # unchanged
    assert updated.project_path == app.project_path
    assert updated.updated_at >= app.updated_at


def test_update_business_context_only(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "p"
    project.mkdir()

    app = repo.create_application(_make_request("App", str(project)))
    new_ctx = BusinessContext(
        description="Updated description",
        regulatory_frameworks=["HIPAA", "SOC2"],
        data_sensitivity="phi",
        main_cia_risk="integrity",
    )
    updated = repo.update_application(
        app.id, ApplicationUpdateRequest(business_context=new_ctx)
    )

    assert updated.business_context == new_ctx
    assert updated.name == app.name


def test_update_with_no_fields_is_rejected_by_model(
    repo: ApplicationRepository,
) -> None:
    with pytest.raises(ValueError):
        ApplicationUpdateRequest()  # no name, no business_context


def test_update_rename_collision_rejected(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    p1 = tmp_path / "p1"
    p2 = tmp_path / "p2"
    p1.mkdir()
    p2.mkdir()

    repo.create_application(_make_request("First", str(p1)))
    second = repo.create_application(_make_request("Second", str(p2)))

    with pytest.raises(ApplicationNameConflictError):
        repo.update_application(
            second.id, ApplicationUpdateRequest(name="first")
        )


def test_update_rename_to_own_name_is_noop(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "p"
    project.mkdir()
    app = repo.create_application(_make_request("Same", str(project)))

    updated = repo.update_application(
        app.id, ApplicationUpdateRequest(name="Same")
    )

    assert updated.name == "Same"
    assert updated.slug == app.slug


def test_get_unknown_app_raises_not_found(repo: ApplicationRepository) -> None:
    with pytest.raises(ApplicationNotFoundError):
        repo.get_application("app_does_not_exist")


def test_delete_removes_record(repo: ApplicationRepository, tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    app = repo.create_application(_make_request("Gone", str(project)))

    repo.delete_application(app.id)

    with pytest.raises(ApplicationNotFoundError):
        repo.get_application(app.id)


def test_delete_unknown_raises(repo: ApplicationRepository) -> None:
    with pytest.raises(ApplicationNotFoundError):
        repo.delete_application("app_nope")


def test_list_is_sorted_by_created_at(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    for i in range(3):
        p = tmp_path / f"p{i}"
        p.mkdir()
        repo.create_application(_make_request(f"App {i}", str(p)))

    apps = repo.list_applications()
    assert len(apps) == 3
    assert [a.name for a in apps] == ["App 0", "App 1", "App 2"]


def test_find_by_name_is_case_insensitive(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "p"
    project.mkdir()
    app = repo.create_application(_make_request("Mixed Case", str(project)))

    assert repo.find_by_name("mixed case") == app
    assert repo.find_by_name("MIXED CASE") == app
    assert repo.find_by_name("does-not-exist") is None


def test_find_by_project_path_resolves_symlinks_and_expands(
    repo: ApplicationRepository, tmp_path: Path
) -> None:
    project = tmp_path / "p"
    project.mkdir()
    app = repo.create_application(_make_request("App", str(project)))

    # Pass a path with a trailing slash or relative chunk — should still match.
    assert repo.find_by_project_path(str(project) + "/") == app
    assert repo.find_by_project_path(str(project / "." / ".." / project.name)) == app


def test_persistence_across_instances(tmp_path: Path) -> None:
    store = tmp_path / "applications.json"
    repo1 = ApplicationRepository(store_path=store)
    project = tmp_path / "p"
    project.mkdir()
    app = repo1.create_application(_make_request("Persistent", str(project)))

    repo2 = ApplicationRepository(store_path=store)
    assert repo2.get_application(app.id) == app


def test_store_file_is_valid_json(tmp_path: Path) -> None:
    store = tmp_path / "applications.json"
    repo = ApplicationRepository(store_path=store)
    project = tmp_path / "p"
    project.mkdir()
    repo.create_application(_make_request("App", str(project)))

    loaded = json.loads(store.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    assert len(loaded) == 1
    first = next(iter(loaded.values()))
    assert set(first.keys()) >= {
        "id",
        "name",
        "slug",
        "project_path",
        "business_context",
        "created_at",
        "updated_at",
        "run_dir_name",
    }
