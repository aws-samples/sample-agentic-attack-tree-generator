"""API tests for the mitigation-override endpoints (M3 v1).

Covers:
- GET on a run with no overrides file returns ``{}``
- PUT then GET round-trip
- PUT with empty / whitespace comment is rejected with 422
- DELETE clears an existing override; DELETE on absent is idempotent
- The /data endpoint stitches override fields into matching mitigations
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server.applications import ApplicationRepository  # noqa: E402
from server.registry import ApplicationRegistry  # noqa: E402
from server.routes.applications import (  # noqa: E402
    router as applications_router,
    set_app_repository,
    set_registry,
)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """FastAPI test client with isolated repo + runs_root."""
    repo = ApplicationRepository(store_path=tmp_path / "applications.json")
    set_app_repository(repo)

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    monkeypatch.setattr("server.registry.get_runs_root", lambda: runs_root)
    set_registry(ApplicationRegistry())

    app = FastAPI()
    app.include_router(applications_router, prefix="/api")
    return TestClient(app)


def _seed_run(runs_root: Path, app_slug: str, version_id: str) -> Path:
    """Set up a minimal run-folder layout the registry will discover."""
    project_dir = runs_root / app_slug
    run_dir = project_dir / version_id
    (run_dir / "output").mkdir(parents=True, exist_ok=True)
    (run_dir / "state").mkdir(parents=True, exist_ok=True)
    (project_dir / "metadata.json").write_text(
        '{"name": "x", "path": "/tmp"}', encoding="utf-8"
    )
    return run_dir


def _seed_data_with_mitigations(run_dir: Path, mitigation_text: str) -> None:
    """Drop a threatforest_data.json holding one tree + one mitigation."""
    payload = {
        "metadata": {"generator": "ThreatForest", "version": "2.0"},
        "project_info": {"application_name": "demo"},
        "status": "complete",
        "threat_count": 1,
        "high_severity_count": 1,
        "extraction_summary": {"total_threats": 1, "high_severity_count": 1},
        "threats": [{"id": "TS001"}],
        "attack_trees": [
            {
                "threat_id": "TS001",
                "ttc_mappings": [
                    {
                        "technique_id": "T1059",
                        "mitigations": [
                            {"mitigation_text": mitigation_text}
                        ],
                    }
                ],
                "mitigations": [],
            }
        ],
        "scanner_context": {},
        "mapping_summary": {"total_mappings": 1},
    }
    (run_dir / "output" / "threatforest_data.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_get_overrides_returns_empty_when_file_absent(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    response = client.get(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides"
    )

    assert response.status_code == 200
    assert response.json() == {"overrides": {}}


def test_put_then_get_round_trip(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    put = client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/Use SCP",
        json={"status": "already_implemented", "comment": "Org-wide SCP — see SEC-1042"},
    )
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["override"]["status"] == "already_implemented"
    assert body["override"]["comment"] == "Org-wide SCP — see SEC-1042"
    assert body["override"]["updated_at"]  # server stamped

    got = client.get(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides"
    )
    assert got.status_code == 200
    assert got.json()["overrides"]["Use SCP"]["status"] == "already_implemented"


def test_put_rejects_empty_comment(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    response = client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/M",
        json={"status": "wont_do", "comment": "   "},  # whitespace only
    )
    assert response.status_code == 422


def test_put_rejects_unknown_status(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    response = client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/M",
        json={"status": "totally_made_up", "comment": "n/a"},
    )
    assert response.status_code == 422


def test_delete_clears_existing_override(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/M",
        json={"status": "in_progress", "comment": "Started this week"},
    )
    delete = client.delete(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/M"
    )
    assert delete.status_code == 200
    assert delete.json() == {"success": True}

    after = client.get(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides"
    )
    assert after.json() == {"overrides": {}}


def test_delete_idempotent_when_absent(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    response = client.delete(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/never-was"
    )
    assert response.status_code == 200


def test_data_endpoint_merges_overrides_into_mitigations(
    client: TestClient, tmp_path: Path
) -> None:
    runs_root = tmp_path / "runs"
    run_dir = _seed_run(runs_root, "demo", "20260101_120000")
    _seed_data_with_mitigations(run_dir, "Rotate IAM keys quarterly")

    client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/Rotate IAM keys quarterly",
        json={"status": "accepted_risk", "comment": "Owner: cloud-sec; review 2026-Q4"},
    )

    response = client.get(
        "/api/applications/demo/versions/20260101_120000/data"
    )
    assert response.status_code == 200
    data = response.json()
    mit = data["attack_trees"][0]["ttc_mappings"][0]["mitigations"][0]
    assert mit["override_status"] == "accepted_risk"
    assert mit["override_comment"].startswith("Owner: cloud-sec")
    assert mit["override_updated_at"]


def test_data_endpoint_skips_unmatched_overrides(
    client: TestClient, tmp_path: Path
) -> None:
    """An override keyed against a missing mitigation must not blow up the merge."""
    runs_root = tmp_path / "runs"
    run_dir = _seed_run(runs_root, "demo", "20260101_120000")
    _seed_data_with_mitigations(run_dir, "Mitigation A")

    client.put(
        "/api/applications/demo/versions/20260101_120000/mitigation-overrides/Mitigation Z",
        json={"status": "not_relevant", "comment": "applies to nothing in this run"},
    )

    response = client.get(
        "/api/applications/demo/versions/20260101_120000/data"
    )
    assert response.status_code == 200
    mit = response.json()["attack_trees"][0]["ttc_mappings"][0]["mitigations"][0]
    assert "override_status" not in mit


def test_overrides_404_for_unknown_version(
    client: TestClient, tmp_path: Path
) -> None:
    """PUT against a missing version must 404 — there's nowhere to write."""
    runs_root = tmp_path / "runs"
    _seed_run(runs_root, "demo", "20260101_120000")

    response = client.put(
        "/api/applications/demo/versions/19990101_000000/mitigation-overrides/M",
        json={"status": "wont_do", "comment": "bogus"},
    )
    assert response.status_code == 404
