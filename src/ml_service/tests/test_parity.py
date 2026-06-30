"""WS-1 gate: the ML service must return the SAME results as the in-process matcher.

These tests load the real embedding model + STIX graphs, so they are slow and
gated behind the TF_ML_PARITY env flag (set it to run them locally / in CI with
model access). Without the flag they're skipped so the fast unit suite stays fast.

Run with:
    TF_ML_PARITY=1 .venv/bin/python -m pytest src/ml_service/tests/test_parity.py -q
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

RUN_PARITY = os.environ.get("TF_ML_PARITY") in ("1", "true", "True")

pytestmark = pytest.mark.skipif(
    not RUN_PARITY,
    reason="set TF_ML_PARITY=1 to run model-loading parity tests",
)

# A fixed, deterministic step set spanning generic + AWS-flavored attack steps
# (the latter exercises the AWS-term boost path in TTCMatcher).
STEPS = [
    "Attacker exploits a public-facing web application to gain initial access",
    "Adversary assumes an over-permissive IAM role to escalate privileges in AWS",
    "Exfiltrate sensitive data from a misconfigured S3 bucket",
    "Inject malicious commands via an unvalidated request parameter",
]
TOP_K = 3


def _client() -> TestClient:
    from ml_service.app import create_app

    return TestClient(create_app(warm=False))


def _in_process_results():
    from threatforest.config import config
    from threatforest.modules.workflow.ttc_mappings.matcher import TTCMatcher

    matcher = TTCMatcher(min_similarity=config.ttc_threshold)
    return matcher.match_steps(STEPS, top_k=TOP_K)


def test_match_steps_parity_with_in_process_matcher() -> None:
    """Service /match_steps must equal a direct TTCMatcher.match_steps call."""
    expected = _in_process_results()

    client = _client()
    resp = client.post("/match_steps", json={"steps": STEPS, "top_k": TOP_K})
    assert resp.status_code == 200, resp.text
    got = resp.json()["results"]

    # Same set of matched steps, same order.
    assert [r["attack_step"] for r in got] == [r["attack_step"] for r in expected]

    for got_step, exp_step in zip(got, expected):
        got_ids = [m["technique_id"] for m in got_step["matches"]]
        exp_ids = [m["technique_id"] for m in exp_step["matches"]]
        assert got_ids == exp_ids, (
            f"technique-id mismatch for step {got_step['attack_step'][:40]!r}: "
            f"{got_ids} != {exp_ids}"
        )
        # Scores identical to float tolerance (same model, same math).
        for gm, em in zip(got_step["matches"], exp_step["matches"]):
            assert gm["technique_id"] == em["technique_id"]
            assert gm["similarity"] == pytest.approx(em["similarity"], abs=1e-6)
            assert gm["framework"] == em["framework"]
            assert gm["confidence"] == em["confidence"]


def test_embed_returns_vectors() -> None:
    """/embed returns one vector per input text with a stable dimension."""
    client = _client()
    resp = client.post("/embed", json={"texts": STEPS})
    assert resp.status_code == 200, resp.text
    vectors = resp.json()["vectors"]
    assert len(vectors) == len(STEPS)
    dims = {len(v) for v in vectors}
    assert len(dims) == 1 and next(iter(dims)) > 0


def test_health_reports_warm_state() -> None:
    client = _client()
    # Trigger a load, then health should reflect it.
    client.post("/embed", json={"texts": ["warm up"]})
    h = client.get("/health").json()
    assert h["status"] == "ok"
    assert h["embedding_model_loaded"] is True
