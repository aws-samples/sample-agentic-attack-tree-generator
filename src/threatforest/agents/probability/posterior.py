"""Bayesian posterior update + Markov reach rollup.

Takes a prior probability from the factor model and updates it with evidence
already produced by the pipeline:
  * TTP match similarity score (0..1) — high similarity means the step maps to
    a known MITRE technique, which is a strong positive signal.
  * Mitigation priority (1 = highest) — a high-priority mitigation raises
    attacker cost and discounts the probability.
  * Non-empty ``feasibility_note`` from the Tree Verifier — soft discount.
  * Tech-stack mismatch — strong discount (the step references technology the
    scanner did not detect in the project).

Update is additive in log-odds space, so contributions compose cleanly and
each adjustment is auditable via the returned rationale string.
"""

from __future__ import annotations

from threatforest.agents.probability.prior import (
    TECH_MARKERS,
    _clamp01,
    _logit,
    _sigmoid,
)

# Per-evidence weight table — calibrate later against real data.
TTP_SIMILARITY_SLOPE = 3.0       # λ = slope * (sim - 0.5), clipped to ±CLIP
TTP_SIMILARITY_CLIP = 1.5

MITIGATION_PRIORITY_LAMBDA = {1: -1.2, 2: -0.7, 3: -0.3}  # 4+ → 0
FEASIBILITY_NOTE_LAMBDA = -0.9
TECH_STACK_MISMATCH_LAMBDA = -1.5


def _clip(value: float, limit: float) -> float:
    return max(-limit, min(limit, value))


def update_posterior(
    prior: float,
    *,
    ttp_similarity: float | None = None,
    mitigation_priority: int | None = None,
    feasibility_note: str = "",
    tech_stack_mismatch: bool = False,
) -> tuple[float, str]:
    """Apply Bayesian log-odds updates to *prior* using pipeline evidence.

    Returns:
        (posterior, rationale) — posterior is in [0, 1]; rationale lists each
        adjustment that was applied, so the UI can surface "why".
    """
    logit = _logit(prior)
    parts: list[str] = []

    if ttp_similarity is not None:
        raw = TTP_SIMILARITY_SLOPE * (ttp_similarity - 0.5)
        adj = _clip(raw, TTP_SIMILARITY_CLIP)
        if adj != 0.0:
            logit += adj
            parts.append(f"ttp_similarity={ttp_similarity:.2f} ({adj:+.2f})")

    if mitigation_priority is not None:
        adj = MITIGATION_PRIORITY_LAMBDA.get(int(mitigation_priority), 0.0)
        if adj != 0.0:
            logit += adj
            parts.append(f"mitigation_priority={mitigation_priority} ({adj:+.2f})")

    if feasibility_note:
        logit += FEASIBILITY_NOTE_LAMBDA
        parts.append(f"feasibility_note ({FEASIBILITY_NOTE_LAMBDA:+.2f})")

    if tech_stack_mismatch:
        logit += TECH_STACK_MISMATCH_LAMBDA
        parts.append(f"tech_stack_mismatch ({TECH_STACK_MISMATCH_LAMBDA:+.2f})")

    posterior = _clamp01(_sigmoid(logit))
    rationale = ", ".join(parts) if parts else "no posterior evidence"
    return posterior, rationale


def detect_tech_stack_mismatch(description: str, tech_stack: str) -> bool:
    """Return True when *description* references a tech absent from *tech_stack*.

    Mirrors the markers used by the Tree Verifier's feasibility check.
    """
    if not description:
        return False
    desc_lower = description.lower()
    stack_lower = (tech_stack or "").lower()
    for tech, markers in TECH_MARKERS.items():
        if tech in stack_lower:
            continue  # tech is present — not a mismatch
        for marker in markers:
            if marker in desc_lower:
                return True
    return False


def compute_reach(steps: list[dict]) -> dict[str, float]:
    """Multiplicative Markov rollup along parent chains.

    The fact node is the attacker's precondition — its reach is 1.0. Every
    other step s has reach(s) = probability(s) * reach(parent(s)). We walk the
    tree with memoisation so cost is O(n).
    """
    by_id = {s.get("id", ""): s for s in steps if s.get("id")}
    memo: dict[str, float] = {}

    def reach(sid: str) -> float:
        if sid in memo:
            return memo[sid]
        step = by_id.get(sid)
        if step is None:
            return 1.0
        pid = step.get("parent_id", "")
        if step.get("category") == "fact" or not pid:
            memo[sid] = 1.0
            return 1.0
        parent_reach = reach(pid) if pid in by_id else 1.0
        memo[sid] = _clamp01(float(step.get("probability", 0.0)) * parent_reach)
        return memo[sid]

    for sid in by_id:
        reach(sid)
    return memo
