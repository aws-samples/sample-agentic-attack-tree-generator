"""Factor → prior probability mapping.

The Tree Generator emits four qualitative attacker-factor fields per non-fact
step. This module converts those factors into a continuous prior probability
in [0, 1] via an additive log-odds model passed through a sigmoid.

All weights are checked in as constants — calibrate later against real data.
"""

from __future__ import annotations

import math

# Base logit for "an arbitrary attack step" — slightly unlikely by default.
BASE_LOGIT = -0.5

# Per-factor log-odds contributions. Empty / unrecognised values contribute 0.
FACTOR_WEIGHTS: dict[str, dict[str, float]] = {
    "skill_required": {"low": +1.0, "med": 0.0, "high": -0.8},
    "access_required": {"none": +0.8, "authenticated": 0.0, "privileged": -1.0},
    "detectability": {"low": +0.6, "med": 0.0, "high": -0.6},
    "exploit_maturity": {"theoretical": -1.2, "poc": 0.0, "weaponised": +1.0},
}

# Tech-stack markers: keys are the tech label, values are substrings that, when
# present in a step description, indicate the step targets that tech stack. If
# the scanner's tech_stack string does not contain the key, the marker
# represents a tech-stack mismatch and the posterior should discount the step.
#
# Kept in sync with the feasibility check in
# ``threatforest.agents.tree.verifier._check_feasibility``.
TECH_MARKERS: dict[str, list[str]] = {
    "java": ["java deserialization", "java rmi", "jndi injection", "spring actuator"],
    "php": ["php object injection", "php deserialization", "php type juggling"],
    ".net": [".net remoting", "viewstate deserialization", "aspx webshell"],
    "ruby": ["ruby marshal", "erb injection", "rails mass assignment"],
}


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1.0 - p))


def _clamp01(p: float) -> float:
    return min(max(p, 0.0), 1.0)


def factor_prior(step: dict) -> tuple[float, str]:
    """Compute a prior probability from the four attacker factors on *step*.

    Returns:
        (prior, rationale) — prior is in [0, 1]; rationale is a short string
        summarising which factor contributions were applied (empty string if
        all factors were missing / neutral).
    """
    logit = BASE_LOGIT
    parts: list[str] = []
    for field, table in FACTOR_WEIGHTS.items():
        value = step.get(field, "")
        if not value:
            continue
        contribution = table.get(value)
        if contribution is None:
            continue  # unrecognised value — treat as neutral
        logit += contribution
        if contribution != 0.0:
            parts.append(f"{field}={value} ({contribution:+.1f})")
    prior = _clamp01(_sigmoid(logit))
    rationale = "prior: " + ("; ".join(parts) if parts else "neutral (no factors)")
    return prior, rationale
