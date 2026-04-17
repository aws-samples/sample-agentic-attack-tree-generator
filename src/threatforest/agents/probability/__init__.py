"""Probability stage — computes per-step probability and Markov reach.

Pure-Python (no LLM). Consumes attacker-factor fields emitted by the Tree
Generator plus evidence from the TTP and Mitigation stages to produce a
calibrated probability per attack step and a multiplicative reach rollup.
"""

from threatforest.agents.probability.prior import factor_prior, TECH_MARKERS
from threatforest.agents.probability.posterior import update_posterior, compute_reach
from threatforest.agents.probability.stage import run_probability_stage

__all__ = [
    "factor_prior",
    "update_posterior",
    "compute_reach",
    "run_probability_stage",
    "TECH_MARKERS",
]
