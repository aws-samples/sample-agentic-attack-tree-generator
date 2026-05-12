"""Canonical registry of all available threat frameworks.

This is the single source of truth for which frameworks ThreatForest supports.
All other code (config defaults, web server, CLI wizard) should import from here
rather than maintaining their own copies.

To add a new framework:
1. Place the STIX bundle in ``data/threat-intelligence/``
2. Add an entry to ``FRAMEWORKS`` below
3. That's it — the pipeline, CLI, and web console will pick it up automatically.
"""

from __future__ import annotations

FRAMEWORKS: dict[str, dict[str, str]] = {
    "attack": {
        "name": "MITRE ATT&CK Enterprise",
        "description": "835 techniques — cloud, network, endpoint",
        "stix_bundle": "enterprise-attack-18.0.json",
        "source_name": "mitre-attack",
        "kill_chain_name": "mitre-attack",
    },
    "atlas": {
        "name": "MITRE ATLAS",
        "description": "AI/ML adversarial threats",
        "stix_bundle": "stix-atlas.json",
        "source_name": "mitre-atlas",
        "kill_chain_name": "mitre-atlas",
    },
    "wiz": {
        "name": "Wiz Cloud Threat Landscape",
        "description": "Cloud-native attack techniques",
        "stix_bundle": "wiz-cloud-threat-landscape.json",
        "source_name": "wiz-cloud-threat-landscape",
        "kill_chain_name": "wiz-cloud-threat-landscape",
    },
}

# source_name values accepted by the mitigation mapper when indexing
# attack-pattern objects from STIX bundles.
STIX_SOURCE_NAMES: list[str] = [
    fw["source_name"] for fw in FRAMEWORKS.values()
] + ["aaf"]  # legacy alias used by some ATT&CK bundles


import re as _re


def technique_url(technique_id: str) -> str | None:
    """Build a deep link for a technique id across the supported frameworks.

    Format detection:
      - ``"AML.*"``        → ATLAS    https://atlas.mitre.org/techniques/<id>
      - ``"T1234[.001]"``  → ATT&CK   https://attack.mitre.org/techniques/T1234[/001]/
      - lowercase slug     → Wiz      https://threats.wiz.io/all-techniques/<slug>

    The Wiz check has to live before any ATT&CK fallback; otherwise slugs
    like ``refresh-token-compromise`` get mistakenly routed to attack.mitre.org
    and produce a 404.
    """
    if not technique_id:
        return None
    if technique_id.startswith("AML."):
        return f"https://atlas.mitre.org/techniques/{technique_id}"
    if _re.match(r"^[a-z][a-z0-9-]+$", technique_id):
        return f"https://threats.wiz.io/all-techniques/{technique_id}"
    parts = technique_id.split(".")
    if len(parts) > 1 and parts[1]:
        return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
    return f"https://attack.mitre.org/techniques/{parts[0]}/"
