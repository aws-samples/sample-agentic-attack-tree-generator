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
