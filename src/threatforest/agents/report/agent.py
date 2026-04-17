"""Report Generator — deterministic, no LLM needed.

Compiles all state files into a structured Markdown report.
"""

import json
from pathlib import Path

from threatforest.agents.scanner.agent import STATE_DIR, resolve_state_dir

OUTPUT_DIR = ".threatforest/output"  # legacy default, overridden by run_dir
OUTPUT_FILE = "threat_model_report.md"


def _resolve_output_dir(repo_path: str, run_dir: str | None = None) -> Path:
    """Return the output directory — uses *run_dir*/output if provided, else legacy path."""
    if run_dir:
        od = Path(run_dir) / "output"
    else:
        od = Path(repo_path) / OUTPUT_DIR
    od.mkdir(parents=True, exist_ok=True)
    return od


def _read_json(path: Path) -> dict:
    try:
        raw = path.read_text()
        raw = raw.replace(",\n]", "\n]").replace(",]", "]")
        return json.loads(raw)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def run_report_generator(repo_path: str, run_dir: str | None = None) -> str:
    """Generate the threat model report from state files. No LLM needed."""
    state_dir = resolve_state_dir(repo_path, run_dir)
    output_dir = _resolve_output_dir(repo_path, run_dir)

    scanner = _read_json(state_dir / "scanner_context.json")
    threats_data = _read_json(state_dir / "threats.json")
    trees_data = _read_json(state_dir / "attack_trees.json")
    mappings_data = _read_json(state_dir / "ttp_mappings.json")
    mitigations_data = _read_json(state_dir / "mitigations.json")

    threats = threats_data.get("threats", [])
    trees = trees_data.get("attack_trees", [])
    mappings = mappings_data.get("ttp_mappings", [])
    mitigations = mitigations_data.get("mitigations", [])

    lines = ["# Threat Model Report", ""]

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append(f"This report covers {len(threats)} threats across {len(trees)} attack trees "
                 f"with {sum(len(t.get('steps', [])) for t in trees)} attack steps, "
                 f"{len(mappings)} TTP mappings, and {len(mitigations)} mitigations "
                 f"for the {Path(repo_path).name} project.")
    lines.append("")

    # Project Context
    lines.append("## Project Context")
    lines.append(f"- **Cloud Provider**: {scanner.get('cloud_provider', 'unknown').upper()}")
    lines.append(f"- **Tech Stack**: {scanner.get('tech_stack', 'N/A')}")
    lines.append(f"- **Services**: {', '.join(scanner.get('services', []))}")
    lines.append(f"- **Auth Mechanisms**: {', '.join(scanner.get('auth_mechanisms', []))}")
    lines.append(f"- **Files Analyzed**: {len(scanner.get('files_analyzed', []))}")
    lines.append("")

    # Threats
    lines.append("## Threats")
    for t in threats:
        sev = t.get("priority") or t.get("severity") or "medium"
        title = t.get("title") or t.get("name") or t.get("description", "")[:80]
        lines.append(f"### {t.get('id', '?')}: {title}")
        lines.append(f"**Severity**: {sev}")
        if t.get("description"):
            lines.append(f"\n{t['description']}")
        if t.get("affected_components"):
            lines.append(f"\n**Affected Components**: {', '.join(t['affected_components'])}")
        lines.append("")

    # Attack Trees
    lines.append("## Attack Trees")
    for tree in trees:
        goal = tree.get("root_goal", "")
        steps = tree.get("steps", [])
        lines.append(f"### {tree.get('id', '?')}: {goal}")
        lines.append(f"Steps: {len(steps)}")
        for s in steps[:10]:
            lines.append(f"- {s.get('description', '')}")
        if len(steps) > 10:
            lines.append(f"- ... and {len(steps) - 10} more steps")
        lines.append("")

    # TTP Mappings
    lines.append("## TTP Mappings")
    lines.append("| Attack Step | Technique | Name | Framework | Similarity |")
    lines.append("|-------------|-----------|------|-----------|------------|")
    for m in mappings:
        step = m.get("attack_step_id", m.get("attack_step_description", ""))[:50]
        fw = m.get("framework", "attack").upper()
        lines.append(f"| {step} | {m.get('technique_id', '')} | {m.get('technique_name', '')} | {fw} | {m.get('similarity_score', 0):.2f} |")
    lines.append("")

    # Mitigations — grouped by remediation type
    lines.append("## Mitigations")

    REMEDIATION_LABELS = {
        "quick_win": "Quick Wins",
        "short_term": "Short Term",
        "medium_term": "Medium Term",
        "long_term": "Long Term",
        "monitoring": "Monitoring & Detection",
    }
    REMEDIATION_ORDER = ["quick_win", "short_term", "medium_term", "long_term", "monitoring"]

    # Summary table
    lines.append("| Priority | Mitigation | Remediation | Technique |")
    lines.append("|----------|-----------|-------------|-----------|")
    sorted_mits = sorted(mitigations, key=lambda m: m.get("priority", 99))
    for m in sorted_mits:
        pri = m.get("priority", "?")
        rtype = m.get("remediation_type", "")
        label = REMEDIATION_LABELS.get(rtype, rtype or "—")
        text = m.get("mitigation_text", "")[:80]
        tid = m.get("technique_id", "")
        lines.append(f"| {pri} | {text} | {label} | {tid} |")
    lines.append("")

    # Detailed sections grouped by remediation type
    from collections import defaultdict as _defaultdict
    by_rtype = _defaultdict(list)
    for m in sorted_mits:
        rtype = m.get("remediation_type", "other")
        by_rtype[rtype].append(m)

    for rtype in REMEDIATION_ORDER:
        group = by_rtype.pop(rtype, [])
        if not group:
            continue
        lines.append(f"### {REMEDIATION_LABELS.get(rtype, rtype)}")
        for m in group:
            pri = m.get("priority", "?")
            lines.append(f"#### [P{pri}] {m.get('mitigation_text', '')[:100]}")
            if m.get("implementation_guidance"):
                lines.append(f"\n{m['implementation_guidance']}")
            if m.get("evidence"):
                lines.append("\n**Evidence**:")
                for e in m["evidence"]:
                    lines.append(f"- [{e.get('source_type', '')}] {e.get('source_ref', '')}: {e.get('relevance', '')}")
            lines.append("")

    # Any remaining without a recognized remediation_type
    for rtype, group in by_rtype.items():
        if not group:
            continue
        lines.append(f"### {REMEDIATION_LABELS.get(rtype, rtype.replace('_', ' ').title())}")
        for m in group:
            pri = m.get("priority", "?")
            lines.append(f"#### [P{pri}] {m.get('mitigation_text', '')[:100]}")
            if m.get("implementation_guidance"):
                lines.append(f"\n{m['implementation_guidance']}")
            if m.get("evidence"):
                lines.append("\n**Evidence**:")
                for e in m["evidence"]:
                    lines.append(f"- [{e.get('source_type', '')}] {e.get('source_ref', '')}: {e.get('relevance', '')}")
            lines.append("")

    # Coverage Summary
    lines.append("## Coverage Summary")
    lines.append(f"- **Threats**: {len(threats)}")
    lines.append(f"- **Attack Trees**: {len(trees)}")
    lines.append(f"- **Attack Steps**: {sum(len(t.get('steps', [])) for t in trees)}")
    lines.append(f"- **TTP Mappings**: {len(mappings)}")
    unique_techniques = {m.get("technique_id") for m in mappings if m.get("technique_id")}
    lines.append(f"- **Unique Techniques**: {len(unique_techniques)}")
    lines.append(f"- **Mitigations**: {len(mitigations)}")
    lines.append("")

    report = "\n".join(lines)
    (output_dir / OUTPUT_FILE).write_text(report)

    # Generate HTML dashboard and registry metadata
    _generate_html_dashboard(repo_path, run_dir=run_dir)

    return str(output_dir / OUTPUT_FILE)


def _steps_to_mermaid(steps: list, mappings_by_step: dict, root_goal: str) -> str:
    """Convert structured steps to a mermaid graph TD diagram."""
    lines = ["graph TD"]

    def _label(text):
        text = text.replace('"', "'").replace("\n", " ").strip()
        # Use \\n for mermaid line breaks inside node labels
        words = text.split()
        result = []
        line = ""
        for w in words:
            if len(line) + len(w) > 40:
                result.append(line)
                line = w
            else:
                line = f"{line} {w}" if line else w
        if line:
            result.append(line)
        return "\\n".join(result)

    # Map step IDs to simple mermaid-safe IDs (no hyphens)
    id_map = {}
    for i, step in enumerate(steps):
        sid = step.get("id", "")
        safe_id = f"S{i}"
        id_map[sid] = safe_id

    # Root goal node
    if root_goal:
        lines.append(f'    GOAL["GOAL: {_label(root_goal)}"]')

    # Identify root (fact) steps and leaf steps
    root_steps = [s for s in steps if not s.get("parent_id")]
    child_ids = {s.get("parent_id") for s in steps if s.get("parent_id")}
    leaf_steps = [s for s in steps if s.get("id") not in child_ids and s.get("parent_id")]

    for step in steps:
        sid = step.get("id", "")
        desc = step.get("description", sid)
        safe = id_map.get(sid, sid)

        label = _label(step.get("title") or desc)
        lines.append(f'    {safe}["{label}"]')

    # Edges: parent → child (top-down flow: fact at top, GOAL at bottom)
    for step in steps:
        pid = step.get("parent_id", "")
        sid = step.get("id", "")
        if pid:
            safe_from = id_map.get(pid, pid)
            safe_to = id_map.get(sid, sid)
            lines.append(f"    {safe_from} --> {safe_to}")

    # Connect leaf steps to GOAL at the bottom
    if root_goal:
        for step in leaf_steps:
            safe = id_map.get(step["id"], step["id"])
            lines.append(f'    {safe} --> GOAL')
        # If no leaf steps, connect root steps to GOAL as fallback
        if not leaf_steps:
            for step in root_steps:
                safe = id_map.get(step["id"], step["id"])
                lines.append(f'    {safe} --> GOAL')

    # Class definitions for node styling
    lines.append('    classDef goal fill:#ff6b6b,stroke:#c92a2a,color:#fff,stroke-width:2px')
    lines.append('    classDef attack fill:#ffd43b,stroke:#f08c00,stroke-width:2px')
    lines.append('    class GOAL goal')
    all_step_ids = [id_map.get(s.get("id", ""), "") for s in steps]
    if all_step_ids:
        lines.append(f'    class {",".join(all_step_ids)} attack')

    return "\n".join(lines)


def _build_attack_trees_for_ui(state_dir: Path, threats: list) -> list:
    """Build attack_trees array in the format the web UI expects."""
    import json as _json

    trees = []
    mappings_by_step = {}
    mitigations_by_step = {}

    try:
        tree_data = _json.loads((state_dir / "attack_trees.json").read_text()).get("attack_trees", [])
    except (FileNotFoundError, _json.JSONDecodeError):
        tree_data = []

    try:
        raw = (state_dir / "ttp_mappings.json").read_text().replace(",\n]", "\n]").replace(",]", "]")
        for m in _json.loads(raw).get("ttp_mappings", []):
            mappings_by_step[m.get("attack_step_id", "")] = m
    except (FileNotFoundError, _json.JSONDecodeError):
        pass

    try:
        raw = (state_dir / "mitigations.json").read_text().replace(",\n]", "\n]").replace(",]", "]")
        for m in _json.loads(raw).get("mitigations", []):
            sid = m.get("attack_step_id", "")
            mitigations_by_step[sid] = m
            for also in m.get("also_applies_to", []):
                mitigations_by_step[also] = m
    except (FileNotFoundError, _json.JSONDecodeError):
        pass

    # Map threat_id to threat data
    threat_map = {}
    for t in threats:
        tid = t.get("id", t.get("threat_id", ""))
        if tid:
            threat_map[tid] = t

    # Count trees per threat_id so we can disambiguate duplicates
    from collections import Counter
    tree_count_by_threat = Counter(t.get("threat_id", "") for t in tree_data)
    tree_index_by_threat: dict[str, int] = {}

    for tree in tree_data:
        threat_id = tree.get("threat_id", "")
        threat = threat_map.get(threat_id, {})
        steps = tree.get("steps", [])

        # Build TTC mappings with embedded mitigations for this tree
        ttc_mappings = []
        tree_mitigations = []
        attack_steps_ui = []

        # Build safe ID map (same as _steps_to_mermaid)
        id_map = {step.get("id", ""): f"S{i}" for i, step in enumerate(steps)}

        for step in steps:
            sid = step.get("id", "")
            safe_id = id_map.get(sid, sid)
            desc = step.get("description", "")
            mapping = mappings_by_step.get(sid, {})
            mit = mitigations_by_step.get(sid)

            # Build attack_step entry
            title = step.get("title", "")
            step_entry = {
                "node_id": safe_id,
                "label": title or desc,
                "description": desc,
                "category": step.get("category", ""),
            }
            if mit:
                tree_mitigations.append({
                    "name": mit.get("mitigation_text", ""),
                    "description": mit.get("implementation_guidance", ""),
                    "attack_step": safe_id,
                    "priority": mit.get("priority", 3),
                    "technique_id": mit.get("technique_id", ""),
                    "remediation_type": mit.get("remediation_type", ""),
                    "evidence": mit.get("evidence", []),
                })
            attack_steps_ui.append(step_entry)

            # Build TTC mapping entry
            if mapping.get("technique_id"):
                mapping_entry = {
                    "attack_step": desc,
                    "technique_id": mapping.get("technique_id", ""),
                    "technique_name": mapping.get("technique_name", ""),
                    "confidence": mapping.get("similarity_score", 0),
                    "similarity": mapping.get("similarity_score", 0),
                    "reasoning": f"Embedding similarity: {mapping.get('similarity_score', 0):.3f}" + (
                        f" (reviewer override: {mapping.get('reviewer_reasoning', '')})" if mapping.get("reviewer_overrode_top1") else ""
                    ),
                }
                ttc_mappings.append(mapping_entry)

        # Build a unique display threat_id when a threat has multiple trees
        if tree_count_by_threat[threat_id] > 1:
            idx = tree_index_by_threat.get(threat_id, 0) + 1
            tree_index_by_threat[threat_id] = idx
            display_threat_id = f"{threat_id} [AttackTree - {idx}]"
        else:
            display_threat_id = threat_id

        trees.append({
            "threat_id": display_threat_id,
            "threat_category": threat.get("category") or threat.get("title") or threat.get("name") or threat.get("description", "")[:80],
            "threat_description": threat.get("description", ""),
            "threat_statement": threat.get("description", ""),
            "threat_action": threat.get("title") or threat.get("name", ""),
            "threatSource": threat.get("threat_source", ""),
            "priority": threat.get("priority") or threat.get("severity", "medium"),
            "attack_steps": attack_steps_ui,
            "ttc_mappings": ttc_mappings,
            "mitigations": tree_mitigations,
            "mapping_count": len(ttc_mappings),
            "root_goal": tree.get("root_goal", ""),
            "mermaid_code": _steps_to_mermaid(steps, mappings_by_step, tree.get("root_goal", "")),
        })

    return trees


def _build_short_summary(
    project_name: str,
    scanner_ctx: dict,
    threat_count: int,
    high_sev: int,
) -> str:
    """Build a concise ≤150-word summary for the applications listing page.

    Captures the project name, cloud provider, key services, and threat
    statistics in a single readable sentence.
    """
    provider = (scanner_ctx.get("cloud_provider") or "").upper()
    services = scanner_ctx.get("services", [])
    tech_stack = scanner_ctx.get("tech_stack", "")

    parts: list[str] = []

    # Opening — project name + provider + stack
    opener = project_name
    if provider:
        opener += f" ({provider}"
        if tech_stack:
            opener += f", {tech_stack}"
        opener += ")"
    elif tech_stack:
        opener += f" ({tech_stack})"
    parts.append(opener)

    # Key services (max 5)
    if services:
        svc_str = ", ".join(services[:5])
        if len(services) > 5:
            svc_str += f" +{len(services) - 5} more"
        parts.append(f"using {svc_str}")

    # Threat stats
    if threat_count:
        threat_part = f"with {threat_count} identified threat{'s' if threat_count != 1 else ''}"
        if high_sev:
            threat_part += f" ({high_sev} high/critical)"
        parts.append(threat_part)

    summary = " ".join(parts) + "."

    # Safety truncation at word boundary if somehow exceeds ~150 words
    words = summary.split()
    if len(words) > 150:
        summary = " ".join(words[:150]) + "..."

    return summary


def _generate_html_dashboard(repo_path: str, run_dir: str | None = None) -> None:
    """Wrap the markdown report in an HTML dashboard and write registry metadata."""
    output_dir = _resolve_output_dir(repo_path, run_dir)
    state_dir = resolve_state_dir(repo_path, run_dir)
    md_file = output_dir / OUTPUT_FILE

    if not md_file.exists():
        return

    # --- Write registry metadata to .threatforest/output/ ---
    registry_dir = output_dir  # same as .threatforest/output/

    import json as _json

    # Read state files for metadata
    threat_count = 0
    high_sev = 0
    threats = []
    scanner_ctx = {}

    try:
        scanner_ctx = _json.loads((state_dir / "scanner_context.json").read_text())
    except (FileNotFoundError, _json.JSONDecodeError):
        pass

    try:
        threats = _json.loads((state_dir / "threats.json").read_text()).get("threats", [])
        threat_count = len(threats)
        high_sev = sum(1 for t in threats if t.get("priority", t.get("severity", "")).lower() in ("critical", "high"))
    except (FileNotFoundError, _json.JSONDecodeError):
        pass

    project_name = Path(repo_path).name
    short_summary = (
        scanner_ctx.get("description")
        or _build_short_summary(project_name, scanner_ctx, threat_count, high_sev)
    )

    metadata = {
        "metadata": {
            "generator": "ThreatForest",
            "version": "2.0",
        },
        "project_info": {
            "application_name": project_name,
            "technologies": scanner_ctx.get("services", []),
            "deployment_environment": scanner_ctx.get("cloud_provider", ""),
            "industry": scanner_ctx.get("industry", ""),
            "summary": f"{scanner_ctx.get('cloud_provider', '').upper()} application using {scanner_ctx.get('tech_stack', 'N/A')[:80]}. "
                       f"Services: {', '.join(scanner_ctx.get('services', [])[:5])}.",
            "short_summary": short_summary,
        },
        "status": "complete",
        "threat_count": threat_count,
        "high_severity_count": high_sev,
        "extraction_summary": {
            "total_threats": threat_count,
            "high_severity_count": high_sev,
        },
        "threats": threats,
        "attack_trees": _build_attack_trees_for_ui(state_dir, threats),
        "scanner_context": scanner_ctx,
    }
    # Count total mappings
    total_mappings = sum(len(t.get("ttc_mappings", [])) for t in metadata.get("attack_trees", []))

    metadata["mapping_summary"] = {
        "total_mappings": total_mappings,
    }

    (registry_dir / "threatforest_data.json").write_text(_json.dumps(metadata, indent=2))


