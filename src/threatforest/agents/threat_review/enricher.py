"""Helpers for the threat-review HITL node.

- `apply_threat_edits`: deterministically mutate threats.json based on structured
  user edits (priority changes, removals).
- `append_threat_review_to_summary`: merge a threat-review summary into
  `scanner_context.json:interviewer_summary`, structuring the field with
  `## Context validation` and `## Threat statement review` subheadings so the
  application overview can render them separately.
- `build_review_summary`: produce a short natural-language recap of the edits
  and feedback that happened during the review loop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ALLOWED_PRIORITIES = {"critical", "high", "medium", "low"}


def apply_threat_edits(state_file: str, edits: dict[str, dict[str, Any]]) -> None:
    """Apply structured edits to threats.json.

    Parameters
    ----------
    state_file:
        Path to threats.json.
    edits:
        Dict keyed by threat id. Per-threat value may contain:
          - "priority": one of critical|high|medium|low
          - "remove": truthy to drop the threat
    """
    path = Path(state_file)
    data = json.loads(path.read_text())
    threats = data.get("threats", [])

    remove_ids = {tid for tid, e in edits.items() if e.get("remove")}
    kept: list[dict] = []
    for t in threats:
        tid = t.get("id")
        if tid in remove_ids:
            continue
        patch = edits.get(tid, {})
        new_prio = patch.get("priority")
        if new_prio and str(new_prio).lower() in ALLOWED_PRIORITIES:
            t["priority"] = str(new_prio).lower()
        kept.append(t)

    data["threats"] = kept
    path.write_text(json.dumps(data, indent=2))


def build_review_summary(
    rounds: int,
    applied_edits: list[dict[str, Any]],
    feedbacks: list[str],
    added_threat_ids: list[str],
    removed_threat_ids: list[str],
    priority_changes: list[dict[str, str]],
    skipped: bool,
) -> str:
    """Build a short natural-language recap of what happened in the review loop.

    `skipped=True` means the user proceeded without any edits or feedback. We
    still return a summary line so the "Threat statement review" subheading
    always appears in the overview.
    """
    if skipped:
        return "User reviewed threats, no changes requested."

    lines: list[str] = []
    lines.append(
        f"User reviewed threats across {rounds} round{'s' if rounds != 1 else ''}."
    )

    for change in priority_changes:
        lines.append(
            f"- Changed priority of {change['id']} "
            f"from {change['from']} to {change['to']}."
        )

    for tid in removed_threat_ids:
        lines.append(f"- Removed {tid} (flagged as false positive or irrelevant).")

    if added_threat_ids:
        joined = ", ".join(added_threat_ids)
        lines.append(
            f"- Added {len(added_threat_ids)} threat"
            f"{'s' if len(added_threat_ids) != 1 else ''} based on feedback: {joined}."
        )

    nonempty_feedback = [f.strip() for f in feedbacks if f and f.strip()]
    if nonempty_feedback:
        joined_feedback = " | ".join(nonempty_feedback)
        lines.append(f"Free-text feedback: \"{joined_feedback}\"")

    return "\n".join(lines)


def append_threat_review_to_summary(state_file: str, threat_review_summary: str) -> None:
    """Merge the threat-review summary into `interviewer_summary`.

    If the existing summary doesn't already use markdown section headings, it is
    wrapped under `## Context validation` before the new `## Threat statement
    review` section is appended. The application overview renders these sections
    as separate subheadings.
    """
    path = Path(state_file)
    ctx = json.loads(path.read_text()) if path.exists() else {}
    existing = (ctx.get("interviewer_summary") or "").strip()

    if existing and not existing.lstrip().startswith("## "):
        existing = f"## Context validation\n{existing}"
    elif not existing:
        # No prior interview summary (interview was skipped entirely) — still
        # include an explicit Context validation section for symmetry.
        existing = "## Context validation\nContext validation was skipped."

    combined = (
        existing
        + "\n\n"
        + "## Threat statement review\n"
        + threat_review_summary.strip()
    )
    ctx["interviewer_summary"] = combined
    path.write_text(json.dumps(ctx, indent=2))


def diff_threats(before: list[dict], after: list[dict]) -> dict[str, Any]:
    """Compute a diff between two threat lists for summary purposes."""
    before_by_id = {t.get("id"): t for t in before}
    after_by_id = {t.get("id"): t for t in after}

    added = [tid for tid in after_by_id if tid not in before_by_id]
    removed = [tid for tid in before_by_id if tid not in after_by_id]

    priority_changes: list[dict[str, str]] = []
    for tid, t_after in after_by_id.items():
        t_before = before_by_id.get(tid)
        if not t_before:
            continue
        p_before = str(t_before.get("priority", "")).lower()
        p_after = str(t_after.get("priority", "")).lower()
        if p_before and p_after and p_before != p_after:
            priority_changes.append({"id": tid, "from": p_before, "to": p_after})

    return {
        "added": added,
        "removed": removed,
        "priority_changes": priority_changes,
    }
