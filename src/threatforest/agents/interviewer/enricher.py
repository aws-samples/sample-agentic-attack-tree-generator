"""Merge user-provided context into scanner_context.json."""

import json
from pathlib import Path


def enrich_scanner_context(
    state_file: str,
    additional_context: dict,
    confidence: str,
    summary: str,
) -> None:
    """Enrich scanner_context.json with interview results.

    Parameters
    ----------
    state_file:
        Path to scanner_context.json.
    additional_context:
        Dict of user-provided context to merge. Keys may include
        auth_mechanisms, services, compliance, data_sensitivity, etc.
    confidence:
        One of "high", "medium", "low".
    summary:
        Brief summary of what was learned in the interview.
    """
    path = Path(state_file)
    ctx = json.loads(path.read_text())

    # Store raw interview results
    ctx["user_context"] = additional_context
    ctx["interviewer_confidence"] = confidence
    ctx["interviewer_summary"] = summary

    # Merge list fields: append unique items
    list_fields = ["auth_mechanisms", "services", "compliance_requirements"]
    for field in list_fields:
        if field in additional_context:
            existing = set(ctx.get(field, []))
            for item in additional_context[field]:
                if item not in existing:
                    ctx.setdefault(field, []).append(item)

    # Merge scalar fields only if not already set
    scalar_fields = ["data_sensitivity", "deployment_model", "industry"]
    for field in scalar_fields:
        if field in additional_context and not ctx.get(field):
            ctx[field] = additional_context[field]

    path.write_text(json.dumps(ctx, indent=2))


def apply_scanner_review_edits(state_file: str, edits: dict) -> None:
    """Apply user edits from the scanner review to scanner_context.json.

    Parameters
    ----------
    state_file:
        Path to scanner_context.json.
    edits:
        Dict of user edits. Keys match scanner_context fields.
        List fields are replaced entirely; scalar fields are overwritten.
    """
    path = Path(state_file)
    ctx = json.loads(path.read_text())

    # Fields the user can edit via scanner review
    editable_fields = [
        "files_analyzed", "industry", "services", "auth_mechanisms",
        "cloud_provider", "tech_stack", "data_sensitivity", "compliance_requirements",
    ]

    for field in editable_fields:
        if field in edits:
            ctx[field] = edits[field]

    ctx["scanner_review_applied"] = True
    path.write_text(json.dumps(ctx, indent=2))
