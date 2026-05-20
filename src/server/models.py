"""Pydantic data models for the ThreatForest API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


CiaObjective = Literal["confidentiality", "integrity", "availability"]

# Canonical default ordering when the user hasn't expressed a preference and
# we don't have a legacy ``main_cia_risk`` value to derive from.
CIA_DEFAULT_ORDER: list[CiaObjective] = [
    "confidentiality",
    "integrity",
    "availability",
]


class BusinessContext(BaseModel):
    """User-provided business context for an application.

    Captured when the application is created (or edited later) and seeded
    into ``scanner_context.json`` before the scanner agent runs so the
    whole pipeline treats these fields as authoritative user input.

    ``cia_priority`` is a length-3 ranking of the CIA objectives, most
    important first. The threat agent uses this to distribute generated
    threats roughly 50/30/20 across rank 1/2/3. The legacy
    ``main_cia_risk`` field is no longer accepted on input but is migrated
    transparently for any persisted records that still carry it.
    """

    description: str
    regulatory_frameworks: list[str]
    data_sensitivity: Literal[
        "public",
        "internal",
        "confidential",
        "highly_confidential",
        "pii",
        "phi",
        "regulated_financial",
        "unknown",
    ]
    cia_priority: list[CiaObjective] = Field(
        default_factory=lambda: list(CIA_DEFAULT_ORDER),
        description="CIA objectives ranked by user — index 0 = most important.",
    )

    @model_validator(mode="before")
    @classmethod
    def _migrate_main_cia_risk(cls, data: object) -> object:
        """Accept legacy ``main_cia_risk`` on input and turn it into a ranking.

        Any persisted record (or a UI client that hasn't been redeployed yet)
        may still send ``main_cia_risk`` as a single value. Promote it to the
        rank-1 position with the remaining objectives in their canonical
        order. ``"unknown"`` and missing values both fall back to the default
        ordering.
        """
        if not isinstance(data, dict):
            return data
        if data.get("cia_priority"):
            data.pop("main_cia_risk", None)
            return data

        legacy = data.pop("main_cia_risk", None)
        if legacy in {"confidentiality", "integrity", "availability"}:
            rest = [o for o in CIA_DEFAULT_ORDER if o != legacy]
            data["cia_priority"] = [legacy, *rest]
        else:
            data["cia_priority"] = list(CIA_DEFAULT_ORDER)
        return data

    @model_validator(mode="after")
    def _validate_priority(self) -> "BusinessContext":
        if len(self.cia_priority) != 3 or set(self.cia_priority) != set(CIA_DEFAULT_ORDER):
            raise ValueError(
                "cia_priority must contain confidentiality, integrity, and availability "
                "exactly once, in the user's preferred order."
            )
        return self


class Application(BaseModel):
    """A persistent application record owned by the user.

    Introduced in the v2 UX model where the application is a first-class
    container that owns a user-chosen name, a business context block, and
    a list of threat model runs over its lifetime. Separate from the
    on-disk folder name (``run_dir_name``) so the app can be renamed
    without moving any run artefacts.
    """

    id: str
    name: str
    slug: str
    project_path: str
    business_context: BusinessContext
    created_at: str
    updated_at: str
    run_dir_name: str


class ApplicationCreateRequest(BaseModel):
    """Payload for ``POST /api/applications``."""

    name: str
    project_path: str
    business_context: BusinessContext


class ApplicationUpdateRequest(BaseModel):
    """Payload for ``PATCH /api/applications/{app_id}``.

    Any subset of fields may be provided; at least one must be set. Note
    that ``project_path`` is only editable before the application has any
    threat-model runs — the server rejects attempts to change it afterwards
    so the version history keeps pointing at the same repo.
    """

    name: str | None = None
    business_context: BusinessContext | None = None
    project_path: str | None = None

    @model_validator(mode="after")
    def _require_one_field(self) -> "ApplicationUpdateRequest":
        if (
            self.name is None
            and self.business_context is None
            and self.project_path is None
        ):
            raise ValueError(
                "At least one of 'name', 'business_context', or 'project_path' must be provided"
            )
        return self


class ApplicationSummary(BaseModel):
    """Summary of a discovered ThreatForest application.

    ``imported`` is True when the on-disk folder originated from a
    ``.tfreport`` bundle dropped into ``.threatforest/imports/`` — those
    apps are read-only because the recipient doesn't have the source code.
    ``imported_from`` carries the source application's display name so the
    UI can show ``"Imported from <name>"`` in tooltips/badges.
    """

    id: str
    name: str
    description: str
    version_count: int
    last_run_date: str
    business_context: BusinessContext | None = None
    imported: bool = False
    imported_from: str | None = None


class VersionSummary(BaseModel):
    """Summary of a single threat model version.

    ``id`` is the on-disk folder name (``YYYYMMDD_HHMMSS``) and is used as
    the filesystem lookup key for fetching version data. ``display_name``
    is a user-friendly label (e.g. ``"Version 3"``) assigned by the registry
    based on chronological order within the application.

    ``run_id`` is populated only when the version corresponds to an
    in-progress run that ``RunManager`` is still tracking — the UI uses it
    to route the user to the live progress page instead of the (non-existent)
    dashboard for that version.
    """

    id: str
    run_date: str
    status: str
    threat_count: int
    high_severity_count: int = 0
    categories: list[str]
    display_name: str = ""
    run_id: str | None = None


class RunConfig(BaseModel):
    """Configuration for initiating a ThreatForest run."""

    project_path: str
    threat_source: Literal["auto", "file"] = "auto"
    threat_file_path: str | None = None
    frameworks: list[str] | None = None  # e.g. ["attack", "atlas"]; None = all

    # Server-side fields populated on resume — not set directly by UI clients.
    # resume_run_dir points to a prior run's directory so the executor can
    # reuse its state files instead of creating a fresh run directory.
    resume_run_dir: str | None = None
    # Graph nodes whose output files already exist on disk and can be skipped.
    skip_nodes: list[str] = []

    # Links the run to a persistent Application record. Required for new runs
    # started from the v2 UX; the route layer resolves it to ``project_path``
    # before ``RunManager`` sees the config. Left optional here because resume
    # flows reconstruct a config that doesn't carry an app_id.
    app_id: str | None = None

    @model_validator(mode="after")
    def _validate_threat_file(self) -> "RunConfig":
        if self.threat_source == "file" and not self.threat_file_path:
            raise ValueError("threat_file_path is required when threat_source is 'file'")
        return self


class RunResponse(BaseModel):
    """Response returned after initiating a run."""

    run_id: str


class ResumeResponse(BaseModel):
    """Response returned after resuming a paused or stopped run."""

    new_run_id: str


class InteractionResponse(BaseModel):
    """User response to an interviewer question."""

    text: str | None = None


class DirectoryEntry(BaseModel):
    """A single file or directory entry in a listing."""

    name: str
    entry_type: str  # "file" | "directory"
    size: int | None = None
    modified: str | None = None


class DirectoryListing(BaseModel):
    """Directory listing returned by the filesystem browse endpoint."""

    current_path: str
    parent_path: str | None
    entries: list[DirectoryEntry]


class ConfigResponse(BaseModel):
    """Current ThreatForest model/provider configuration."""

    model_provider: str
    model_id: str
    embeddings_model: str
    default_browse_path: str
    aws_profile: str | None = None


class RunState(BaseModel):
    """Tracks the state of an active or completed run."""

    run_id: str
    status: str  # "pending" | "running" | "pausing" | "paused" | "stopped" | "complete" | "failed"
    config: RunConfig
    started_at: str
    completed_at: str | None = None
    output_dir: str | None = None
    error: str | None = None
    # Set when the run is paused or stopped mid-pipeline.
    paused_at_stage: str | None = None
    paused_at: str | None = None


class ProvidersResponse(BaseModel):
    """List of available model providers."""

    providers: list[str]


class ConfigTestRequest(BaseModel):
    """Request to test a model provider configuration."""

    provider: str
    model_id: str
    aws_profile: str | None = None
    aws_region: str | None = None
    api_key: str | None = None


class ConfigTestResponse(BaseModel):
    """Result of a configuration test."""

    success: bool
    message: str


class ConfigSaveRequest(BaseModel):
    """Request to save model provider configuration."""

    provider: str
    model_id: str
    aws_profile: str | None = None


class LangfuseConfigResponse(BaseModel):
    """Current Langfuse tracing configuration."""

    enabled: bool = False
    public_key: str | None = None
    secret_key_configured: bool = False
    host: str = "https://cloud.langfuse.com"


class LangfuseConfigSaveRequest(BaseModel):
    """Request to save Langfuse tracing configuration."""

    enabled: bool
    public_key: str | None = None
    secret_key: str | None = None
    host: str = "https://cloud.langfuse.com"


# ---------------------------------------------------------------------------
# Mitigation overrides (M3 v1)
#
# A user-editable disposition layer that sits *over* the immutable pipeline
# output in ``threatforest_data.json``. Each override applies to a single
# mitigation (keyed by its ``mitigation_text``) within a single run. The
# overrides file lives at ``<run_dir>/mitigation_overrides.json`` and is
# merged into the data response by the /data route.
#
# Storage shape carries a ``version`` marker so we can introduce per-threat
# scoping later without breaking the v1 file layout.
# ---------------------------------------------------------------------------

MitigationStatus = Literal[
    "not_relevant",
    "already_implemented",
    "in_progress",
    "wont_do",
    "accepted_risk",
]


class MitigationOverride(BaseModel):
    """A user disposition recorded against a single mitigation."""

    status: MitigationStatus
    # Required. The rationale survives across runs once carry-forward lands;
    # asking for it on every status set keeps that future feature useful.
    comment: str
    updated_at: str  # ISO 8601, set server-side

    @model_validator(mode="after")
    def _validate_comment(self) -> "MitigationOverride":
        if not self.comment or not self.comment.strip():
            raise ValueError("comment is required when setting a mitigation status")
        return self


class MitigationOverrideRequest(BaseModel):
    """Inbound payload from the UI when setting an override."""

    status: MitigationStatus
    comment: str

    @model_validator(mode="after")
    def _validate_comment(self) -> "MitigationOverrideRequest":
        if not self.comment or not self.comment.strip():
            raise ValueError("comment is required when setting a mitigation status")
        return self
