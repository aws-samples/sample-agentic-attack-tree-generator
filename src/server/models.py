"""Pydantic data models for the ThreatForest API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, model_validator


class BusinessContext(BaseModel):
    """User-provided business context for an application.

    Captured when the application is created (or edited later) and seeded
    into ``scanner_context.json`` before the scanner agent runs so the
    whole pipeline treats these fields as authoritative user input.

    All fields are required — "unknown" sentinel values are available on
    the literal-typed fields so the create-application form still feels
    light while guaranteeing the agent has something to reason with.
    """

    description: str
    regulatory_frameworks: list[str]
    data_sensitivity: Literal[
        "public",
        "internal",
        "confidential",
        "pii",
        "phi",
        "regulated_financial",
        "unknown",
    ]
    main_cia_risk: Literal[
        "confidentiality",
        "integrity",
        "availability",
        "unknown",
    ]


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
    """Summary of a discovered ThreatForest application."""

    id: str
    name: str
    description: str
    version_count: int
    last_run_date: str
    business_context: BusinessContext | None = None


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
