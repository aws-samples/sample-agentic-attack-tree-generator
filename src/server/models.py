"""Pydantic data models for the ThreatForest API."""

from __future__ import annotations

from pydantic import BaseModel


class ApplicationSummary(BaseModel):
    """Summary of a discovered ThreatForest application."""

    id: str
    name: str
    description: str
    version_count: int
    last_run_date: str


class VersionSummary(BaseModel):
    """Summary of a single threat model version."""

    id: str
    run_date: str
    status: str
    threat_count: int
    high_severity_count: int = 0
    categories: list[str]


class RunConfig(BaseModel):
    """Configuration for initiating a ThreatForest run."""

    project_path: str
    threat_source: str  # "auto" | "file"
    threat_file_path: str | None = None
    frameworks: list[str] | None = None  # e.g. ["attack", "atlas"]; None = all


class RunResponse(BaseModel):
    """Response returned after initiating a run."""

    run_id: str


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
    status: str  # "pending" | "running" | "complete" | "failed"
    config: RunConfig
    started_at: str
    completed_at: str | None = None
    output_dir: str | None = None
    error: str | None = None


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
