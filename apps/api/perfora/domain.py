from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


class ProviderId(StrEnum):
    OPENCODE = "opencode"
    OLLAMA = "ollama"
    OPENAI = "openai"


class ToolStatus(BaseModel):
    id: str
    label: str
    available: bool
    version: str | None = None
    detail: str


class ModelInfo(BaseModel):
    provider: ProviderId
    id: str
    label: str
    available: bool = True
    compatible: bool = True
    capability_status: Literal["compatible", "unsupported", "unknown"] = "unknown"
    locality: Literal["local", "remote", "unknown"]
    context_window: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProviderCatalog(BaseModel):
    provider: ProviderId
    available: bool
    detail: str
    models: list[ModelInfo] = Field(default_factory=list)


class RepositoryRequest(BaseModel):
    path: str


class RepositorySnapshot(BaseModel):
    path: str
    name: str
    valid: bool
    detail: str
    is_flutter: bool = False
    is_git: bool = False
    branch: str | None = None
    commit_sha: str | None = None
    clean: bool | None = None
    fingerprint: str | None = None
    packages: list[str] = Field(default_factory=list)

    @property
    def resolved_path(self) -> Path:
        return Path(self.path)


class AuditCreate(BaseModel):
    repository_path: str
    provider: ProviderId
    model_id: str
    remote_source_consent: bool = False


class Finding(BaseModel):
    id: str
    audit_id: str
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    status: Literal["confirmed", "hypothesis"] = "confirmed"
    file: str
    line: int = Field(ge=1)
    symbol: str | None = None
    framework: str
    evidence: list[str]
    explanation: str
    recommendation: str
    model_explanation: str | None = None
    fix_status: Literal[
        "not_requested", "generated", "applied", "verified", "failed", "rolled_back"
    ] = "not_requested"


class AuditEvent(BaseModel):
    sequence: int
    type: str
    message: str
    progress: int = Field(ge=0, le=100)
    created_at: datetime = Field(default_factory=utc_now)
    data: dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    id: str
    repository: RepositorySnapshot
    provider: ProviderId
    model_id: str
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    status: Literal["queued", "running", "partial", "completed", "failed", "cancelled"]
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    findings: list[Finding] = Field(default_factory=list)
    events: list[AuditEvent] = Field(default_factory=list)
    error: str | None = None
    context_manifest: list[str] = Field(default_factory=list)


class FixProposal(BaseModel):
    finding_id: str
    audit_id: str
    summary: str
    risk: str
    patch: str
    expected_head: str
    generated_at: datetime = Field(default_factory=utc_now)


class FixApplyRequest(BaseModel):
    approved: bool
    expected_head: str
    patch: str
    verification_commands: list[str] = Field(default_factory=lambda: ["flutter analyze"])


class FixApplyResult(BaseModel):
    finding_id: str
    branch: str
    applied: bool
    verified: bool
    verification: list[dict[str, Any]]
    reverse_patch_available: bool
