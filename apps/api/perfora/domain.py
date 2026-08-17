from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

CURRENT_AUDIT_RECORD_VERSION = 4


def utc_now() -> datetime:
    return datetime.now(UTC)


class ProviderId(StrEnum):
    OPENCODE = "opencode"
    OLLAMA = "ollama"
    OPENAI = "openai"


class AuditType(StrEnum):
    PERFORMANCE = "performance"
    SECURITY = "security"


class TriageStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    VERIFIED_RESOLVED = "verified_resolved"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    REOPENED = "reopened"


class ComparisonStatus(StrEnum):
    NEW = "new"
    UNCHANGED = "unchanged"
    REGRESSED = "regressed"
    SEVERITY_CHANGED = "severity_changed"


class VerificationOutcome(StrEnum):
    VERIFIED_RESOLVED = "verified_resolved"
    STILL_PRESENT = "still_present"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


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
    audit_type: AuditType = AuditType.PERFORMANCE
    remote_source_consent: bool = False


class RulePackMetadata(BaseModel):
    id: str = "legacy"
    version: str = "unknown"


class ScanCoverage(BaseModel):
    files_discovered: int = Field(default=0, ge=0)
    files_scanned: int = Field(default=0, ge=0)
    files_skipped: int = Field(default=0, ge=0)
    scanned_by_type: dict[str, int] = Field(default_factory=dict)
    skipped_by_reason: dict[str, int] = Field(default_factory=dict)
    rules_executed: list[str] = Field(default_factory=list)
    scanned_files: list[str] | None = None
    skipped_files_by_reason: dict[str, list[str]] | None = None

    @model_validator(mode="after")
    def validate_totals(self) -> ScanCoverage:
        if self.files_skipped != sum(self.skipped_by_reason.values()):
            raise ValueError("files_skipped must equal skipped_by_reason totals")
        if self.files_discovered != self.files_scanned + self.files_skipped:
            raise ValueError("files_discovered must equal scanned and skipped files")
        if self.scanned_files is not None and len(self.scanned_files) != self.files_scanned:
            raise ValueError("scanned_files must contain every scanned file")
        if self.skipped_files_by_reason is not None:
            skipped_manifest_total = sum(
                len(paths) for paths in self.skipped_files_by_reason.values()
            )
            if skipped_manifest_total != self.files_skipped:
                raise ValueError("skipped_files_by_reason must contain every skipped file")
        return self


class ModelEnrichment(BaseModel):
    provider: ProviderId | None = None
    model_id: str | None = None
    explanation: str
    recommendation: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)


class VerificationAttempt(BaseModel):
    id: str
    outcome: VerificationOutcome
    message: str
    started_at: datetime
    completed_at: datetime
    repository: RepositorySnapshot
    analyzer_version: str = "unknown"
    rule_pack: RulePackMetadata = Field(default_factory=RulePackMetadata)
    scan_coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    rule_executed: bool = False
    source_present: bool = False
    file_scanned: bool = False
    observed_file: str | None = None
    observed_line: int | None = Field(default=None, ge=1)
    observed_evidence: list[str] = Field(default_factory=list)


class FindingNote(BaseModel):
    id: str
    body: str
    created_at: datetime = Field(default_factory=utc_now)


class FindingStatusChange(BaseModel):
    from_status: TriageStatus
    to_status: TriageStatus
    reason: str | None = None
    changed_at: datetime = Field(default_factory=utc_now)


class Finding(BaseModel):
    id: str
    audit_id: str
    fingerprint: str = ""
    rule_id: str
    rule_version: str = "legacy"
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
    model_enrichment: ModelEnrichment | None = None
    triage_status: TriageStatus = TriageStatus.NEW
    comparison_status: ComparisonStatus | None = None
    owner: str | None = None
    due_at: datetime | None = None
    resolution_commit: str | None = None
    disposition_reason: str | None = None
    suppression_expires_at: datetime | None = None
    ticket_url: str | None = None
    notes: list[FindingNote] = Field(default_factory=list)
    status_history: list[FindingStatusChange] = Field(default_factory=list)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    verification_attempts: list[VerificationAttempt] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_model_explanation(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("model_enrichment"):
            return value
        explanation = value.get("model_explanation")
        if not explanation:
            return value
        migrated = dict(value)
        migrated["model_enrichment"] = {
            "explanation": explanation,
            "recommendation": None,
        }
        return migrated


class AuditEvent(BaseModel):
    sequence: int
    type: str
    message: str
    progress: int = Field(ge=0, le=100)
    created_at: datetime = Field(default_factory=utc_now)
    data: dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    id: str
    record_version: int = CURRENT_AUDIT_RECORD_VERSION
    repository: RepositorySnapshot
    provider: ProviderId
    model_id: str
    audit_type: AuditType = AuditType.PERFORMANCE
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    status: Literal["queued", "running", "partial", "completed", "failed", "cancelled"]
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    findings: list[Finding] = Field(default_factory=list)
    events: list[AuditEvent] = Field(default_factory=list)
    error: str | None = None
    context_manifest: list[str] = Field(default_factory=list)
    analyzer_version: str = "unknown"
    rule_pack: RulePackMetadata = Field(default_factory=RulePackMetadata)
    scan_coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    baseline_audit_id: str | None = None


class AnalyzerResult(BaseModel):
    analyzer_version: str = "unknown"
    rule_pack: RulePackMetadata = Field(default_factory=RulePackMetadata)
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    findings: list[dict[str, Any]] = Field(default_factory=list)


class AgentPrompt(BaseModel):
    finding_id: str
    audit_id: str
    prompt: str
    redacted: bool = True
    generated_at: datetime = Field(default_factory=utc_now)


class FindingUpdate(BaseModel):
    triage_status: TriageStatus | None = None
    owner: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    resolution_commit: str | None = Field(default=None, max_length=200)
    disposition_reason: str | None = Field(default=None, max_length=4000)
    suppression_expires_at: datetime | None = None
    ticket_url: str | None = Field(default=None, max_length=1000)
    note: str | None = Field(default=None, max_length=4000)


class SeverityChange(BaseModel):
    fingerprint: str
    finding_id: str
    baseline_finding_id: str
    from_severity: Literal["low", "medium", "high", "critical"]
    to_severity: Literal["low", "medium", "high", "critical"]


class AuditComparison(BaseModel):
    current_audit_id: str
    baseline_audit_id: str | None = None
    new_finding_ids: list[str] = Field(default_factory=list)
    unchanged_finding_ids: list[str] = Field(default_factory=list)
    regressed_finding_ids: list[str] = Field(default_factory=list)
    severity_changes: list[SeverityChange] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
