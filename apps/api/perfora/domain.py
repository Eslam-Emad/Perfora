from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

CURRENT_AUDIT_RECORD_VERSION = 6


def utc_now() -> datetime:
    return datetime.now(UTC)


class ProviderId(StrEnum):
    OPENCODE = "opencode"
    OLLAMA = "ollama"
    OPENAI = "openai"


class AuditType(StrEnum):
    PERFORMANCE = "performance"
    SECURITY = "security"


class RuntimeArtifactKind(StrEnum):
    AUTO = "auto"
    TIMELINE = "timeline"
    CPU_PROFILE = "cpu_profile"
    MEMORY_SNAPSHOT = "memory_snapshot"
    HEAP_COMPARISON = "heap_comparison"
    APP_SIZE = "app_size"
    FRAME_TIMING = "frame_timing"
    NETWORK_TRACE = "network_trace"


class RuntimeBuildMode(StrEnum):
    PROFILE = "profile"
    RELEASE = "release"
    DEBUG = "debug"
    UNKNOWN = "unknown"


class RuntimeReliability(StrEnum):
    TRUSTED = "trusted"
    UNRELIABLE = "unreliable"
    UNVERIFIED = "unverified"


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


class OpenAISettingsStatus(BaseModel):
    configured: bool
    source: Literal["settings", "environment", "none"]


class OllamaSettingsStatus(BaseModel):
    base_url: str
    source: Literal["settings", "environment", "default"]
    locality: Literal["local", "remote"]


class ProviderSettingsSnapshot(BaseModel):
    openai: OpenAISettingsStatus
    ollama: OllamaSettingsStatus


class ProviderSettingsUpdate(BaseModel):
    openai_api_key: SecretStr | None = Field(default=None, min_length=20, max_length=4096)
    clear_openai_api_key: bool = False
    ollama_base_url: str | None = Field(default=None, min_length=8, max_length=2048)

    @field_validator("openai_api_key")
    @classmethod
    def validate_openai_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return value
        secret = value.get_secret_value()
        if secret != secret.strip() or any(character.isspace() for character in secret):
            raise ValueError("OpenAI API key cannot contain whitespace")
        return value

    @model_validator(mode="after")
    def validate_update(self) -> ProviderSettingsUpdate:
        if not self.model_fields_set:
            raise ValueError("At least one provider setting must be supplied")
        if "openai_api_key" in self.model_fields_set and self.openai_api_key is None:
            raise ValueError("openai_api_key cannot be null")
        if self.openai_api_key is not None and self.clear_openai_api_key:
            raise ValueError("Cannot set and clear the OpenAI API key together")
        if "ollama_base_url" in self.model_fields_set and self.ollama_base_url is None:
            raise ValueError("ollama_base_url cannot be null")
        return self


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
    coverage_by_platform: dict[str, int] = Field(default_factory=dict)
    rules_by_control_group: dict[str, list[str]] = Field(default_factory=dict)

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


class SecurityStandardReference(BaseModel):
    id: str
    title: str
    url: str


class DependencyComponent(BaseModel):
    bom_ref: str
    name: str
    version: str = "unknown"
    ecosystem: str
    source_file: str
    scope: Literal["required", "optional", "excluded", "unknown"] = "unknown"
    direct: bool | None = None
    purl: str | None = None
    license: str | None = None
    privacy_category: str | None = None
    privacy_sensitive: bool = False


class DependencyInventory(BaseModel):
    components: list[DependencyComponent] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    coverage_by_ecosystem: dict[str, int] = Field(default_factory=dict)
    license_counts: dict[str, int] = Field(default_factory=dict)
    privacy_sdk_counts: dict[str, int] = Field(default_factory=dict)
    vulnerability_matching: Literal["not_requested", "disabled", "completed"] = "not_requested"


class DependencyVersionChange(BaseModel):
    ecosystem: str
    name: str
    from_version: str
    to_version: str


class DependencyChangeReport(BaseModel):
    added: list[DependencyComponent] = Field(default_factory=list)
    removed: list[DependencyComponent] = Field(default_factory=list)
    updated: list[DependencyVersionChange] = Field(default_factory=list)


class RuntimeImportRequest(BaseModel):
    repository_path: str
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=2, max_length=25_000_000)
    kind: RuntimeArtifactKind = RuntimeArtifactKind.AUTO
    build_mode: RuntimeBuildMode = RuntimeBuildMode.UNKNOWN
    flutter_version: str | None = Field(default=None, max_length=100)
    devtools_version: str | None = Field(default=None, max_length=100)
    dart_version: str | None = Field(default=None, max_length=100)
    label: str | None = Field(default=None, max_length=200)


class RuntimeArtifactProvenance(BaseModel):
    filename: str
    sha256: str
    artifact_format: str
    build_mode: RuntimeBuildMode
    build_mode_source: Literal["artifact", "declared", "unknown"] = "unknown"
    flutter_version: str | None = None
    devtools_version: str | None = None
    dart_version: str | None = None
    captured_at: datetime | None = None
    imported_at: datetime = Field(default_factory=utc_now)


class RuntimeEvidence(BaseModel):
    id: str
    kind: str
    name: str
    trace_reference: str
    timestamp_us: float | None = None
    duration_us: float | None = None
    value: float | int | None = None
    unit: str | None = None
    thread: str | None = None
    source_file: str | None = None
    source_line: int | None = Field(default=None, ge=1)
    details: dict[str, str | float | int | bool | None] = Field(default_factory=dict)


class RuntimeFinding(BaseModel):
    id: str
    rule_id: str
    rule_version: str = "1.0.0"
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    explanation: str
    recommendation: str
    evidence_ids: list[str] = Field(min_length=1)
    source_file: str | None = None
    source_line: int | None = Field(default=None, ge=1)
    observed: Literal[True] = True


class RuntimeBreakdownItem(BaseModel):
    name: str
    value: float | int
    unit: str
    trace_reference: str | None = None


class RuntimeCapture(BaseModel):
    id: str
    record_version: int = 1
    repository: RepositorySnapshot
    label: str
    kind: RuntimeArtifactKind
    reliability: RuntimeReliability
    provenance: RuntimeArtifactProvenance
    metrics: dict[str, float | int] = Field(default_factory=dict)
    metric_units: dict[str, str] = Field(default_factory=dict)
    breakdowns: dict[str, list[RuntimeBreakdownItem]] = Field(default_factory=dict)
    evidence: list[RuntimeEvidence] = Field(default_factory=list)
    findings: list[RuntimeFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class RuntimeMetricDelta(BaseModel):
    metric: str
    unit: str
    baseline: float
    current: float
    delta: float
    percent_change: float | None = None
    direction: Literal["improved", "regressed", "unchanged", "informational"]


class RuntimeCaptureComparison(BaseModel):
    baseline_capture_id: str
    current_capture_id: str
    compatible: bool
    warnings: list[str] = Field(default_factory=list)
    metric_deltas: list[RuntimeMetricDelta] = Field(default_factory=list)
    new_finding_rule_ids: list[str] = Field(default_factory=list)
    resolved_finding_rule_ids: list[str] = Field(default_factory=list)


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
    control_group: str | None = None
    platforms: list[str] = Field(default_factory=list)
    standards: list[SecurityStandardReference] = Field(default_factory=list)
    detection_limitations: list[str] = Field(default_factory=list)
    manual_verification: list[str] = Field(default_factory=list)
    false_positive_guidance: str | None = None
    model_enrichment: ModelEnrichment | None = None
    triage_status: TriageStatus = TriageStatus.NEW
    comparison_status: ComparisonStatus | None = None
    owner: str | None = None
    due_at: datetime | None = None
    resolution_commit: str | None = None
    disposition_reason: str | None = None
    suppression_expires_at: datetime | None = None
    suppression_policy_managed: bool = False
    suppression_approved_by: str | None = None
    suppression_approved_at: date | None = None
    suppression_ticket_url: str | None = None
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
    dependency_inventory: DependencyInventory = Field(default_factory=DependencyInventory)
    organization: str | None = None
    policy_sources: list[str] = Field(default_factory=list)


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
    dependency_changes: DependencyChangeReport = Field(default_factory=DependencyChangeReport)
