from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from .analyzer_client import AnalyzerUnavailable, DartAnalyzerClient
from .audits import AuditCoordinator
from .database import AuditStore
from .domain import (
    CURRENT_AUDIT_RECORD_VERSION,
    AnalyzerResult,
    Finding,
    FindingStatusChange,
    RepositorySnapshot,
    ScanCoverage,
    TriageStatus,
    VerificationAttempt,
    VerificationOutcome,
)
from .repositories import inspect_repository


class VerificationError(ValueError):
    pass


RepositoryInspector = Callable[[str], Awaitable[RepositorySnapshot]]


class VerificationService:
    def __init__(
        self,
        store: AuditStore,
        analyzer: DartAnalyzerClient,
        repository_inspector: RepositoryInspector = inspect_repository,
    ):
        self.store = store
        self.analyzer = analyzer
        self.repository_inspector = repository_inspector
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def verify(self, audit_id: str, finding_id: str) -> VerificationAttempt:
        audit = self.store.get(audit_id)
        if audit is None:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if finding is None:
            raise KeyError(finding_id)
        self._validate_request(finding)

        key = (audit_id, finding_id)
        lock = self._locks.setdefault(key, asyncio.Lock())
        if lock.locked():
            raise VerificationError("Verification is already running for this finding")
        async with lock:
            started_at = datetime.now(UTC)
            repository = await self.repository_inspector(audit.repository.path)
            if not repository.valid:
                return self._record(
                    audit_id,
                    finding_id,
                    VerificationAttempt(
                        id=uuid.uuid4().hex,
                        outcome=VerificationOutcome.ERROR,
                        message=f"Repository verification failed: {repository.detail}",
                        started_at=started_at,
                        completed_at=datetime.now(UTC),
                        repository=repository,
                    ),
                )
            try:
                analysis = await self.analyzer.analyze(
                    Path(repository.path), audit.audit_type
                )
            except AnalyzerUnavailable as error:
                return self._record(
                    audit_id,
                    finding_id,
                    VerificationAttempt(
                        id=uuid.uuid4().hex,
                        outcome=VerificationOutcome.ERROR,
                        message=f"Deterministic analyzer failed: {error}",
                        started_at=started_at,
                        completed_at=datetime.now(UTC),
                        repository=repository,
                    ),
                )
            except Exception as error:  # noqa: BLE001
                return self._record(
                    audit_id,
                    finding_id,
                    VerificationAttempt(
                        id=uuid.uuid4().hex,
                        outcome=VerificationOutcome.ERROR,
                        message=(
                            "Deterministic verification failed at the analyzer boundary: "
                            f"{type(error).__name__}"
                        ),
                        started_at=started_at,
                        completed_at=datetime.now(UTC),
                        repository=repository,
                    ),
                )

            attempt = self._evaluate(finding, repository, analysis, started_at)
            return self._record(audit_id, finding_id, attempt)

    @staticmethod
    def _validate_request(finding: Finding) -> None:
        if not finding.fingerprint:
            raise VerificationError(
                "Legacy findings without a stable fingerprint require a new audit before verification"
            )
        if finding.triage_status not in {
            TriageStatus.RESOLVED,
            TriageStatus.VERIFIED_RESOLVED,
        }:
            raise VerificationError(
                "Mark the finding resolved before running deterministic verification"
            )

    def _evaluate(
        self,
        finding: Finding,
        repository: RepositorySnapshot,
        analysis: AnalyzerResult,
        started_at: datetime,
    ) -> VerificationAttempt:
        now = datetime.now(UTC)
        rule_executed = finding.rule_id in analysis.coverage.rules_executed
        source_path = self._source_path(repository, finding.file)
        source_present = source_path.is_file()
        normalized_file = self._normalize(finding.file)
        scanned_files = (
            {self._normalize(path) for path in analysis.coverage.scanned_files}
            if analysis.coverage.scanned_files is not None
            else None
        )
        file_scanned = scanned_files is not None and normalized_file in scanned_files

        common = {
            "id": uuid.uuid4().hex,
            "started_at": started_at,
            "completed_at": now,
            "repository": repository,
            "analyzer_version": analysis.analyzer_version,
            "rule_pack": analysis.rule_pack,
            "scan_coverage": analysis.coverage,
            "rule_executed": rule_executed,
            "source_present": source_present,
            "file_scanned": file_scanned,
        }
        if not rule_executed:
            return VerificationAttempt(
                **common,
                outcome=VerificationOutcome.INCONCLUSIVE,
                message=f"Rule {finding.rule_id} did not execute during verification",
            )
        if source_present and scanned_files is None:
            return VerificationAttempt(
                **common,
                outcome=VerificationOutcome.INCONCLUSIVE,
                message="Analyzer did not return a per-file coverage manifest",
            )
        if source_present and not file_scanned:
            skipped_reason = self._skip_reason(analysis.coverage, normalized_file)
            detail = f" ({skipped_reason})" if skipped_reason else ""
            return VerificationAttempt(
                **common,
                outcome=VerificationOutcome.INCONCLUSIVE,
                message=f"Finding source was not scanned{detail}",
            )

        observed = self._matching_finding(finding, analysis)
        if observed is not None:
            return VerificationAttempt(
                **common,
                outcome=VerificationOutcome.STILL_PRESENT,
                message="The deterministic finding is still present in the current repository",
                observed_file=str(observed.get("file") or finding.file),
                observed_line=int(observed.get("line") or finding.line),
                observed_evidence=[str(item) for item in observed.get("evidence", [])],
            )
        message = (
            "The original source file was removed and the rule no longer reports the finding"
            if not source_present
            else "The rule scanned the source and no longer reports the finding"
        )
        return VerificationAttempt(
            **common,
            outcome=VerificationOutcome.VERIFIED_RESOLVED,
            message=message,
        )

    def _matching_finding(
        self, original: Finding, analysis: AnalyzerResult
    ) -> dict | None:
        occurrences: dict[str, int] = {}
        semantic_match: dict | None = None
        for raw in analysis.findings:
            basis = AuditCoordinator._fingerprint_basis(raw)
            occurrence = occurrences.get(basis, 0)
            occurrences[basis] = occurrence + 1
            fingerprint = AuditCoordinator._fingerprint(basis, occurrence)
            if fingerprint == original.fingerprint:
                return raw
            if (
                str(raw.get("rule_id")) == original.rule_id
                and self._normalize(str(raw.get("file") or ""))
                == self._normalize(original.file)
                and " ".join(str(raw.get("symbol") or "").split())
                == " ".join(str(original.symbol or "").split())
            ):
                semantic_match = raw
        return semantic_match

    def _record(
        self, audit_id: str, finding_id: str, attempt: VerificationAttempt
    ) -> VerificationAttempt:
        audit = self.store.get(audit_id)
        if audit is None:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if finding is None:
            raise KeyError(finding_id)
        previous_status = finding.triage_status
        finding.verification_attempts.append(attempt)
        if attempt.outcome == VerificationOutcome.VERIFIED_RESOLVED:
            finding.triage_status = TriageStatus.VERIFIED_RESOLVED
        elif attempt.outcome == VerificationOutcome.STILL_PRESENT and previous_status in {
            TriageStatus.RESOLVED,
            TriageStatus.VERIFIED_RESOLVED,
        }:
            finding.triage_status = TriageStatus.REOPENED
        if finding.triage_status != previous_status:
            finding.status_history.append(
                FindingStatusChange(
                    from_status=previous_status,
                    to_status=finding.triage_status,
                    reason=attempt.message,
                    changed_at=attempt.completed_at,
                )
            )
        audit.record_version = CURRENT_AUDIT_RECORD_VERSION
        audit.updated_at = attempt.completed_at
        self.store.save(audit)
        return attempt

    @staticmethod
    def _source_path(repository: RepositorySnapshot, relative: str) -> Path:
        root = Path(repository.path).resolve()
        target = (root / relative).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            raise VerificationError("Finding path escapes the repository") from None
        return target

    @staticmethod
    def _skip_reason(coverage: ScanCoverage, relative: str) -> str | None:
        for reason, paths in (coverage.skipped_files_by_reason or {}).items():
            if relative in {VerificationService._normalize(path) for path in paths}:
                return reason.replace("_", " ")
        return None

    @staticmethod
    def _normalize(path: str) -> str:
        return path.replace("\\", "/")
