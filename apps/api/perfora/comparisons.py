from __future__ import annotations

from datetime import UTC, datetime

from .database import AuditStore
from .domain import (
    AuditComparison,
    AuditRecord,
    ComparisonStatus,
    Finding,
    FindingStatusChange,
    SeverityChange,
    TriageStatus,
)


class ComparisonError(ValueError):
    pass


class AuditComparisonService:
    def __init__(self, store: AuditStore):
        self.store = store

    def compare(self, current_id: str, baseline_id: str | None = None) -> AuditComparison:
        current = self.store.get(current_id)
        if current is None:
            raise KeyError(current_id)
        baseline = self._resolve_baseline(current, baseline_id)
        return self._compare_records(current, baseline)

    def apply_baseline(self, current: AuditRecord) -> AuditComparison:
        baseline = self._resolve_baseline(current, None)
        comparison = self._compare_records(current, baseline)
        current.baseline_audit_id = baseline.id if baseline else None
        now = datetime.now(UTC)
        baseline_by_fingerprint = self._by_fingerprint(baseline.findings) if baseline else {}
        older_by_fingerprint = self._older_findings(current, baseline)

        severity_change_ids = {item.finding_id for item in comparison.severity_changes}
        for finding in current.findings:
            finding.last_seen_at = now
            previous = baseline_by_fingerprint.get(finding.fingerprint)
            if previous:
                self._carry_triage(previous, finding)
                finding.first_seen_at = previous.first_seen_at or baseline.created_at
                if previous.triage_status in {
                    TriageStatus.RESOLVED,
                    TriageStatus.VERIFIED_RESOLVED,
                }:
                    self._reopen(finding, previous.triage_status, "Finding reappeared in scan")
                    finding.comparison_status = ComparisonStatus.REGRESSED
                elif self._suppression_expired(previous, now):
                    self._reopen(finding, previous.triage_status, "Suppression expired")
                    finding.comparison_status = ComparisonStatus.REGRESSED
                elif finding.id in severity_change_ids:
                    finding.comparison_status = ComparisonStatus.SEVERITY_CHANGED
                else:
                    finding.comparison_status = ComparisonStatus.UNCHANGED
                continue

            older = older_by_fingerprint.get(finding.fingerprint)
            if older:
                self._carry_triage(older, finding)
                finding.first_seen_at = older.first_seen_at or older.last_seen_at or now
                self._reopen(finding, older.triage_status, "Finding returned after absence")
                finding.comparison_status = ComparisonStatus.REGRESSED
            else:
                finding.first_seen_at = now
                finding.comparison_status = ComparisonStatus.NEW
        return comparison

    def _resolve_baseline(
        self, current: AuditRecord, baseline_id: str | None
    ) -> AuditRecord | None:
        if baseline_id:
            baseline = self.store.get(baseline_id)
            if baseline is None:
                raise ComparisonError("Baseline audit not found")
            self._validate_baseline(current, baseline)
            return baseline

        candidates = [
            audit
            for audit in self.store.list()
            if audit.id != current.id
            and audit.repository.path == current.repository.path
            and audit.audit_type == current.audit_type
            and audit.created_at < current.created_at
            and audit.status in {"completed", "partial"}
        ]
        return max(candidates, key=lambda item: item.created_at, default=None)

    @staticmethod
    def _validate_baseline(current: AuditRecord, baseline: AuditRecord) -> None:
        if baseline.id == current.id:
            raise ComparisonError("An audit cannot be its own baseline")
        if baseline.repository.path != current.repository.path:
            raise ComparisonError("Baseline must use the same repository path")
        if baseline.audit_type != current.audit_type:
            raise ComparisonError("Baseline must use the same audit type")
        if baseline.created_at >= current.created_at:
            raise ComparisonError("Baseline must be older than the current audit")

    def _compare_records(
        self, current: AuditRecord, baseline: AuditRecord | None
    ) -> AuditComparison:
        current_map = self._by_fingerprint(current.findings)
        if baseline is None:
            return AuditComparison(
                current_audit_id=current.id,
                new_finding_ids=[finding.id for finding in current.findings],
            )

        baseline_map = self._by_fingerprint(baseline.findings)
        older_fingerprints = set(self._older_findings(current, baseline))
        result = AuditComparison(current_audit_id=current.id, baseline_audit_id=baseline.id)
        for fingerprint, finding in current_map.items():
            previous = baseline_map.get(fingerprint)
            if previous is None:
                target = (
                    result.regressed_finding_ids
                    if fingerprint in older_fingerprints
                    else result.new_finding_ids
                )
                target.append(finding.id)
            elif previous.triage_status in {
                TriageStatus.RESOLVED,
                TriageStatus.VERIFIED_RESOLVED,
            } or self._suppression_expired(previous, datetime.now(UTC)):
                result.regressed_finding_ids.append(finding.id)
            elif previous.severity != finding.severity:
                result.severity_changes.append(
                    SeverityChange(
                        fingerprint=fingerprint,
                        finding_id=finding.id,
                        baseline_finding_id=previous.id,
                        from_severity=previous.severity,
                        to_severity=finding.severity,
                    )
                )
            else:
                result.unchanged_finding_ids.append(finding.id)
        result.resolved_findings = [
            finding
            for fingerprint, finding in baseline_map.items()
            if fingerprint not in current_map
        ]
        return result

    def _older_findings(
        self, current: AuditRecord, baseline: AuditRecord | None
    ) -> dict[str, Finding]:
        cutoff = baseline.created_at if baseline else current.created_at
        candidates = sorted(
            (
                audit
                for audit in self.store.list()
                if audit.id != current.id
                and audit.repository.path == current.repository.path
                and audit.audit_type == current.audit_type
                and audit.created_at < cutoff
                and audit.status in {"completed", "partial"}
            ),
            key=lambda item: item.created_at,
            reverse=True,
        )
        result: dict[str, Finding] = {}
        for audit in candidates:
            for finding in audit.findings:
                if finding.fingerprint:
                    result.setdefault(finding.fingerprint, finding)
        return result

    @staticmethod
    def _by_fingerprint(findings: list[Finding]) -> dict[str, Finding]:
        return {finding.fingerprint: finding for finding in findings if finding.fingerprint}

    @staticmethod
    def _carry_triage(previous: Finding, current: Finding) -> None:
        current.triage_status = previous.triage_status
        current.owner = previous.owner
        current.due_at = previous.due_at
        current.resolution_commit = previous.resolution_commit
        current.disposition_reason = previous.disposition_reason
        current.suppression_expires_at = previous.suppression_expires_at
        current.ticket_url = previous.ticket_url
        current.notes = list(previous.notes)
        current.status_history = list(previous.status_history)
        current.verification_attempts = list(previous.verification_attempts)

    @staticmethod
    def _suppression_expired(finding: Finding, now: datetime) -> bool:
        if finding.triage_status not in {
            TriageStatus.FALSE_POSITIVE,
            TriageStatus.RISK_ACCEPTED,
        } or finding.suppression_expires_at is None:
            return False
        expiration = finding.suppression_expires_at
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        return expiration <= now

    @staticmethod
    def _reopen(finding: Finding, previous: TriageStatus, reason: str) -> None:
        finding.triage_status = TriageStatus.REOPENED
        finding.status_history.append(
            FindingStatusChange(
                from_status=previous,
                to_status=TriageStatus.REOPENED,
                reason=reason,
            )
        )
