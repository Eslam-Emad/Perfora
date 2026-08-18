from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from .database import AuditStore
from .domain import AuditRecord, TriageStatus

_OPEN_STATUSES = {
    TriageStatus.NEW,
    TriageStatus.INVESTIGATING,
    TriageStatus.IN_PROGRESS,
    TriageStatus.REOPENED,
}


class PortfolioService:
    """Build an organization view from the latest local evidence per repository and audit type."""

    def __init__(self, store: AuditStore):
        self.store = store

    def summary(self) -> dict:
        audits = self.store.list()
        latest = self._latest_evidence(audits)
        evidence_audits = [audit for audit in audits if audit.status in {"completed", "partial"}]
        now = datetime.now(UTC)
        repository_audits: dict[str, list[AuditRecord]] = defaultdict(list)
        for audit in latest:
            repository_audits[audit.repository.path].append(audit)

        repositories = []
        owners: dict[str, dict[str, int | str]] = {}
        for path, records in repository_audits.items():
            findings = [finding for audit in records for finding in audit.findings]
            open_findings = [item for item in findings if item.triage_status in _OPEN_STATUSES]
            governance = self._governance_counts(findings, now)
            for finding in open_findings:
                owner = finding.owner or "Unassigned"
                bucket = owners.setdefault(owner, {"owner": owner, "open": 0, "overdue": 0})
                bucket["open"] = int(bucket["open"]) + 1
                if finding.due_at and self._as_utc(finding.due_at) < now:
                    bucket["overdue"] = int(bucket["overdue"]) + 1
            latest_record = max(records, key=lambda item: item.updated_at)
            repositories.append(
                {
                    "path": path,
                    "name": latest_record.repository.name,
                    "latest_audit_at": latest_record.updated_at.isoformat(),
                    "audit_count": sum(audit.repository.path == path for audit in audits),
                    "open_findings": len(open_findings),
                    "high_or_critical": sum(
                        item.severity in {"high", "critical"} for item in open_findings
                    ),
                    "verified_resolved": sum(
                        item.triage_status == TriageStatus.VERIFIED_RESOLVED for item in findings
                    ),
                    "recurrences": sum(
                        item.triage_status == TriageStatus.REOPENED
                        or getattr(item.comparison_status, "value", None) == "regressed"
                        for item in findings
                    ),
                    "governance_issues": sum(governance.values()),
                    "governance": governance,
                }
            )

        repositories.sort(key=lambda item: item["latest_audit_at"], reverse=True)
        owner_rows = sorted(
            owners.values(),
            key=lambda item: (-int(item["overdue"]), -int(item["open"]), str(item["owner"])),
        )
        trends = [
            self._trend(audit)
            for audit in sorted(evidence_audits, key=lambda item: item.created_at)
        ]
        return {
            "generated_at": now.isoformat(),
            "totals": {
                "repositories": len(repositories),
                "audits": len(audits),
                "open_findings": sum(item["open_findings"] for item in repositories),
                "high_or_critical": sum(item["high_or_critical"] for item in repositories),
                "verified_resolved": sum(item["verified_resolved"] for item in repositories),
                "recurrences": sum(item["recurrences"] for item in repositories),
                "governance_issues": sum(item["governance_issues"] for item in repositories),
            },
            "repositories": repositories,
            "owners": owner_rows,
            "trends": trends,
            "scope": "latest local audit per repository and audit type",
        }

    @staticmethod
    def _latest_evidence(audits: list[AuditRecord]) -> list[AuditRecord]:
        latest: dict[tuple[str, str], AuditRecord] = {}
        candidates = [audit for audit in audits if audit.status in {"completed", "partial"}]
        for audit in candidates:
            key = (audit.repository.path, audit.audit_type.value)
            if key not in latest or audit.updated_at > latest[key].updated_at:
                latest[key] = audit
        return list(latest.values())

    @classmethod
    def _governance_counts(cls, findings: list, now: datetime) -> dict[str, int]:
        return {
            "unassigned_high_or_critical": sum(
                finding.severity in {"high", "critical"}
                and finding.triage_status in _OPEN_STATUSES
                and not finding.owner
                for finding in findings
            ),
            "missing_due_date": sum(
                finding.severity == "critical"
                and finding.triage_status in _OPEN_STATUSES
                and not finding.due_at
                for finding in findings
            ),
            "overdue": sum(
                finding.triage_status in _OPEN_STATUSES
                and finding.due_at is not None
                and cls._as_utc(finding.due_at) < now
                for finding in findings
            ),
            "expired_suppression": sum(
                finding.suppression_expires_at is not None
                and cls._as_utc(finding.suppression_expires_at) < now
                for finding in findings
            ),
            "resolved_not_verified": sum(
                finding.triage_status == TriageStatus.RESOLVED for finding in findings
            ),
        }

    @staticmethod
    def _trend(audit: AuditRecord) -> dict:
        return {
            "audit_id": audit.id,
            "repository": audit.repository.name,
            "audit_type": audit.audit_type.value,
            "created_at": audit.created_at.isoformat(),
            "total": len(audit.findings),
            "new": sum(
                getattr(item.comparison_status, "value", None) == "new" for item in audit.findings
            ),
            "regressed": sum(
                getattr(item.comparison_status, "value", None) == "regressed"
                or item.triage_status == TriageStatus.REOPENED
                for item in audit.findings
            ),
            "verified_resolved": sum(
                item.triage_status == TriageStatus.VERIFIED_RESOLVED for item in audit.findings
            ),
        }

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
