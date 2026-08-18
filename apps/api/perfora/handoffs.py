from __future__ import annotations

from typing import Literal

from .database import AuditStore
from .security import redact_secrets

TicketSystem = Literal["github", "jira", "linear", "generic"]


class TicketHandoffService:
    def __init__(self, store: AuditStore):
        self.store = store

    def build(self, audit_id: str, finding_id: str, system: TicketSystem) -> dict:
        audit = self.store.get(audit_id)
        if audit is None:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if finding is None:
            raise KeyError(finding_id)
        latest_verification = (
            finding.verification_attempts[-1].outcome.value
            if finding.verification_attempts
            else "not run"
        )
        evidence = "\n".join(f"- {item}" for item in finding.evidence)
        standards = ", ".join(item.id for item in finding.standards) or "not mapped"
        body = redact_secrets(
            f"""## Perfora finding

**Severity:** {finding.severity}
**Status:** {finding.triage_status.value}
**Repository:** {audit.repository.name}
**Location:** `{finding.file}:{finding.line}`
**Rule:** `{finding.rule_id}@{finding.rule_version}`
**Fingerprint:** `{finding.fingerprint}`
**Owner:** {finding.owner or "unassigned"}
**Due date:** {finding.due_at.isoformat() if finding.due_at else "not set"}
**Latest verification:** {latest_verification}
**Standards:** {standards}

### Deterministic explanation
{finding.explanation}

### Evidence
{evidence}

### Recommended change
{finding.recommendation}

### Acceptance criteria
- Confirm the root cause against the current repository state.
- Implement the smallest safe fix using existing project conventions.
- Add or update focused regression coverage.
- Re-run Perfora and attach the deterministic verification result.
- Do not mark the finding verified resolved without a clean re-scan.

_Generated locally by Perfora from audit `{audit.id}`. Review before creating an external issue._
"""
        )
        title = redact_secrets(f"[Perfora][{finding.severity.upper()}] {finding.title}")
        labels = ["perfora", finding.severity, audit.audit_type.value]
        return {
            "system": system,
            "title": title,
            "body": body,
            "labels": labels,
            "finding_id": finding.id,
            "audit_id": audit.id,
            "redacted": True,
            "automatic_creation": False,
        }
