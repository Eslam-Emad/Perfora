from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from .database import AuditStore
from .domain import (
    CURRENT_AUDIT_RECORD_VERSION,
    Finding,
    FindingNote,
    FindingStatusChange,
    FindingUpdate,
    TriageStatus,
)
from .policy import PolicyError, RepositoryPolicy, load_policy


class FindingUpdateError(ValueError):
    pass


class FindingService:
    def __init__(self, store: AuditStore):
        self.store = store

    def update(self, audit_id: str, finding_id: str, request: FindingUpdate) -> Finding:
        audit = self.store.get(audit_id)
        if audit is None:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if finding is None:
            raise KeyError(finding_id)
        if not request.model_fields_set:
            raise FindingUpdateError("At least one finding field must be provided")

        fields = request.model_fields_set
        target_status = (
            request.triage_status if "triage_status" in fields else finding.triage_status
        )
        if target_status is None:
            raise FindingUpdateError("triage_status cannot be null")
        if target_status == TriageStatus.VERIFIED_RESOLVED:
            raise FindingUpdateError(
                "Verified resolved is assigned only by a deterministic re-scan"
            )
        try:
            policy = load_policy(Path(audit.repository.path) / ".perfora.yaml")
        except PolicyError:
            policy = RepositoryPolicy()
        if (
            "triage_status" in fields
            and target_status == TriageStatus.RISK_ACCEPTED
            and policy.suppressions.require_approval
        ):
            raise FindingUpdateError(
                "Risk acceptance requires an approved suppression in the repository policy pack"
            )

        disposition_reason = (
            self._clean(request.disposition_reason)
            if "disposition_reason" in fields
            else finding.disposition_reason
        )
        if (
            target_status
            in {
                TriageStatus.FALSE_POSITIVE,
                TriageStatus.RISK_ACCEPTED,
            }
            and not disposition_reason
        ):
            raise FindingUpdateError(
                "A disposition reason is required for false positive or risk accepted"
            )

        owner = self._clean(request.owner) if "owner" in fields else finding.owner
        due_at = request.due_at if "due_at" in fields else finding.due_at
        if target_status == TriageStatus.RESOLVED:
            if finding.severity in policy.ownership.require_owner_for and not owner:
                raise FindingUpdateError("An owner is required before resolving this finding")
            if finding.severity in policy.ownership.require_due_date_for and not due_at:
                raise FindingUpdateError("A due date is required before resolving this finding")

        suppression_expires_at = (
            request.suppression_expires_at
            if "suppression_expires_at" in fields
            else finding.suppression_expires_at
        )
        if suppression_expires_at and self._as_utc(suppression_expires_at) <= datetime.now(UTC):
            raise FindingUpdateError("Suppression expiration must be in the future")

        note = self._clean(request.note) if "note" in fields else None
        if "note" in fields and not note:
            raise FindingUpdateError("Note cannot be empty")

        previous_status = finding.triage_status
        if "triage_status" in fields:
            finding.triage_status = target_status
        for field in (
            "owner",
            "due_at",
            "resolution_commit",
            "suppression_expires_at",
            "ticket_url",
        ):
            if field in fields:
                value = getattr(request, field)
                if isinstance(value, str):
                    value = self._clean(value)
                setattr(finding, field, value)
        if "disposition_reason" in fields:
            finding.disposition_reason = disposition_reason
        if note:
            finding.notes.append(FindingNote(id=uuid.uuid4().hex, body=note))
        if finding.triage_status != previous_status:
            finding.status_history.append(
                FindingStatusChange(
                    from_status=previous_status,
                    to_status=finding.triage_status,
                    reason=disposition_reason,
                )
            )

        audit.record_version = CURRENT_AUDIT_RECORD_VERSION
        audit.updated_at = datetime.now(UTC)
        self.store.save(audit)
        return finding

    @staticmethod
    def _clean(value: str | None) -> str | None:
        cleaned = value.strip() if value else ""
        return cleaned or None

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
