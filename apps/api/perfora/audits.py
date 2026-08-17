from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .analyzer_client import AnalyzerUnavailable, DartAnalyzerClient
from .comparisons import AuditComparisonService
from .database import AuditStore
from .domain import (
    AuditCreate,
    AuditEvent,
    AuditRecord,
    Finding,
    ModelEnrichment,
    RepositorySnapshot,
)
from .fingerprints import finding_fingerprint, fingerprint_basis
from .providers import ProviderRegistry
from .security import redact_secrets

ENRICHMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "explanation": {"type": "string"},
        "recommendation": {"type": "string"},
    },
    "required": ["explanation", "recommendation"],
    "additionalProperties": False,
}


class AuditCoordinator:
    def __init__(
        self,
        store: AuditStore,
        analyzer: DartAnalyzerClient,
        providers: ProviderRegistry,
    ):
        self.store = store
        self.analyzer = analyzer
        self.providers = providers
        self.comparisons = AuditComparisonService(store)
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker: asyncio.Task | None = None
        self._conditions: dict[str, asyncio.Condition] = {}

    async def start(self) -> None:
        if self._worker is None:
            self._worker = asyncio.create_task(self._run_queue(), name="perfora-audit-worker")

    async def stop(self) -> None:
        if self._worker:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None

    async def create(
        self,
        request: AuditCreate,
        repository: RepositorySnapshot,
        model_metadata: dict,
    ) -> AuditRecord:
        audit_id = uuid.uuid4().hex
        audit = AuditRecord(
            id=audit_id,
            repository=repository,
            provider=request.provider,
            model_id=request.model_id,
            audit_type=request.audit_type,
            model_metadata=model_metadata,
            status="queued",
        )
        self._append_event(audit, "queued", "Audit queued", 0)
        self.store.save(audit)
        self._conditions[audit_id] = asyncio.Condition()
        await self.queue.put(audit_id)
        return audit

    def get(self, audit_id: str) -> AuditRecord | None:
        return self.store.get(audit_id)

    async def wait_for_event(self, audit_id: str, after: int, timeout: float = 15) -> AuditRecord:
        current = self.store.get(audit_id)
        if current is None:
            raise KeyError(audit_id)
        if len(current.events) > after or current.status in {"completed", "partial", "failed"}:
            return current
        condition = self._conditions.setdefault(audit_id, asyncio.Condition())
        async with condition:
            try:
                await asyncio.wait_for(condition.wait(), timeout=timeout)
            except TimeoutError:
                pass
        latest = self.store.get(audit_id)
        if latest is None:
            raise KeyError(audit_id)
        return latest

    async def _run_queue(self) -> None:
        while True:
            audit_id = await self.queue.get()
            try:
                await self._run(audit_id)
            finally:
                self.queue.task_done()

    async def _run(self, audit_id: str) -> None:
        audit = self.store.get(audit_id)
        if audit is None:
            return
        audit.status = "running"
        self._append_event(audit, "started", "Inspecting repository evidence", 10)
        await self._persist_and_notify(audit)
        try:
            analysis = await self.analyzer.analyze(Path(audit.repository.path), audit.audit_type)
        except AnalyzerUnavailable as error:
            audit.status = "failed"
            audit.error = str(error)
            self._append_event(audit, "failed", "Deterministic analyzer failed", 100)
            await self._persist_and_notify(audit)
            return

        audit.analyzer_version = analysis.analyzer_version
        audit.rule_pack = analysis.rule_pack
        audit.scan_coverage = analysis.coverage
        fingerprint_occurrences: dict[str, int] = {}
        for raw in analysis.findings:
            fingerprint_basis = self._fingerprint_basis(raw)
            occurrence = fingerprint_occurrences.get(fingerprint_basis, 0)
            fingerprint_occurrences[fingerprint_basis] = occurrence + 1
            finding = Finding(
                id=uuid.uuid4().hex,
                audit_id=audit.id,
                fingerprint=self._fingerprint(fingerprint_basis, occurrence),
                **raw,
            )
            audit.findings.append(finding)
        comparison = self.comparisons.apply_baseline(audit)
        self._append_event(
            audit,
            "evidence_ready",
            f"Found {len(audit.findings)} {audit.audit_type.value} issue(s)",
            55,
            {
                "finding_count": len(audit.findings),
                "files_scanned": audit.scan_coverage.files_scanned,
                "files_skipped": audit.scan_coverage.files_skipped,
                "baseline_audit_id": comparison.baseline_audit_id,
                "new_findings": len(comparison.new_finding_ids),
                "regressed_findings": len(comparison.regressed_finding_ids),
                "resolved_findings": len(comparison.resolved_findings),
            },
        )
        await self._persist_and_notify(audit)

        if not audit.findings:
            audit.status = "completed"
            self._append_event(
                audit,
                "completed",
                f"No {audit.audit_type.value} findings detected",
                100,
            )
            await self._persist_and_notify(audit)
            return

        first = audit.findings[0]
        audit.context_manifest = [first.file]
        prompt = self._enrichment_prompt(audit, first)
        self._append_event(
            audit,
            "model_started",
            f"Enriching evidence with {audit.provider.value}/{audit.model_id}",
            70,
        )
        await self._persist_and_notify(audit)
        try:
            enrichment = await self.providers.generate_json(
                audit.provider, audit.model_id, prompt, ENRICHMENT_SCHEMA
            )
            first.model_enrichment = ModelEnrichment(
                provider=audit.provider,
                model_id=audit.model_id,
                explanation=enrichment["explanation"],
                recommendation=enrichment["recommendation"],
            )
            audit.status = "completed"
            self._append_event(audit, "completed", "Audit completed", 100)
        # This is the job-runner boundary: every provider failure must become a
        # durable partial result instead of terminating the queue worker.
        except Exception as error:  # noqa: BLE001
            audit.status = "partial"
            audit.error = f"{type(error).__name__}: model enrichment failed"
            self._append_event(
                audit,
                "partial",
                "Evidence is available, but model enrichment failed",
                100,
            )
        await self._persist_and_notify(audit)

    def _enrichment_prompt(self, audit: AuditRecord, finding: Finding) -> str:
        evidence = "\n".join(f"- {redact_secrets(item)}" for item in finding.evidence)
        return redact_secrets(
            f"""You are Perfora's evidence-bound Flutter {audit.audit_type.value} reviewer.
Explain only the confirmed finding below. Do not invent runtime measurements.

Framework: {finding.framework}
Rule: {finding.rule_id}
File: {finding.file}:{finding.line}
Symbol: {finding.symbol or "unknown"}
Evidence:
{evidence}

Return a concise causal explanation and one specific, safe recommendation."""
        )

    @staticmethod
    def _fingerprint_basis(raw: dict) -> str:
        return fingerprint_basis(raw)

    @staticmethod
    def _fingerprint(basis: str, occurrence: int = 0) -> str:
        return finding_fingerprint(basis, occurrence)

    def _append_event(
        self,
        audit: AuditRecord,
        event_type: str,
        message: str,
        progress: int,
        data: dict | None = None,
    ) -> None:
        audit.events.append(
            AuditEvent(
                sequence=len(audit.events) + 1,
                type=event_type,
                message=message,
                progress=progress,
                data=data or {},
            )
        )
        audit.updated_at = datetime.now(UTC)

    async def _persist_and_notify(self, audit: AuditRecord) -> None:
        self.store.save(audit)
        condition = self._conditions.setdefault(audit.id, asyncio.Condition())
        async with condition:
            condition.notify_all()
