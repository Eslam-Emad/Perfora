from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response, StreamingResponse

from . import __version__
from .analyzer_client import DartAnalyzerClient
from .audits import AuditCoordinator
from .comparisons import AuditComparisonService, ComparisonError
from .config import settings
from .database import AuditStore
from .domain import (
    AuditCreate,
    FindingUpdate,
    ProviderSettingsUpdate,
    RepositoryRequest,
    RuntimeImportRequest,
)
from .exports import (
    export_audit_cyclonedx,
    export_evidence_package,
    export_html,
    export_json,
    export_sarif,
)
from .findings import FindingService, FindingUpdateError
from .handoffs import TicketHandoffService, TicketSystem
from .portfolio import PortfolioService
from .prompts import PromptBuildError, PromptService
from .provider_settings import ProviderSettingsError, ProviderSettingsService
from .providers import ProviderRegistry
from .repositories import (
    RepositoryPickerCancelled,
    RepositoryPickerError,
    inspect_repository,
    pick_repository_path,
)
from .runtime_artifacts import RuntimeArtifactError, RuntimeArtifactService
from .setup import tool_health
from .verifications import VerificationError, VerificationService

store = AuditStore(settings.database_path)
providers = ProviderRegistry(settings)
analyzer = DartAnalyzerClient(settings)
coordinator = AuditCoordinator(store, analyzer, providers)
prompts = PromptService(store)
findings = FindingService(store)
comparisons = AuditComparisonService(store)
verifications = VerificationService(store, analyzer)
runtime_artifacts = RuntimeArtifactService(store)
portfolio = PortfolioService(store)
ticket_handoffs = TicketHandoffService(store)
provider_settings = ProviderSettingsService(settings)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await coordinator.start()
    yield
    await coordinator.stop()


app = FastAPI(title="Perfora API", version=__version__, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict:
    return {"name": "Perfora", "status": "ready", "version": __version__}


@app.get("/api/setup")
async def setup_status() -> dict:
    tools, catalogs = await asyncio.gather(tool_health(), providers.catalogs())
    return {"tools": tools, "providers": catalogs}


@app.get("/api/providers/models")
async def model_catalogs() -> dict:
    return {"providers": await providers.catalogs()}


@app.get("/api/settings/providers")
async def get_provider_settings():
    return provider_settings.snapshot()


@app.patch("/api/settings/providers")
async def update_provider_settings(request: ProviderSettingsUpdate):
    try:
        snapshot = provider_settings.update(request)
    except ProviderSettingsError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    return {"settings": snapshot, "providers": await providers.catalogs()}


@app.post("/api/repositories/validate")
async def validate_repository(request: RepositoryRequest):
    return await inspect_repository(request.path)


@app.post("/api/repositories/pick")
async def pick_repository():
    try:
        selected_path = await pick_repository_path()
    except RepositoryPickerCancelled as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    except RepositoryPickerError as error:
        raise HTTPException(status_code=501, detail=str(error)) from None
    return await inspect_repository(selected_path)


@app.get("/api/audits")
async def list_audits() -> dict:
    return {"audits": store.list()}


@app.get("/api/portfolio")
async def portfolio_summary() -> dict:
    return portfolio.summary()


@app.get("/api/runtime-captures")
async def list_runtime_captures(repository_path: str | None = None) -> dict:
    return {"captures": store.list_runtime_captures(repository_path)}


@app.post("/api/runtime-captures/import", status_code=201)
async def import_runtime_capture(request: RuntimeImportRequest):
    repository = await inspect_repository(request.repository_path)
    if not repository.valid:
        raise HTTPException(status_code=422, detail=repository.detail)
    try:
        return runtime_artifacts.import_capture(request, repository)
    except RuntimeArtifactError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


@app.get("/api/runtime-captures/compare")
async def compare_runtime_captures(baseline_id: str, current_id: str):
    try:
        return runtime_artifacts.compare(baseline_id, current_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Runtime capture not found") from None


@app.get("/api/runtime-captures/{capture_id}")
async def get_runtime_capture(capture_id: str):
    capture = store.get_runtime_capture(capture_id)
    if not capture:
        raise HTTPException(status_code=404, detail="Runtime capture not found")
    return capture


@app.post("/api/audits", status_code=202)
async def create_audit(request: AuditCreate):
    repository = await inspect_repository(request.repository_path)
    if not repository.valid:
        raise HTTPException(status_code=422, detail=repository.detail)
    catalogs = await providers.catalogs()
    catalog = next(
        (
            provider_catalog
            for provider_catalog in catalogs
            if provider_catalog.provider == request.provider
        ),
        None,
    )
    model = next(
        (
            available_model
            for available_model in (catalog.models if catalog else [])
            if available_model.id == request.model_id
        ),
        None,
    )
    if not catalog or not catalog.available:
        raise HTTPException(status_code=422, detail="Selected provider is unavailable")
    if not model:
        raise HTTPException(status_code=422, detail="Selected model is unavailable")
    if model.locality != "local" and not request.remote_source_consent:
        raise HTTPException(
            status_code=422,
            detail="Remote source consent is required for this provider",
        )
    return await coordinator.create(request, repository, model.model_dump())


@app.get("/api/audits/{audit_id}")
async def get_audit(audit_id: str):
    audit = store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.get("/api/audits/{audit_id}/comparison")
async def compare_audit(audit_id: str, baseline_id: str | None = None):
    try:
        return comparisons.compare(audit_id, baseline_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or baseline not found") from None
    except ComparisonError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


@app.patch("/api/audits/{audit_id}/findings/{finding_id}")
async def update_finding(audit_id: str, finding_id: str, request: FindingUpdate):
    try:
        return findings.update(audit_id, finding_id, request)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except FindingUpdateError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None


@app.post("/api/audits/{audit_id}/findings/{finding_id}/verify")
async def verify_finding(audit_id: str, finding_id: str):
    try:
        return await verifications.verify(audit_id, finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except VerificationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@app.get("/api/audits/{audit_id}/findings/{finding_id}/ticket-handoff")
async def build_ticket_handoff(
    audit_id: str,
    finding_id: str,
    system: TicketSystem = "generic",
):
    try:
        return ticket_handoffs.build(audit_id, finding_id, system)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None


@app.get("/api/audits/{audit_id}/events")
async def stream_audit_events(audit_id: str):
    if not store.get(audit_id):
        raise HTTPException(status_code=404, detail="Audit not found")

    async def event_stream():
        after = 0
        terminal = {"completed", "partial", "failed", "cancelled"}
        while True:
            audit = await coordinator.wait_for_event(audit_id, after)
            for event in audit.events[after:]:
                yield f"data: {event.model_dump_json()}\n\n"
            after = len(audit.events)
            if audit.status in terminal:
                yield f"event: terminal\ndata: {json.dumps({'status': audit.status})}\n\n"
                break

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/audits/{audit_id}/export")
async def export_audit(
    audit_id: str,
    format: str = Query(pattern="^(json|html|sarif|cyclonedx|evidence)$"),
):
    audit = store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if format == "evidence":
        package = export_evidence_package(audit, settings.report_signing_key)
        safe_name = (
            "".join(
                character if character.isalnum() or character in {"-", "_"} else "-"
                for character in audit.repository.name
            ).strip("-")
            or "repository"
        )
        return Response(
            package,
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="perfora-{safe_name}-{audit.id[:8]}-evidence.zip"'
                )
            },
        )
    exporters = {
        "json": export_json,
        "html": export_html,
        "sarif": export_sarif,
        "cyclonedx": export_audit_cyclonedx,
    }
    media_types = {
        "json": "application/json",
        "html": "text/html",
        "sarif": "application/sarif+json",
        "cyclonedx": "application/vnd.cyclonedx+json; version=1.7",
    }
    return PlainTextResponse(exporters[format](audit), media_type=media_types[format])


@app.post("/api/audits/{audit_id}/findings/{finding_id}/prompt")
async def build_agent_prompt(audit_id: str, finding_id: str):
    try:
        return prompts.build(audit_id, finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except PromptBuildError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
