from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse

from .analyzer_client import DartAnalyzerClient
from .audits import AuditCoordinator
from .config import settings
from .database import AuditStore
from .domain import AuditCreate, FixApplyRequest, RepositoryRequest
from .exports import export_html, export_json, export_sarif
from .fixes import FixSafetyError, FixService
from .providers import ProviderRegistry
from .repositories import inspect_repository
from .setup import tool_health

store = AuditStore(settings.database_path)
providers = ProviderRegistry(settings)
coordinator = AuditCoordinator(store, DartAnalyzerClient(settings), providers)
fixes = FixService(store, providers)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await coordinator.start()
    yield
    await coordinator.stop()


app = FastAPI(title="Perfora API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict:
    return {"name": "Perfora", "status": "ready", "version": "0.1.0"}


@app.get("/api/setup")
async def setup_status() -> dict:
    tools, catalogs = await asyncio.gather(tool_health(), providers.catalogs())
    return {"tools": tools, "providers": catalogs}


@app.get("/api/providers/models")
async def model_catalogs() -> dict:
    return {"providers": await providers.catalogs()}


@app.post("/api/repositories/validate")
async def validate_repository(request: RepositoryRequest):
    return await inspect_repository(request.path)


@app.get("/api/audits")
async def list_audits() -> dict:
    return {"audits": store.list()}


@app.post("/api/audits", status_code=202)
async def create_audit(request: AuditCreate):
    repository = await inspect_repository(request.repository_path)
    if not repository.valid:
        raise HTTPException(status_code=422, detail=repository.detail)
    catalogs = await providers.catalogs()
    catalog = next((item for item in catalogs if item.provider == request.provider), None)
    model = next(
        (item for item in (catalog.models if catalog else []) if item.id == request.model_id),
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
async def export_audit(audit_id: str, format: str = Query(pattern="^(json|html|sarif)$")):
    audit = store.get(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    exporters = {"json": export_json, "html": export_html, "sarif": export_sarif}
    media_types = {
        "json": "application/json",
        "html": "text/html",
        "sarif": "application/sarif+json",
    }
    return PlainTextResponse(exporters[format](audit), media_type=media_types[format])


@app.post("/api/audits/{audit_id}/findings/{finding_id}/fix")
async def propose_fix(audit_id: str, finding_id: str):
    try:
        return await fixes.propose(audit_id, finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except FixSafetyError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@app.post("/api/audits/{audit_id}/findings/{finding_id}/apply")
async def apply_fix(audit_id: str, finding_id: str, request: FixApplyRequest):
    try:
        return await fixes.apply(audit_id, finding_id, request)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except (FixSafetyError, ValueError) as error:
        raise HTTPException(status_code=409, detail=str(error)) from None


@app.post("/api/audits/{audit_id}/findings/{finding_id}/rollback")
async def rollback_fix(audit_id: str, finding_id: str):
    try:
        return await fixes.rollback(audit_id, finding_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Audit or finding not found") from None
    except FixSafetyError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
