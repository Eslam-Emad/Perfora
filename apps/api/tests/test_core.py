from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from perfora.config import Settings
from perfora.database import AuditStore
from perfora.domain import (
    AuditRecord,
    Finding,
    ProviderId,
    RepositorySnapshot,
)
from perfora.exports import export_html, export_sarif
from perfora.fixes import FixSafetyError, FixService
from perfora.main import app
from perfora.providers import ProviderRegistry
from perfora.repositories import inspect_repository
from perfora.security import redact_secrets


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["name"] == "Perfora"


@pytest.mark.asyncio
async def test_validates_flutter_repository(tmp_path: Path) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: sample\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )

    result = await inspect_repository(str(tmp_path))

    assert result.valid is True
    assert result.is_flutter is True
    assert result.packages == ["."]
    assert result.fingerprint


def test_redacts_likely_secrets() -> None:
    source = 'const apiKey = "sk-example012345678901234567890";'

    redacted = redact_secrets(source)

    assert "sk-example" not in redacted
    assert "[REDACTED]" in redacted


def test_exports_evidence_as_html_and_sarif(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    html = export_html(audit)
    sarif = export_sarif(audit)

    assert "Perfora evidence report" in html
    assert "controller.dart:8" in html
    assert '"ruleId": "lifecycle.missing_cleanup"' in sarif


def test_rejects_patch_outside_approved_file(tmp_path: Path) -> None:
    settings = Settings(database_path=tmp_path / "test.db")
    service = FixService(AuditStore(settings.database_path), ProviderRegistry(settings))
    patch = """diff --git a/lib/other.dart b/lib/other.dart
--- a/lib/other.dart
+++ b/lib/other.dart
@@ -1 +1 @@
-old
+new
"""

    with pytest.raises(FixSafetyError, match="outside the approved finding"):
        service._validate_patch(tmp_path, patch, allowed_file="lib/controller.dart")


def _audit(repository: Path) -> AuditRecord:
    snapshot = RepositorySnapshot(
        path=str(repository),
        name="sample",
        valid=True,
        detail="Flutter repository",
        is_flutter=True,
    )
    audit = AuditRecord(
        id="audit-1",
        repository=snapshot,
        provider=ProviderId.OLLAMA,
        model_id="qwen",
        status="completed",
    )
    audit.findings.append(
        Finding(
            id="finding-1",
            audit_id=audit.id,
            rule_id="lifecycle.missing_cleanup",
            title="Controller is not released",
            severity="high",
            confidence=0.94,
            file="lib/controller.dart",
            line=8,
            framework="Provider",
            evidence=["Controller is created by the class."],
            explanation="The controller outlives its owner.",
            recommendation="Dispose the controller.",
        )
    )
    return audit

