from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from perfora import repositories
from perfora.config import Settings
from perfora.database import AuditStore
from perfora.domain import (
    AuditRecord,
    Finding,
    FixApplyRequest,
    ProviderId,
    RepositorySnapshot,
)
from perfora.exports import export_html, export_sarif
from perfora.fixes import FixSafetyError, FixService
from perfora.main import app
from perfora.process import run_process
from perfora.providers import ProviderRegistry
from perfora.repositories import inspect_repository, pick_repository_path
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


@pytest.mark.asyncio
async def test_rejects_an_empty_repository_path_without_using_the_server_cwd() -> None:
    result = await inspect_repository("   ")

    assert result.valid is False
    assert result.path == "   "
    assert result.detail == "Repository path is required"


@pytest.mark.asyncio
async def test_rejects_a_relative_repository_path() -> None:
    result = await inspect_repository("projects/sample_flutter")

    assert result.valid is False
    assert result.path == "projects/sample_flutter"
    assert result.detail == "Repository path must be absolute"


@pytest.mark.asyncio
async def test_accepts_a_file_url_pasted_from_the_desktop(tmp_path: Path) -> None:
    project = tmp_path / "Flutter Project"
    project.mkdir()
    (project / "pubspec.yaml").write_text(
        "name: sample\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )

    result = await inspect_repository(project.as_uri())

    assert result.valid is True
    assert result.path == str(project)


@pytest.mark.asyncio
async def test_accepts_an_absolute_path_wrapped_in_quotes(tmp_path: Path) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: sample\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )

    result = await inspect_repository(f'"{tmp_path}"')

    assert result.valid is True
    assert result.path == str(tmp_path)


@pytest.mark.asyncio
async def test_native_picker_returns_selected_macos_path(monkeypatch) -> None:
    async def choose_folder(command, **_):
        assert command[0] == "osascript"
        return "/Users/islam/projects/flutter_app/"

    monkeypatch.setattr(repositories.sys, "platform", "darwin")
    monkeypatch.setattr(repositories, "run_process", choose_folder)

    selected_path = await pick_repository_path()

    assert selected_path == "/Users/islam/projects/flutter_app"


@pytest.mark.asyncio
async def test_native_picker_reports_cancellation_without_a_generic_failure(monkeypatch) -> None:
    async def cancel_folder_selection(*_args, **_kwargs):
        raise repositories.ProcessError(["osascript"], 1, "User canceled. (-128)")

    monkeypatch.setattr(repositories.sys, "platform", "darwin")
    monkeypatch.setattr(repositories, "run_process", cancel_folder_selection)

    with pytest.raises(repositories.RepositoryPickerCancelled, match="selection was cancelled"):
        await pick_repository_path()


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
    settings = Settings(database_path=tmp_path.parent / f"{tmp_path.name}.db")
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


@pytest.mark.asyncio
async def test_applies_and_rolls_back_reviewed_patch(tmp_path: Path) -> None:
    source = tmp_path / "lib" / "controller.dart"
    source.parent.mkdir()
    source.write_text("final value = 1;\n")
    await run_process(["git", "init", "-q"], cwd=tmp_path)
    await run_process(["git", "add", "."], cwd=tmp_path)
    await run_process(
        [
            "git",
            "-c",
            "user.name=Perfora Test",
            "-c",
            "user.email=perfora@test.local",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=tmp_path,
    )
    head = await run_process(["git", "rev-parse", "HEAD"], cwd=tmp_path)
    settings = Settings(database_path=tmp_path.parent / f"{tmp_path.name}.db")
    store = AuditStore(settings.database_path)
    audit = _audit(tmp_path)
    store.save(audit)
    service = FixService(store, ProviderRegistry(settings))
    patch = """diff --git a/lib/controller.dart b/lib/controller.dart
--- a/lib/controller.dart
+++ b/lib/controller.dart
@@ -1 +1 @@
-final value = 1;
+final value = 2;
"""

    result = await service.apply(
        audit.id,
        audit.findings[0].id,
        FixApplyRequest(
            approved=True,
            expected_head=head,
            patch=patch,
            verification_commands=[],
        ),
    )
    assert result.applied is True
    assert result.branch.startswith("perfora/fix-")
    assert source.read_text() == "final value = 2;\n"

    rollback = await service.rollback(audit.id, audit.findings[0].id)

    assert rollback["rolled_back"] is True
    assert source.read_text() == "final value = 1;\n"


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
