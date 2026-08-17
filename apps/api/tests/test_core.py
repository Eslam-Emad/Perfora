import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from perfora import analyzer_client, repositories
from perfora.analyzer_client import DartAnalyzerClient
from perfora.config import Settings
from perfora.database import AuditStore
from perfora.domain import (
    AuditRecord,
    AuditType,
    Finding,
    FixApplyRequest,
    ProviderId,
    RepositorySnapshot,
)
from perfora.exports import export_html, export_sarif
from perfora.fixes import FIX_SCHEMA, FixSafetyError, FixService
from perfora.main import app
from perfora.process import run_process
from perfora.prompts import PromptService
from perfora.providers import ProviderRegistry
from perfora.providers.base import ProviderStructuredOutputError
from perfora.providers.opencode import (
    OpenCodeAdapter,
    _decode_json_object,
    _extract_unified_diff,
    _generation_environment,
    _text_from_json_events,
)
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


def test_decodes_opencode_json_from_markdown_or_commentary() -> None:
    response = """I prepared the requested result.
```json
{"summary":"Remove the exception","risk":"low","patch":"diff --git a/file b/file\\n"}
```
"""

    decoded = _decode_json_object(response)

    assert decoded["summary"] == "Remove the exception"
    assert decoded["patch"].startswith("diff --git")


def test_reads_text_parts_from_opencode_jsonl_events() -> None:
    output = """{"type":"step_start","part":{"type":"step-start"}}
{"type":"text","part":{"type":"text","text":"{\\"summary\\":\\"ok\\"}"}}
{"type":"step_finish","part":{"type":"step-finish"}}"""

    assert _text_from_json_events(output) == '{"summary":"ok"}'


def test_rejects_opencode_output_without_a_json_object() -> None:
    with pytest.raises(ProviderStructuredOutputError):
        _decode_json_object("I could not generate the requested patch.")


def test_opencode_generation_agent_denies_tools_and_limits_steps(monkeypatch) -> None:
    monkeypatch.delenv("OPENCODE_CONFIG_CONTENT", raising=False)

    config = json.loads(_generation_environment()["OPENCODE_CONFIG_CONTENT"])
    agent = config["agent"]["perfora-json"]

    assert agent["mode"] == "primary"
    assert agent["steps"] == 1
    assert agent["permission"] == {"*": "deny"}


@pytest.mark.asyncio
async def test_opencode_sends_generation_prompt_over_stdin(monkeypatch) -> None:
    observed: dict = {}

    async def generate(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return '{"type":"text","part":{"type":"text","text":"{\\"summary\\":\\"ok\\"}"}}'

    monkeypatch.setattr("perfora.providers.opencode.shutil.which", lambda _: "/bin/opencode")
    monkeypatch.setattr("perfora.providers.opencode.run_process", generate)

    result = await OpenCodeAdapter().generate_json(
        "opencode/big-pickle",
        "sensitive source prompt",
        {"type": "object", "properties": {"summary": {"type": "string"}}},
    )

    assert result == {"summary": "ok"}
    assert "sensitive source prompt" not in observed["command"]
    assert "sensitive source prompt" in observed["input_text"]
    assert observed["command"][-3:] == ["--agent", "perfora-json", "--pure"]


def test_fix_schema_uses_patch_lines_instead_of_a_multiline_json_string() -> None:
    assert "patch_lines" in FIX_SCHEMA["properties"]
    assert "patch" not in FIX_SCHEMA["properties"]


def test_extracts_a_direct_fenced_unified_diff() -> None:
    response = """Here is the requested patch:
```diff
diff --git a/ios/Runner/Info.plist b/ios/Runner/Info.plist
--- a/ios/Runner/Info.plist
+++ b/ios/Runner/Info.plist
@@ -1,2 +1 @@
-<true/>
+<false/>
```
"""

    patch = _extract_unified_diff(response)

    assert patch is not None
    assert patch.startswith("diff --git")
    assert patch.endswith("+<false/>")


@pytest.mark.asyncio
async def test_dart_analyzer_selects_the_security_rule_pack(tmp_path: Path, monkeypatch) -> None:
    analyzer_root = tmp_path / "analyzer"
    package_config = analyzer_root / ".dart_tool" / "package_config.json"
    package_config.parent.mkdir(parents=True)
    package_config.write_text("{}")
    repository = tmp_path / "repository"
    repository.mkdir()
    captured_command: list[str] = []

    async def analyze(command, **_):
        captured_command.extend(command)
        return "[]"

    monkeypatch.setattr(analyzer_client.shutil, "which", lambda _: "/usr/bin/dart")
    monkeypatch.setattr(analyzer_client, "run_process", analyze)
    client = DartAnalyzerClient(Settings(analyzer_root=analyzer_root))

    assert await client.analyze(repository, AuditType.SECURITY) == []
    assert captured_command[-2:] == ["--audit-type", "security"]


def test_existing_audit_records_default_to_performance(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    payload = audit.model_dump(exclude={"audit_type"})

    assert AuditRecord.model_validate(payload).audit_type == AuditType.PERFORMANCE


def test_exports_evidence_as_html_and_sarif(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    html = export_html(audit)
    sarif = export_sarif(audit)

    assert "Perfora evidence report" in html
    assert "controller.dart:8" in html
    assert '"ruleId": "lifecycle.missing_cleanup"' in sarif
    assert '"auditType": "performance"' in sarif


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


def test_builds_complete_secret_redacted_agent_prompt(tmp_path: Path) -> None:
    source = tmp_path / "lib" / "controller.dart"
    source.parent.mkdir()
    source.write_text('const apiKey = "sk-example012345678901234567890";\nclass Controller {}\n')
    settings = Settings(database_path=tmp_path.parent / f"{tmp_path.name}.db")
    store = AuditStore(settings.database_path)
    audit = _audit(tmp_path)
    audit.audit_type = AuditType.SECURITY
    audit.repository.branch = "feature/security"
    audit.repository.commit_sha = "abc123"
    audit.repository.clean = False
    audit.repository.fingerprint = "fingerprint-1"
    audit.repository.packages = [".", "packages/shared"]
    audit.context_manifest = ["lib/controller.dart", "pubspec.yaml"]
    audit.findings[0].model_explanation = "The model confirmed the ownership gap."
    store.save(audit)

    result = PromptService(store).build(audit.id, audit.findings[0].id)

    assert result.redacted is True
    assert result.finding_id == "finding-1"
    assert "Audit type: security" in result.prompt
    assert "Selected provider/model: ollama/qwen" in result.prompt
    assert "Branch: feature/security" in result.prompt
    assert "Commit: abc123" in result.prompt
    assert "Clean at audit time: false" in result.prompt
    assert "Rule ID: lifecycle.missing_cleanup" in result.prompt
    assert "Controller is created by the class." in result.prompt
    assert "The controller outlives its owner." in result.prompt
    assert "The model confirmed the ownership gap." in result.prompt
    assert "Dispose the controller." in result.prompt
    assert "packages/shared" in result.prompt
    assert "class Controller {}" in result.prompt
    assert "[REDACTED]" in result.prompt
    assert "sk-example" not in result.prompt
    assert "Do not commit, push" in result.prompt


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
