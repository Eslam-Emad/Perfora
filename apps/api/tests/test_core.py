import hashlib
import hmac
import io
import json
import sqlite3
import stat
import zipfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from perfora import analyzer_client, repositories
from perfora import main as main_module
from perfora.analyzer_client import DartAnalyzerClient
from perfora.audits import AuditCoordinator
from perfora.comparisons import AuditComparisonService
from perfora.config import Settings
from perfora.database import DATABASE_SCHEMA_VERSION, AuditStore
from perfora.domain import (
    AnalyzerResult,
    AuditRecord,
    AuditType,
    ComparisonStatus,
    Finding,
    FindingUpdate,
    ModelEnrichment,
    ProviderCatalog,
    ProviderId,
    ProviderSettingsUpdate,
    RepositorySnapshot,
    RulePackMetadata,
    ScanCoverage,
    SecurityStandardReference,
    TriageStatus,
    VerificationOutcome,
)
from perfora.exports import export_evidence_package, export_html, export_sarif
from perfora.findings import FindingService, FindingUpdateError
from perfora.handoffs import TicketHandoffService
from perfora.main import app
from perfora.portfolio import PortfolioService
from perfora.prompts import PromptService
from perfora.provider_settings import (
    ProviderSettingsError,
    ProviderSettingsService,
    normalize_ollama_base_url,
)
from perfora.providers.base import ProviderStructuredOutputError
from perfora.providers.ollama import OllamaAdapter
from perfora.providers.opencode import (
    OpenCodeAdapter,
    _decode_json_object,
    _generation_environment,
    _text_from_json_events,
)
from perfora.repositories import inspect_repository, pick_repository_path
from perfora.security import redact_secrets
from perfora.verifications import VerificationError, VerificationService


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["name"] == "Perfora"


def test_legacy_mutating_fix_routes_are_not_exposed() -> None:
    paths = app.openapi()["paths"]

    assert not any(path.endswith(("/fix", "/apply", "/rollback")) for path in paths)
    assert "patch" in paths["/api/audits/{audit_id}/findings/{finding_id}"]
    assert "/api/audits/{audit_id}/comparison" in paths
    assert "post" in paths["/api/audits/{audit_id}/findings/{finding_id}/verify"]
    assert "/api/portfolio" in paths
    assert "/api/audits/{audit_id}/findings/{finding_id}/ticket-handoff" in paths
    assert "get" in paths["/api/settings/providers"]
    assert "patch" in paths["/api/settings/providers"]


def test_provider_settings_are_write_only_and_preserve_unrelated_local_config(
    tmp_path: Path,
) -> None:
    local_env = tmp_path / ".env.local"
    local_env.write_text("# Local overrides\nUNRELATED_SETTING=keep\n", encoding="utf-8")
    local_settings = Settings(
        database_path=tmp_path / "settings.db",
        local_env_path=local_env,
        openai_api_key=None,
        process_openai_api_key=None,
        ollama_base_url="http://127.0.0.1:11434",
        process_ollama_base_url=None,
    )
    service = ProviderSettingsService(local_settings)
    secret = "sk-test-provider-settings-0123456789"

    snapshot = service.update(
        ProviderSettingsUpdate(
            openai_api_key=secret,
            ollama_base_url="https://ollama.example.test:11434/",
        )
    )

    saved = local_env.read_text(encoding="utf-8")
    assert snapshot.openai.configured is True
    assert snapshot.openai.source == "settings"
    assert snapshot.ollama.base_url == "https://ollama.example.test:11434"
    assert snapshot.ollama.locality == "remote"
    assert secret not in snapshot.model_dump_json()
    assert "UNRELATED_SETTING=keep" in saved
    assert secret in saved
    assert stat.S_IMODE(local_env.stat().st_mode) == 0o600

    cleared = service.update(ProviderSettingsUpdate(clear_openai_api_key=True))

    assert cleared.openai.configured is False
    assert "OPENAI_API_KEY" not in local_env.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "value",
    [
        "file:///tmp/ollama.sock",
        "http://user:password@localhost:11434",
        "http://localhost:11434/api",
        "http://localhost:invalid",
        "http://localhost:11434\nPERFORA_OLLAMA_BASE_URL=https://example.test",
    ],
)
def test_rejects_unsafe_or_ambiguous_ollama_urls(value: str) -> None:
    with pytest.raises(ProviderSettingsError):
        normalize_ollama_base_url(value)


def test_provider_settings_api_never_returns_the_openai_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_settings = Settings(
        database_path=tmp_path / "settings-api.db",
        local_env_path=tmp_path / ".env.local",
        openai_api_key=None,
        process_openai_api_key=None,
        process_ollama_base_url=None,
    )

    class FakeProviders:
        async def catalogs(self):
            return [
                ProviderCatalog(
                    provider=ProviderId.OPENAI,
                    available=True,
                    detail="Mocked provider",
                )
            ]

    monkeypatch.setattr(main_module, "provider_settings", ProviderSettingsService(local_settings))
    monkeypatch.setattr(main_module, "providers", FakeProviders())
    secret = "sk-test-api-response-012345678901"

    client = TestClient(app)
    response = client.patch("/api/settings/providers", json={"openai_api_key": secret})
    status_response = client.get("/api/settings/providers")

    assert response.status_code == 200
    assert response.json()["settings"]["openai"] == {
        "configured": True,
        "source": "settings",
    }
    assert response.json()["providers"][0]["detail"] == "Mocked provider"
    assert secret not in response.text
    assert secret not in status_response.text


@pytest.mark.asyncio
async def test_remote_ollama_endpoint_marks_discovered_models_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"models": [{"name": "qwen2.5-coder:7b"}]}

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url: str):
            assert url == "https://ollama.example.test:11434/api/tags"
            return FakeResponse()

    monkeypatch.setattr("perfora.providers.ollama.httpx.AsyncClient", FakeClient)
    adapter = OllamaAdapter(
        Settings(
            database_path=tmp_path / "ollama.db",
            ollama_base_url="https://ollama.example.test:11434",
        )
    )

    catalog = await adapter.catalog()

    assert catalog.available is True
    assert catalog.models[0].locality == "remote"
    assert catalog.detail == "1 model(s) at remote Ollama endpoint"


def test_runtime_capture_import_list_detail_and_comparison_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: runtime_fixture\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )
    runtime_store = AuditStore(tmp_path / "runtime-api.db")
    monkeypatch.setattr(main_module, "store", runtime_store)
    monkeypatch.setattr(
        main_module,
        "runtime_artifacts",
        main_module.RuntimeArtifactService(runtime_store),
    )
    body = {
        "repository_path": str(tmp_path),
        "filename": "frame_timing.json",
        "content": json.dumps(
            {
                "frame_count": 2,
                "frame_build_times": [5000, 24000],
                "frame_rasterizer_times": [5000, 6000],
            }
        ),
        "build_mode": "profile",
        "flutter_version": "3.35.0",
        "devtools_version": "2.48.0",
    }

    client = TestClient(app)
    imported = client.post("/api/runtime-captures/import", json=body)
    capture_id = imported.json()["id"]
    listed = client.get("/api/runtime-captures", params={"repository_path": str(tmp_path)})
    detail = client.get(f"/api/runtime-captures/{capture_id}")
    comparison = client.get(
        "/api/runtime-captures/compare",
        params={"baseline_id": capture_id, "current_id": capture_id},
    )

    assert imported.status_code == 201
    assert imported.json()["kind"] == "frame_timing"
    assert listed.json()["captures"][0]["id"] == capture_id
    assert detail.json()["provenance"]["flutter_version"] == "3.35.0"
    assert comparison.json()["compatible"] is True


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
        return json.dumps(
            {
                "analyzer_version": "0.3.0",
                "rule_pack": {"id": "security", "version": "1.0.0"},
                "coverage": {
                    "files_discovered": 3,
                    "files_scanned": 2,
                    "files_skipped": 1,
                    "scanned_by_type": {"dart": 2},
                    "skipped_by_reason": {"generated_source": 1},
                    "rules_executed": ["security.hardcoded_secret"],
                    "scanned_files": ["lib/a.dart", "lib/b.dart"],
                    "skipped_files_by_reason": {"generated_source": ["lib/generated.g.dart"]},
                },
                "findings": [],
            }
        )

    monkeypatch.setattr(analyzer_client.shutil, "which", lambda _: "/usr/bin/dart")
    monkeypatch.setattr(analyzer_client, "run_process", analyze)
    client = DartAnalyzerClient(Settings(analyzer_root=analyzer_root))

    result = await client.analyze(repository, AuditType.SECURITY)

    assert result.findings == []
    assert result.analyzer_version == "0.3.0"
    assert result.rule_pack == RulePackMetadata(id="security", version="1.0.0")
    assert result.coverage.files_scanned == 2
    assert captured_command[-2:] == ["--audit-type", "security"]


def test_existing_audit_records_default_to_performance(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    payload = audit.model_dump(exclude={"audit_type"})

    assert AuditRecord.model_validate(payload).audit_type == AuditType.PERFORMANCE


def test_database_migrates_and_loads_a_legacy_audit(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    legacy = _audit(tmp_path).model_dump(
        exclude={"record_version", "analyzer_version", "rule_pack", "scan_coverage"}
    )
    legacy["findings"][0].pop("fingerprint", None)
    legacy["findings"][0].pop("rule_version", None)
    legacy["findings"][0].pop("model_enrichment", None)
    legacy["findings"][0]["model_explanation"] = "Legacy model explanation"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE audits (id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO audits(id, payload, updated_at) VALUES (?, ?, ?)",
            (legacy["id"], json.dumps(legacy, default=str), legacy["updated_at"].isoformat()),
        )

    store = AuditStore(database_path)
    loaded = store.get(legacy["id"])

    assert store.schema_version == DATABASE_SCHEMA_VERSION
    assert loaded is not None
    assert loaded.record_version == 6
    assert loaded.analyzer_version == "unknown"
    assert loaded.findings[0].rule_version == "legacy"
    assert loaded.findings[0].model_enrichment is not None
    assert loaded.findings[0].model_enrichment.explanation == "Legacy model explanation"


def test_exports_evidence_as_html_and_sarif(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    html = export_html(audit)
    sarif = export_sarif(audit)

    assert "Perfora evidence report" in html
    assert "controller.dart:8" in html
    assert '"ruleId": "lifecycle.missing_cleanup"' in sarif
    assert '"auditType": "performance"' in sarif
    assert '"perforaFindingFingerprint": "sha256:fixture"' in sarif
    assert '"triageStatus": "new"' in sarif
    assert '"verificationOutcome": null' in sarif
    assert "<strong>Triage:</strong> new" in html


def test_exports_redacted_checksummed_and_signed_evidence_package(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.findings[0].evidence.append("Authorization: Bearer sk-example012345678901234567890")

    package = export_evidence_package(audit, "organization-signing-key")

    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        assert names == {
            "audit.json",
            "report.html",
            "results.sarif.json",
            "dependencies.cdx.json",
            "manifest.json",
        }
        for name, metadata in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == metadata["sha256"]
        assert b"sk-example" not in archive.read("audit.json")
        assert b"[REDACTED]" in archive.read("audit.json")
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(b"organization-signing-key", payload, hashlib.sha256).hexdigest()
        assert manifest["signature"] == {
            "algorithm": "hmac-sha256",
            "value": expected,
        }


def test_builds_local_portfolio_governance_and_redacted_ticket_handoff(
    tmp_path: Path,
) -> None:
    store = AuditStore(tmp_path / "portfolio.db")
    older = _audit(tmp_path)
    older.id = "older"
    older.created_at = datetime(2026, 8, 1, tzinfo=UTC)
    older.updated_at = older.created_at
    older.findings[0].audit_id = older.id
    store.save(older)

    current = _audit(tmp_path)
    current.id = "current"
    current.created_at = datetime(2026, 8, 17, tzinfo=UTC)
    current.updated_at = current.created_at
    current.findings[0].audit_id = current.id
    current.findings[0].severity = "critical"
    current.findings[0].comparison_status = ComparisonStatus.REGRESSED
    current.findings[0].evidence.append("Authorization: Bearer sk-example012345678901234567890")
    store.save(current)
    failed = _audit(tmp_path)
    failed.id = "failed"
    failed.status = "failed"
    failed.created_at = datetime(2026, 8, 18, tzinfo=UTC)
    failed.updated_at = failed.created_at
    failed.findings = []
    store.save(failed)

    portfolio = PortfolioService(store).summary()
    handoff = TicketHandoffService(store).build(current.id, current.findings[0].id, "jira")

    assert portfolio["totals"]["repositories"] == 1
    assert portfolio["totals"]["audits"] == 3
    assert portfolio["totals"]["open_findings"] == 1
    assert portfolio["totals"]["recurrences"] == 1
    assert portfolio["totals"]["governance_issues"] == 2
    assert portfolio["owners"] == [{"owner": "Unassigned", "open": 1, "overdue": 0}]
    assert handoff["system"] == "jira"
    assert handoff["automatic_creation"] is False
    assert "sha256:fixture" in handoff["body"]
    assert "[REDACTED]" in handoff["body"]
    assert "sk-example" not in handoff["body"]


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
    audit.findings[0].model_enrichment = ModelEnrichment(
        provider=ProviderId.OLLAMA,
        model_id="qwen",
        explanation="The model confirmed the ownership gap.",
        recommendation="Use the existing owner cleanup hook.",
    )
    audit.findings[0].control_group = "MASVS-STORAGE"
    audit.findings[0].platforms = ["Dart", "Android", "iOS"]
    audit.findings[0].standards = [
        SecurityStandardReference(
            id="MASVS-STORAGE-1",
            title="Secure storage of sensitive data",
            url="https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/",
        )
    ]
    audit.findings[0].detection_limitations = ["Static source evidence only."]
    audit.findings[0].manual_verification = ["Inspect the release artifact."]
    audit.findings[0].false_positive_guidance = "Prove the value is not sensitive."
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
    assert "Stable fingerprint: sha256:fixture" in result.prompt
    assert "Rule version: 1.0.0" in result.prompt
    assert "Control group: MASVS-STORAGE" in result.prompt
    assert "Platforms: Dart, Android, iOS" in result.prompt
    assert "MASVS-STORAGE-1: Secure storage of sensitive data" in result.prompt
    assert "Static source evidence only." in result.prompt
    assert "Inspect the release artifact." in result.prompt
    assert "False-positive guidance: Prove the value is not sensitive." in result.prompt
    assert "Triage status: new" in result.prompt
    assert "Baseline audit ID: none" in result.prompt
    assert "No triage notes recorded" in result.prompt
    assert "No deterministic verification attempts recorded" in result.prompt
    assert "Controller is created by the class." in result.prompt
    assert "The controller outlives its owner." in result.prompt
    assert "The model confirmed the ownership gap." in result.prompt
    assert "Use the existing owner cleanup hook." in result.prompt
    assert "Dispose the controller." in result.prompt
    assert "packages/shared" in result.prompt
    assert "class Controller {}" in result.prompt
    assert "[REDACTED]" in result.prompt
    assert "sk-example" not in result.prompt
    assert "Do not commit, push" in result.prompt


def test_finding_fingerprint_is_stable_when_only_the_line_moves() -> None:
    original = {
        "rule_id": "lifecycle.missing_cleanup",
        "file": "lib/controller.dart",
        "line": 8,
        "symbol": "Owner.controller",
        "framework": "Provider",
    }
    moved = {**original, "line": 42}

    original_basis = AuditCoordinator._fingerprint_basis(original)
    moved_basis = AuditCoordinator._fingerprint_basis(moved)

    assert original_basis == moved_basis
    assert AuditCoordinator._fingerprint(original_basis) == AuditCoordinator._fingerprint(
        moved_basis
    )


def test_updates_finding_triage_with_reason_note_and_history(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "triage.db")
    audit = _audit(tmp_path)
    store.save(audit)
    service = FindingService(store)

    with pytest.raises(FindingUpdateError, match="disposition reason"):
        service.update(
            audit.id,
            audit.findings[0].id,
            FindingUpdate(triage_status=TriageStatus.RISK_ACCEPTED),
        )
    with pytest.raises(FindingUpdateError, match="deterministic re-scan"):
        service.update(
            audit.id,
            audit.findings[0].id,
            FindingUpdate(triage_status=TriageStatus.VERIFIED_RESOLVED),
        )

    updated = service.update(
        audit.id,
        audit.findings[0].id,
        FindingUpdate(
            triage_status=TriageStatus.RISK_ACCEPTED,
            owner="Security team",
            disposition_reason="Compensating network control is documented.",
            suppression_expires_at=datetime.now(UTC) + timedelta(days=30),
            note="Review again before release.",
        ),
    )

    assert updated.triage_status == TriageStatus.RISK_ACCEPTED
    assert updated.owner == "Security team"
    assert updated.notes[0].body == "Review again before release."
    assert updated.status_history[0].from_status == TriageStatus.NEW
    assert updated.status_history[0].to_status == TriageStatus.RISK_ACCEPTED


def test_policy_requires_reviewed_suppression_instead_of_manual_risk_acceptance(
    tmp_path: Path,
) -> None:
    (tmp_path / ".perfora.yaml").write_text(
        """version: 2
suppressions:
  require_reason: true
  require_expiry: true
  require_approval: true
"""
    )
    store = AuditStore(tmp_path / "approved-suppression.db")
    audit = _audit(tmp_path)
    store.save(audit)

    with pytest.raises(FindingUpdateError, match="approved suppression"):
        FindingService(store).update(
            audit.id,
            audit.findings[0].id,
            FindingUpdate(
                triage_status=TriageStatus.RISK_ACCEPTED,
                disposition_reason="Requested exception",
            ),
        )


def test_compares_new_unchanged_resolved_regressed_and_severity_changes(
    tmp_path: Path,
) -> None:
    store = AuditStore(tmp_path / "comparison.db")
    older = _audit(tmp_path)
    older.id = "older"
    older.created_at = datetime(2026, 1, 1, tzinfo=UTC)
    older.updated_at = older.created_at
    older.findings[0].id = "older-regressed"
    older.findings[0].audit_id = older.id
    older.findings[0].fingerprint = "sha256:regressed"
    store.save(older)

    baseline = _audit(tmp_path)
    baseline.id = "baseline"
    baseline.created_at = datetime(2026, 1, 2, tzinfo=UTC)
    baseline.updated_at = baseline.created_at
    baseline.findings[0].id = "baseline-same"
    baseline.findings[0].audit_id = baseline.id
    baseline.findings.extend(
        [
            baseline.findings[0].model_copy(
                deep=True,
                update={
                    "id": "baseline-severity",
                    "audit_id": baseline.id,
                    "fingerprint": "sha256:severity",
                    "severity": "medium",
                },
            ),
            baseline.findings[0].model_copy(
                deep=True,
                update={
                    "id": "baseline-resolved",
                    "audit_id": baseline.id,
                    "fingerprint": "sha256:resolved",
                },
            ),
        ]
    )
    store.save(baseline)

    current = _audit(tmp_path)
    current.id = "current"
    current.created_at = datetime(2026, 1, 3, tzinfo=UTC)
    current.updated_at = current.created_at
    current.findings[0].id = "current-same"
    current.findings[0].audit_id = current.id
    current.findings.extend(
        [
            current.findings[0].model_copy(
                deep=True,
                update={
                    "id": "current-severity",
                    "audit_id": current.id,
                    "fingerprint": "sha256:severity",
                    "severity": "critical",
                },
            ),
            current.findings[0].model_copy(
                deep=True,
                update={
                    "id": "current-new",
                    "audit_id": current.id,
                    "fingerprint": "sha256:new",
                },
            ),
            current.findings[0].model_copy(
                deep=True,
                update={
                    "id": "current-regressed",
                    "audit_id": current.id,
                    "fingerprint": "sha256:regressed",
                },
            ),
        ]
    )
    store.save(current)

    comparison = AuditComparisonService(store).compare(current.id, baseline.id)

    assert comparison.unchanged_finding_ids == ["current-same"]
    assert comparison.new_finding_ids == ["current-new"]
    assert comparison.regressed_finding_ids == ["current-regressed"]
    assert comparison.severity_changes[0].finding_id == "current-severity"
    assert comparison.resolved_findings[0].id == "baseline-resolved"


def test_removed_policy_suppression_does_not_leak_into_the_next_audit(
    tmp_path: Path,
) -> None:
    store = AuditStore(tmp_path / "policy-suppression.db")
    previous = _audit(tmp_path)
    previous.id = "previous-policy"
    previous.created_at = datetime(2026, 8, 1, tzinfo=UTC)
    previous.updated_at = previous.created_at
    previous.findings[0].audit_id = previous.id
    previous.findings[0].triage_status = TriageStatus.RISK_ACCEPTED
    previous.findings[0].disposition_reason = "Approved temporary exception"
    previous.findings[0].suppression_expires_at = datetime(2026, 12, 31, tzinfo=UTC)
    previous.findings[0].suppression_policy_managed = True
    previous.findings[0].suppression_approved_by = "Security review board"
    previous.findings[0].suppression_approved_at = date(2026, 8, 1)
    store.save(previous)

    current = _audit(tmp_path)
    current.id = "current-policy"
    current.created_at = datetime(2026, 8, 17, tzinfo=UTC)
    current.updated_at = current.created_at
    current.findings[0].audit_id = current.id

    AuditComparisonService(store).apply_baseline(current)

    assert current.findings[0].triage_status == TriageStatus.NEW
    assert current.findings[0].suppression_approved_by is None
    assert current.findings[0].suppression_expires_at is None


def test_applies_baseline_triage_and_reopens_resolved_findings(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "carry-forward.db")
    baseline = _audit(tmp_path)
    baseline.id = "baseline"
    baseline.created_at = datetime(2026, 1, 1, tzinfo=UTC)
    baseline.updated_at = baseline.created_at
    baseline.findings[0].audit_id = baseline.id
    baseline.findings[0].triage_status = TriageStatus.RESOLVED
    baseline.findings[0].owner = "Mobile platform"
    store.save(baseline)
    current = _audit(tmp_path)
    current.id = "current"
    current.created_at = datetime(2026, 1, 2, tzinfo=UTC)
    current.updated_at = current.created_at
    current.findings[0].audit_id = current.id

    comparison = AuditComparisonService(store).apply_baseline(current)

    assert comparison.baseline_audit_id == baseline.id
    assert current.baseline_audit_id == baseline.id
    assert current.findings[0].owner == "Mobile platform"
    assert current.findings[0].triage_status == TriageStatus.REOPENED
    assert current.findings[0].comparison_status == ComparisonStatus.REGRESSED


@pytest.mark.asyncio
async def test_verification_marks_a_resolved_finding_verified_when_absent(
    tmp_path: Path,
) -> None:
    raw = _raw_finding()
    audit = _audit(tmp_path)
    audit.findings[0].fingerprint = AuditCoordinator._fingerprint(
        AuditCoordinator._fingerprint_basis(raw)
    )
    audit.findings[0].triage_status = TriageStatus.RESOLVED
    source = tmp_path / audit.findings[0].file
    source.parent.mkdir(parents=True)
    source.write_text("class Controller {}\n")
    store = AuditStore(tmp_path / "verification-resolved.db")
    store.save(audit)

    result = await VerificationService(
        store,
        _AnalyzerStub(_verification_result(audit.findings[0].file, [])),
        _repository_inspector(audit.repository),
    ).verify(audit.id, audit.findings[0].id)

    saved = store.get(audit.id)
    assert result.outcome == VerificationOutcome.VERIFIED_RESOLVED
    assert result.rule_executed is True
    assert result.file_scanned is True
    assert saved is not None
    assert saved.findings[0].triage_status == TriageStatus.VERIFIED_RESOLVED
    assert saved.findings[0].verification_attempts[0].id == result.id


@pytest.mark.asyncio
async def test_verification_reopens_a_resolved_finding_that_is_still_present(
    tmp_path: Path,
) -> None:
    raw = _raw_finding()
    audit = _audit(tmp_path)
    audit.findings[0].fingerprint = AuditCoordinator._fingerprint(
        AuditCoordinator._fingerprint_basis(raw)
    )
    audit.findings[0].triage_status = TriageStatus.RESOLVED
    source = tmp_path / audit.findings[0].file
    source.parent.mkdir(parents=True)
    source.write_text("class Controller {}\n")
    store = AuditStore(tmp_path / "verification-present.db")
    store.save(audit)

    result = await VerificationService(
        store,
        _AnalyzerStub(_verification_result(audit.findings[0].file, [raw])),
        _repository_inspector(audit.repository),
    ).verify(audit.id, audit.findings[0].id)

    saved = store.get(audit.id)
    assert result.outcome == VerificationOutcome.STILL_PRESENT
    assert result.observed_line == 8
    assert saved is not None
    assert saved.findings[0].triage_status == TriageStatus.REOPENED
    assert saved.findings[0].status_history[-1].to_status == TriageStatus.REOPENED


@pytest.mark.asyncio
async def test_verification_is_inconclusive_when_the_source_is_skipped(
    tmp_path: Path,
) -> None:
    raw = _raw_finding()
    audit = _audit(tmp_path)
    audit.findings[0].fingerprint = AuditCoordinator._fingerprint(
        AuditCoordinator._fingerprint_basis(raw)
    )
    audit.findings[0].triage_status = TriageStatus.RESOLVED
    source = tmp_path / audit.findings[0].file
    source.parent.mkdir(parents=True)
    source.write_text("class Controller {}\n")
    store = AuditStore(tmp_path / "verification-skipped.db")
    store.save(audit)
    result = AnalyzerResult(
        analyzer_version="0.3.0",
        rule_pack=RulePackMetadata(id="performance", version="1.0.0"),
        coverage=ScanCoverage(
            files_discovered=1,
            files_scanned=0,
            files_skipped=1,
            skipped_by_reason={"generated_source": 1},
            rules_executed=["lifecycle.missing_cleanup"],
            scanned_files=[],
            skipped_files_by_reason={"generated_source": [audit.findings[0].file]},
        ),
    )

    attempt = await VerificationService(
        store,
        _AnalyzerStub(result),
        _repository_inspector(audit.repository),
    ).verify(audit.id, audit.findings[0].id)

    saved = store.get(audit.id)
    assert attempt.outcome == VerificationOutcome.INCONCLUSIVE
    assert "generated source" in attempt.message
    assert saved is not None
    assert saved.findings[0].triage_status == TriageStatus.RESOLVED


@pytest.mark.asyncio
async def test_verification_rejects_legacy_or_unresolved_findings(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.findings[0].fingerprint = ""
    store = AuditStore(tmp_path / "verification-guard.db")
    store.save(audit)
    service = VerificationService(
        store,
        _AnalyzerStub(AnalyzerResult()),
        _repository_inspector(audit.repository),
    )

    with pytest.raises(VerificationError, match="stable fingerprint"):
        await service.verify(audit.id, audit.findings[0].id)


@pytest.mark.asyncio
async def test_model_enrichment_does_not_replace_deterministic_content(tmp_path: Path) -> None:
    raw_finding = {
        "rule_id": "lifecycle.missing_cleanup",
        "rule_version": "1.0.0",
        "title": "Controller is not released",
        "severity": "high",
        "confidence": 0.94,
        "file": "lib/controller.dart",
        "line": 8,
        "symbol": "Owner.controller",
        "framework": "Provider",
        "evidence": ["Controller is owned by the class."],
        "explanation": "Deterministic explanation",
        "recommendation": "Deterministic recommendation",
    }

    class AnalyzerStub:
        async def analyze(self, *_):
            return AnalyzerResult(
                analyzer_version="0.3.0",
                rule_pack=RulePackMetadata(id="performance", version="1.0.0"),
                coverage=ScanCoverage(
                    files_discovered=1,
                    files_scanned=1,
                    scanned_by_type={"dart": 1},
                    rules_executed=["lifecycle.missing_cleanup"],
                    scanned_files=["lib/controller.dart"],
                    skipped_files_by_reason={},
                ),
                findings=[raw_finding],
            )

    class ProviderStub:
        async def generate_json(self, *_):
            return {
                "explanation": "Model explanation",
                "recommendation": "Model recommendation",
            }

    database_path = tmp_path / "audit.db"
    fingerprint = AuditCoordinator._fingerprint(AuditCoordinator._fingerprint_basis(raw_finding))
    (tmp_path / ".perfora.yaml").write_text(
        f"""version: 2
organization: Mobile engineering
suppressions:
  require_reason: true
  require_expiry: true
  require_approval: true
suppress:
  - fingerprint: {fingerprint}
    reason: Approved migration exception
    expires: 2099-01-01
    approved_by: Security review board
    approved_at: 2026-08-17
ownership:
  routes:
    - owner: Mobile platform
      rule_ids: [lifecycle.missing_cleanup]
      due_days: 7
"""
    )
    store = AuditStore(database_path)
    audit = _audit(tmp_path)
    audit.findings = []
    audit.status = "queued"
    store.save(audit)
    coordinator = AuditCoordinator(store, AnalyzerStub(), ProviderStub())

    await coordinator._run(audit.id)
    completed = store.get(audit.id)

    assert completed is not None
    assert completed.findings[0].recommendation == "Deterministic recommendation"
    assert completed.findings[0].model_enrichment is not None
    assert completed.findings[0].model_enrichment.recommendation == "Model recommendation"
    assert completed.organization == "Mobile engineering"
    assert completed.policy_sources == [str(tmp_path / ".perfora.yaml")]
    assert completed.findings[0].owner == "Mobile platform"
    assert completed.findings[0].triage_status == TriageStatus.RISK_ACCEPTED
    assert completed.findings[0].suppression_policy_managed is True
    assert completed.findings[0].suppression_approved_by == "Security review board"
    assert completed.findings[0].status_history[0].to_status == TriageStatus.RISK_ACCEPTED
    assert completed.analyzer_version == "0.3.0"
    assert completed.scan_coverage.files_scanned == 1


class _AnalyzerStub:
    def __init__(self, result: AnalyzerResult):
        self.result = result

    async def analyze(self, *_):
        return self.result


def _repository_inspector(snapshot: RepositorySnapshot):
    async def inspect(_: str) -> RepositorySnapshot:
        return snapshot

    return inspect


def _raw_finding() -> dict:
    return {
        "rule_id": "lifecycle.missing_cleanup",
        "rule_version": "1.0.0",
        "title": "Controller is not released",
        "severity": "high",
        "confidence": 0.94,
        "file": "lib/controller.dart",
        "line": 8,
        "symbol": None,
        "framework": "Provider",
        "evidence": ["Controller is created by the class."],
        "explanation": "The controller outlives its owner.",
        "recommendation": "Dispose the controller.",
    }


def _verification_result(file: str, findings: list[dict]) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_version="0.3.0",
        rule_pack=RulePackMetadata(id="performance", version="1.0.0"),
        coverage=ScanCoverage(
            files_discovered=1,
            files_scanned=1,
            scanned_by_type={"dart": 1},
            rules_executed=["lifecycle.missing_cleanup"],
            scanned_files=[file],
            skipped_files_by_reason={},
        ),
        findings=findings,
    )


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
            fingerprint="sha256:fixture",
            rule_id="lifecycle.missing_cleanup",
            rule_version="1.0.0",
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
