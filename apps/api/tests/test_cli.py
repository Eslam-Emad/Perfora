import json
import subprocess
from pathlib import Path

import pytest

from perfora import cli
from perfora.analyzer_client import AnalyzerTimeout, AnalyzerUnavailable
from perfora.ci_report import export_ci_sarif
from perfora.domain import AnalyzerResult, AuditType
from perfora.fingerprints import assign_fingerprints
from perfora.policy import PolicyError, RepositoryPolicy, load_policy, policy_sources


def _finding(*, file: str, symbol: str, severity: str = "high") -> dict:
    return {
        "rule_id": "security.insecure_transport",
        "rule_version": "1.0.0",
        "title": "Cleartext endpoint",
        "severity": severity,
        "confidence": 0.98,
        "file": file,
        "line": 4,
        "symbol": symbol,
        "framework": "Dart",
        "evidence": ["A cleartext URL is embedded in source."],
        "explanation": "Traffic is not encrypted.",
        "recommendation": "Use HTTPS.",
    }


def _analysis(*findings: dict) -> list[tuple[AuditType, AnalyzerResult]]:
    return [(AuditType.SECURITY, AnalyzerResult(findings=list(findings)))]


def test_loads_strict_repository_policy_and_rejects_undocumented_fields(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / ".perfora.yaml"
    policy_path.write_text(
        """version: 1
audit:
  types: [security]
policy:
  fail_on:
    severity: critical
    only_new: false
include: [lib/**]
exclude: ['**/*.g.dart']
"""
    )

    policy = load_policy(policy_path)

    assert policy.audit.types == [AuditType.SECURITY]
    assert policy.policy.fail_on.severity == "critical"
    assert policy.include == ["lib/**"]

    policy_path.write_text("version: 1\nunknown: true\n")
    with pytest.raises(PolicyError, match="Extra inputs are not permitted"):
        load_policy(policy_path)


def test_policy_requires_suppression_reason_and_expiry(tmp_path: Path) -> None:
    fingerprint = assign_fingerprints([_finding(file="lib/a.dart", symbol="api")])[0]["fingerprint"]
    policy_path = tmp_path / ".perfora.yaml"
    policy_path.write_text(f"version: 1\nsuppress:\n  - fingerprint: {fingerprint}\n")

    with pytest.raises(PolicyError, match="requires a non-empty reason"):
        load_policy(policy_path)


def test_layers_local_policy_packs_with_ownership_and_approved_suppressions(
    tmp_path: Path,
) -> None:
    fingerprint = assign_fingerprints(
        [{**_finding(file="lib/a.dart", symbol="api"), "audit_type": "security"}]
    )[0]["fingerprint"]
    shared = tmp_path / "mobile-security.yaml"
    shared.write_text(
        f"""version: 2
organization: Mobile engineering
exclude: [build/**]
policy:
  fail_on:
    severity: high
    only_new: false
suppressions:
  require_reason: true
  require_expiry: true
  require_approval: true
suppress:
  - fingerprint: {fingerprint}
    reason: Migration exception approved by the security team.
    expires: 2099-01-01
    approved_by: Security review board
    approved_at: 2026-08-17
ownership:
  require_owner_for: [high, critical]
  require_due_date_for: [critical]
  routes:
    - owner: Application security
      control_groups: [network-security]
      due_days: 14
"""
    )
    repository_policy = tmp_path / ".perfora.yaml"
    repository_policy.write_text(
        """version: 2
extends: [mobile-security.yaml]
exclude: ['**/*.g.dart']
policy:
  fail_on:
    severity: critical
    only_new: true
suppressions:
  require_reason: false
  require_expiry: false
  require_approval: false
"""
    )

    policy = load_policy(repository_policy)
    finding = _finding(file="lib/a.dart", symbol="api")
    finding["control_group"] = "network-security"
    policy.assign_ownership(finding)

    assert policy.organization == "Mobile engineering"
    assert policy.exclude == ["build/**", "**/*.g.dart"]
    assert policy.suppress[0].approved_by == "Security review board"
    assert policy.policy.fail_on.severity == "high"
    assert policy.policy.fail_on.only_new is False
    assert policy.suppressions.require_approval is True
    assert finding["owner"] == "Application security"
    assert finding["due_at"] is not None
    assert policy.governance_violations(finding) == []
    assert policy_sources(policy) == [str(shared), str(repository_policy)]


def test_report_classifies_baseline_and_gates_only_new_findings(tmp_path: Path) -> None:
    existing = _finding(file="lib/existing.dart", symbol="existing")
    introduced = _finding(file="lib/new.dart", symbol="new", severity="critical")

    report = cli._build_report(
        repository=tmp_path,
        current=_analysis(existing, introduced),
        baseline=_analysis(existing),
        baseline_ref="origin/main",
        baseline_commit="abc123",
        include_paths=["lib/**"],
        exclude_paths=["**/*.g.dart"],
        severity="high",
        only_new=True,
        policy=RepositoryPolicy(),
        config_path=None,
    )

    assert report["summary"] == {
        "total": 2,
        "new": 1,
        "unchanged": 1,
        "resolved": 0,
        "suppressed": 0,
        "policy_violations": 1,
        "severity_violations": 1,
        "governance_violations": 0,
    }
    assert {item["baseline_status"] for item in report["findings"]} == {
        "new",
        "unchanged",
    }
    sarif = json.loads(export_ci_sarif(report))
    results = sarif["runs"][0]["results"]
    assert {result["baselineState"] for result in results} == {"new", "unchanged"}
    assert all("perforaFindingFingerprint" in item["partialFingerprints"] for item in results)
    assert all(
        not item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("/")
        for item in results
    )


def test_repository_suppression_removes_finding_from_gate(tmp_path: Path) -> None:
    finding = _finding(file="lib/new.dart", symbol="new", severity="critical")
    fingerprint = assign_fingerprints([{**finding, "audit_type": "security"}])[0]["fingerprint"]
    policy = RepositoryPolicy.model_validate(
        {
            "suppress": [
                {
                    "fingerprint": fingerprint,
                    "reason": "Accepted until the service migration completes.",
                    "expires": "2099-01-01",
                }
            ]
        }
    )

    report = cli._build_report(
        repository=tmp_path,
        current=_analysis(finding),
        baseline=[],
        baseline_ref=None,
        baseline_commit=None,
        include_paths=[],
        exclude_paths=[],
        severity="high",
        only_new=True,
        policy=policy,
        config_path=None,
    )

    assert report["findings"][0]["suppressed"] is True
    assert report["summary"]["policy_violations"] == 0


def test_archives_baseline_without_mutating_current_worktree(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@perfora.local"], cwd=repository, check=True
    )
    subprocess.run(["git", "config", "user.name", "Perfora Test"], cwd=repository, check=True)
    source = repository / "lib" / "app.dart"
    source.parent.mkdir()
    source.write_text("const endpoint = 'https://example.test';\n")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)
    source.write_text("const endpoint = 'http://example.test';\n")

    with cli.archived_git_ref(repository, "HEAD") as (baseline, commit):
        assert len(commit) == 40
        assert "https://" in (baseline / "lib" / "app.dart").read_text()
        assert "http://" in source.read_text()


def test_cli_has_stable_policy_exit_and_never_requires_a_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )
    output = tmp_path / "audit.json"

    async def analyze(_self, _repository, _audit_type, **_kwargs):
        return AnalyzerResult(findings=[_finding(file="lib/app.dart", symbol="endpoint")])

    monkeypatch.setattr(cli.DartAnalyzerClient, "analyze", analyze)

    result = cli.run_cli(
        [
            "audit",
            "--repository",
            str(tmp_path),
            "--type",
            "security",
            "--deterministic-only",
            "--fail-on",
            "new-high",
            "--output",
            str(output),
        ]
    )

    assert result == cli.EXIT_POLICY_VIOLATION
    report = json.loads(output.read_text())
    assert report["tool"]["mode"] == "deterministic"
    assert report["summary"]["policy_violations"] == 1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (AnalyzerUnavailable("missing analyzer"), cli.EXIT_ANALYZER_FAILURE),
        (AnalyzerTimeout("timed out"), cli.EXIT_TIMEOUT),
    ],
)
def test_cli_maps_analyzer_failures_to_stable_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected: int,
) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )

    async def analyze(_self, _repository, _audit_type, **_kwargs):
        raise error

    monkeypatch.setattr(cli.DartAnalyzerClient, "analyze", analyze)

    result = cli.run_cli(["audit", "--repository", str(tmp_path), "--type", "security"])

    assert result == expected


def test_cli_maps_invalid_policy_and_baseline_to_stable_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )
    policy_path = tmp_path / ".perfora.yaml"
    policy_path.write_text("version: 3\n")

    assert (
        cli.run_cli(["audit", "--repository", str(tmp_path), "--type", "security"])
        == cli.EXIT_USAGE_OR_CONFIG
    )

    policy_path.unlink()

    async def analyze(_self, _repository, _audit_type, **_kwargs):
        return AnalyzerResult()

    monkeypatch.setattr(cli.DartAnalyzerClient, "analyze", analyze)
    assert (
        cli.run_cli(
            [
                "audit",
                "--repository",
                str(tmp_path),
                "--type",
                "security",
                "--baseline",
                "origin/main",
            ]
        )
        == cli.EXIT_BASELINE_FAILURE
    )


def test_cli_can_disable_the_gate_explicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: fixture\ndependencies:\n  flutter:\n    sdk: flutter\n"
    )

    async def analyze(_self, _repository, _audit_type, **_kwargs):
        return AnalyzerResult(
            findings=[_finding(file="lib/app.dart", symbol="endpoint", severity="critical")]
        )

    monkeypatch.setattr(cli.DartAnalyzerClient, "analyze", analyze)

    result = cli.run_cli(
        [
            "audit",
            "--repository",
            str(tmp_path),
            "--type",
            "security",
            "--fail-on",
            "none",
            "--output",
            str(tmp_path / "report.json"),
        ]
    )

    assert result == cli.EXIT_SUCCESS
