from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .analyzer_client import AnalyzerTimeout, AnalyzerUnavailable, DartAnalyzerClient
from .ci_report import export_ci_markdown, render_ci_report
from .config import settings
from .domain import AnalyzerResult, AuditType, DependencyInventory
from .fingerprints import assign_fingerprints
from .policy import PolicyError, RepositoryPolicy, Severity, load_policy, policy_sources
from .repositories import inspect_repository
from .supply_chain import compare_dependencies, inventory_dependencies

EXIT_SUCCESS = 0
EXIT_POLICY_VIOLATION = 1
EXIT_USAGE_OR_CONFIG = 2
EXIT_ANALYZER_FAILURE = 3
EXIT_BASELINE_FAILURE = 4
EXIT_TIMEOUT = 5

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class BaselineError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="perfora", description="Deterministic Flutter audits")
    parser.add_argument("--version", action="version", version=f"Perfora {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="Run deterministic repository checks")
    audit.add_argument("--repository", default=".", help="Flutter repository or package path")
    audit.add_argument(
        "--type",
        dest="audit_types",
        action="append",
        choices=[item.value for item in AuditType],
        help="Rule pack to run; repeat to run both (defaults to policy)",
    )
    audit.add_argument("--baseline", help="Git commit or ref used to classify new findings")
    audit.add_argument("--config", help="Policy path (defaults to <repository>/.perfora.yaml)")
    audit.add_argument("--include", action="append", help="Include glob; repeat as needed")
    audit.add_argument("--exclude", action="append", help="Exclude glob; repeat as needed")
    audit.add_argument(
        "--format",
        dest="output_format",
        choices=["json", "html", "sarif", "cyclonedx"],
        default="json",
    )
    audit.add_argument("--output", help="Artifact path; defaults to stdout")
    audit.add_argument("--summary", help="Write a Markdown CI/job summary")
    audit.add_argument(
        "--fail-on",
        choices=[
            "none",
            "low",
            "medium",
            "high",
            "critical",
            "new-low",
            "new-medium",
            "new-high",
            "new-critical",
        ],
        help="Override the repository severity gate, for example new-high",
    )
    new_only = audit.add_mutually_exclusive_group()
    new_only.add_argument("--new-only", action="store_true", default=None)
    new_only.add_argument("--all-findings", action="store_false", dest="new_only")
    audit.add_argument(
        "--timeout", type=float, default=120, help="Seconds allowed per analyzer run"
    )
    audit.add_argument(
        "--deterministic-only",
        action="store_true",
        help="Explicitly assert analyzer-only mode (the CLI never invokes a model provider)",
    )
    return parser


def main() -> None:
    raise SystemExit(run_cli())


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    try:
        return asyncio.run(_run_audit(args))
    except PolicyError as error:
        print(f"Perfora configuration error: {error}", file=sys.stderr)
        return EXIT_USAGE_OR_CONFIG
    except BaselineError as error:
        print(f"Perfora baseline error: {error}", file=sys.stderr)
        return EXIT_BASELINE_FAILURE
    except AnalyzerTimeout as error:
        print(f"Perfora analyzer timeout: {error}", file=sys.stderr)
        return EXIT_TIMEOUT
    except AnalyzerUnavailable as error:
        print(f"Perfora analyzer error: {error}", file=sys.stderr)
        return EXIT_ANALYZER_FAILURE
    except OSError as error:
        print(f"Perfora file error: {error}", file=sys.stderr)
        return EXIT_USAGE_OR_CONFIG


async def _run_audit(args: argparse.Namespace) -> int:
    repository = Path(args.repository).expanduser().resolve()
    if not repository.is_dir():
        raise PolicyError(f"Repository does not exist or is not a directory: {repository}")
    snapshot = await inspect_repository(str(repository))
    if not snapshot.valid:
        raise PolicyError(snapshot.detail)
    policy_path = (
        Path(args.config).expanduser().resolve() if args.config else repository / ".perfora.yaml"
    )
    policy = load_policy(policy_path)
    audit_types = (
        [AuditType(item) for item in args.audit_types] if args.audit_types else policy.audit.types
    )
    include_paths = args.include if args.include is not None else policy.include
    exclude_paths = [*policy.exclude, *(args.exclude or [])]
    severity, only_new = _gate(args, policy)

    analyzer = DartAnalyzerClient(settings)
    current = await _analyze_all(
        analyzer,
        repository,
        audit_types,
        include_paths,
        exclude_paths,
        args.timeout,
    )
    current_inventory = inventory_dependencies(repository)
    baseline_results: list[tuple[AuditType, AnalyzerResult]] = []
    baseline_inventory = DependencyInventory()
    baseline_commit: str | None = None
    if args.baseline:
        with archived_git_ref(repository, args.baseline) as (baseline_root, baseline_commit):
            baseline_results = await _analyze_all(
                analyzer,
                baseline_root,
                audit_types,
                include_paths,
                exclude_paths,
                args.timeout,
            )
            baseline_inventory = inventory_dependencies(baseline_root)

    report = _build_report(
        repository=repository,
        current=current,
        baseline=baseline_results,
        baseline_ref=args.baseline,
        baseline_commit=baseline_commit,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
        severity=severity,
        only_new=only_new,
        policy=policy,
        config_path=policy_path if policy_path.exists() else None,
        current_inventory=current_inventory,
        baseline_inventory=baseline_inventory,
    )
    artifact = render_ci_report(report, args.output_format)
    _write_or_print(artifact, args.output)
    if args.summary:
        _write_text(Path(args.summary), export_ci_markdown(report))

    summary = report["summary"]
    print(
        f"Perfora found {summary['total']} finding(s); "
        f"{summary['policy_violations']} violate the configured gate.",
        file=sys.stderr,
    )
    return EXIT_POLICY_VIOLATION if summary["policy_violations"] else EXIT_SUCCESS


async def _analyze_all(
    analyzer: DartAnalyzerClient,
    repository: Path,
    audit_types: list[AuditType],
    include_paths: list[str],
    exclude_paths: list[str],
    timeout: float,
) -> list[tuple[AuditType, AnalyzerResult]]:
    results = []
    for audit_type in audit_types:
        result = await analyzer.analyze(
            repository,
            audit_type,
            include_paths=include_paths,
            exclude_paths=exclude_paths,
            timeout_seconds=timeout,
        )
        results.append((audit_type, result))
    return results


def _gate(args: argparse.Namespace, policy: RepositoryPolicy) -> tuple[Severity | None, bool]:
    severity = policy.policy.fail_on.severity
    only_new = policy.policy.fail_on.only_new
    if args.fail_on:
        if args.fail_on == "none":
            severity = None
        elif args.fail_on.startswith("new-"):
            severity = args.fail_on.removeprefix("new-")
            only_new = True
        else:
            severity = args.fail_on
            only_new = False
    if args.new_only is not None:
        only_new = args.new_only
    return severity, only_new


def _build_report(
    *,
    repository: Path,
    current: list[tuple[AuditType, AnalyzerResult]],
    baseline: list[tuple[AuditType, AnalyzerResult]],
    baseline_ref: str | None,
    baseline_commit: str | None,
    include_paths: list[str],
    exclude_paths: list[str],
    severity: Severity | None,
    only_new: bool,
    policy: RepositoryPolicy,
    config_path: Path | None,
    current_inventory: DependencyInventory | None = None,
    baseline_inventory: DependencyInventory | None = None,
) -> dict:
    current_inventory = current_inventory or DependencyInventory()
    baseline_inventory = baseline_inventory or DependencyInventory()
    current_findings = _flatten_findings(current)
    baseline_findings = _flatten_findings(baseline)
    baseline_by_fingerprint = {item["fingerprint"]: item for item in baseline_findings}
    current_fingerprints = {item["fingerprint"] for item in current_findings}
    suppressions = {item.fingerprint: item for item in policy.suppress}

    for finding in current_findings:
        previous = baseline_by_fingerprint.get(finding["fingerprint"])
        finding["baseline_status"] = "unchanged" if previous else "new"
        finding["baseline_severity"] = previous["severity"] if previous else None
        suppression = suppressions.get(finding["fingerprint"])
        active = suppression is not None and (
            suppression.expires is None or suppression.expires >= datetime.now(UTC).date()
        )
        finding["suppressed"] = active
        finding["suppression_reason"] = suppression.reason if active else None
        finding["suppression_expires"] = (
            suppression.expires.isoformat() if active and suppression.expires else None
        )
        finding["suppression_policy_managed"] = active
        finding["suppression_approved_by"] = suppression.approved_by if active else None
        finding["suppression_approved_at"] = (
            suppression.approved_at.isoformat() if active and suppression.approved_at else None
        )
        finding["suppression_ticket_url"] = suppression.ticket_url if active else None
        policy.assign_ownership(finding)
        finding["governance_violations"] = policy.governance_violations(finding)

    resolved = []
    for finding in baseline_findings:
        if finding["fingerprint"] not in current_fingerprints:
            resolved.append(
                {
                    **finding,
                    "baseline_status": "absent",
                    "baseline_severity": finding["severity"],
                    "suppressed": False,
                    "suppression_reason": None,
                    "suppression_expires": None,
                    "suppression_policy_managed": False,
                    "suppression_approved_by": None,
                    "suppression_approved_at": None,
                    "suppression_ticket_url": None,
                    "owner": None,
                    "due_at": None,
                    "governance_violations": [],
                }
            )

    violations = [
        finding
        for finding in current_findings
        if severity is not None
        and not finding["suppressed"]
        and _SEVERITY_ORDER[finding["severity"]] >= _SEVERITY_ORDER[severity]
        and (not only_new or finding["baseline_status"] == "new")
    ]
    governance_violations = [
        finding for finding in current_findings if finding["governance_violations"]
    ]
    violating_fingerprints = {
        finding["fingerprint"] for finding in [*violations, *governance_violations]
    }
    commit = _git_output(repository, ["rev-parse", "HEAD"], required=False)
    analyses = [
        {
            "audit_type": audit_type.value,
            "analyzer_version": result.analyzer_version,
            "rule_pack": result.rule_pack.model_dump(mode="json"),
            "coverage": result.coverage.model_dump(mode="json"),
        }
        for audit_type, result in current
    ]
    dependency_changes = compare_dependencies(current_inventory, baseline_inventory)
    return {
        "schema_version": 1,
        "tool": {"name": "Perfora", "version": __version__, "mode": "deterministic"},
        "generated_at": datetime.now(UTC).isoformat(),
        "repository": {
            "name": repository.name,
            "path": str(repository),
            "commit": commit,
            "baseline_ref": baseline_ref,
            "baseline_commit": baseline_commit,
        },
        "audit_types": [item.value for item, _ in current],
        "policy": {
            "config": str(config_path) if config_path else None,
            "sources": policy_sources(policy),
            "organization": policy.organization,
            "severity": severity,
            "only_new": only_new,
            "include": include_paths,
            "exclude": exclude_paths,
        },
        "analyses": analyses,
        "dependency_inventory": current_inventory.model_dump(mode="json"),
        "dependency_changes": dependency_changes.model_dump(mode="json"),
        "summary": {
            "total": len(current_findings),
            "new": sum(item["baseline_status"] == "new" for item in current_findings),
            "unchanged": sum(item["baseline_status"] == "unchanged" for item in current_findings),
            "resolved": len(resolved),
            "suppressed": sum(item["suppressed"] for item in current_findings),
            "policy_violations": len(violating_fingerprints),
            "severity_violations": len(violations),
            "governance_violations": len(governance_violations),
        },
        "findings": current_findings,
        "resolved_findings": resolved,
    }


def _flatten_findings(results: list[tuple[AuditType, AnalyzerResult]]) -> list[dict]:
    raw = []
    for audit_type, result in results:
        raw.extend({**finding, "audit_type": audit_type.value} for finding in result.findings)
    return assign_fingerprints(raw)


@contextmanager
def archived_git_ref(repository: Path, git_ref: str) -> Iterator[tuple[Path, str]]:
    git_root_text = _git_output(repository, ["rev-parse", "--show-toplevel"], required=True)
    assert git_root_text is not None
    git_root = Path(git_root_text).resolve()
    try:
        relative_repository = repository.relative_to(git_root)
    except ValueError as error:
        raise BaselineError(f"Repository is outside Git root {git_root}") from error
    commit = _git_output(repository, ["rev-parse", "--verify", f"{git_ref}^{{commit}}"], True)
    assert commit is not None
    with tempfile.TemporaryDirectory(prefix="perfora-baseline-") as temporary:
        temporary_path = Path(temporary)
        archive_path = temporary_path / "repository.tar"
        completed = subprocess.run(
            ["git", "archive", "--format=tar", "--output", str(archive_path), commit],
            cwd=git_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip()
            raise BaselineError(f"Could not archive {git_ref}: {detail}")
        extracted = temporary_path / "worktree"
        extracted.mkdir()
        try:
            with tarfile.open(archive_path) as archive:
                archive.extractall(extracted, filter="data")
        except (OSError, tarfile.TarError) as error:
            raise BaselineError(f"Could not extract baseline {git_ref}: {error}") from error
        baseline_root = extracted / relative_repository
        if not baseline_root.is_dir():
            raise BaselineError(
                f"Selected repository path {relative_repository} does not exist at {git_ref}"
            )
        yield baseline_root, commit


def _git_output(repository: Path, arguments: list[str], required: bool) -> str | None:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        if required:
            detail = (completed.stderr or completed.stdout).strip()
            raise BaselineError(detail or f"git {' '.join(arguments)} failed")
        return None
    return completed.stdout.strip() or None


def _write_or_print(content: str, output: str | None) -> None:
    if not output or output == "-":
        print(content)
        return
    _write_text(Path(output), content + ("\n" if not content.endswith("\n") else ""))


def _write_text(path: Path, content: str) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
