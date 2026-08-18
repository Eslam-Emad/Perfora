from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .domain import AuditType

Severity = Literal["low", "medium", "high", "critical"]


class PolicyError(ValueError):
    pass


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuditSelection(_StrictModel):
    types: list[AuditType] = Field(
        default_factory=lambda: [AuditType.SECURITY, AuditType.PERFORMANCE],
        min_length=1,
    )


class FailOnPolicy(_StrictModel):
    severity: Severity | None = "high"
    only_new: bool = True


class GatePolicy(_StrictModel):
    fail_on: FailOnPolicy = Field(default_factory=FailOnPolicy)


class SuppressionRequirements(_StrictModel):
    require_reason: bool = True
    require_expiry: bool = True
    require_approval: bool = False


class Suppression(_StrictModel):
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=1000)
    expires: date | None = None
    approved_by: str | None = Field(default=None, max_length=200)
    approved_at: date | None = None
    ticket_url: str | None = Field(default=None, max_length=1000)


class OwnershipRoute(_StrictModel):
    owner: str = Field(min_length=1, max_length=200)
    rule_ids: list[str] = Field(default_factory=list)
    control_groups: list[str] = Field(default_factory=list)
    severities: list[Severity] = Field(default_factory=list)
    due_days: int | None = Field(default=None, ge=0, le=3650)

    def matches(self, finding: dict) -> bool:
        selectors = (
            not self.rule_ids or finding.get("rule_id") in self.rule_ids,
            not self.control_groups or finding.get("control_group") in self.control_groups,
            not self.severities or finding.get("severity") in self.severities,
        )
        return all(selectors)


class OwnershipPolicy(_StrictModel):
    routes: list[OwnershipRoute] = Field(default_factory=list)
    require_owner_for: list[Severity] = Field(default_factory=list)
    require_due_date_for: list[Severity] = Field(default_factory=list)


class RepositoryPolicy(_StrictModel):
    version: Literal[1, 2] = 1
    extends: list[str] = Field(default_factory=list)
    organization: str | None = Field(default=None, max_length=200)
    audit: AuditSelection = Field(default_factory=AuditSelection)
    policy: GatePolicy = Field(default_factory=GatePolicy)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    suppressions: SuppressionRequirements = Field(default_factory=SuppressionRequirements)
    suppress: list[Suppression] = Field(default_factory=list)
    ownership: OwnershipPolicy = Field(default_factory=OwnershipPolicy)

    @model_validator(mode="after")
    def validate_suppressions(self) -> RepositoryPolicy:
        seen: set[str] = set()
        for suppression in self.suppress:
            if suppression.fingerprint in seen:
                raise ValueError(f"duplicate suppression for {suppression.fingerprint}")
            seen.add(suppression.fingerprint)
            if self.suppressions.require_reason and not (suppression.reason or "").strip():
                raise ValueError(
                    f"suppression {suppression.fingerprint} requires a non-empty reason"
                )
            if self.suppressions.require_expiry and suppression.expires is None:
                raise ValueError(f"suppression {suppression.fingerprint} requires an expiry")
            if self.suppressions.require_approval and not (
                (suppression.approved_by or "").strip() and suppression.approved_at
            ):
                raise ValueError(
                    f"suppression {suppression.fingerprint} requires approved_by and approved_at"
                )
        return self

    def assign_ownership(self, finding: dict, today: date | None = None) -> None:
        for route in self.ownership.routes:
            if not route.matches(finding):
                continue
            finding["owner"] = route.owner
            finding["due_at"] = (
                ((today or datetime.now(UTC).date()) + timedelta(days=route.due_days)).isoformat()
                if route.due_days is not None
                else None
            )
            return
        finding["owner"] = None
        finding["due_at"] = None

    def governance_violations(self, finding: dict) -> list[str]:
        violations = []
        severity = finding.get("severity")
        if severity in self.ownership.require_owner_for and not finding.get("owner"):
            violations.append("owner_required")
        if severity in self.ownership.require_due_date_for and not finding.get("due_at"):
            violations.append("due_date_required")
        return violations


def load_policy(path: Path | None) -> RepositoryPolicy:
    if path is None or not path.exists():
        return RepositoryPolicy()
    raw, sources = _load_policy_layers(path.resolve(), ())
    try:
        policy = RepositoryPolicy.model_validate(raw)
    except ValidationError as error:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in error.errors()
        )
        raise PolicyError(f"Invalid policy {path}: {details}") from error
    policy.__dict__["_sources"] = [str(source) for source in sources]
    return policy


def policy_sources(policy: RepositoryPolicy) -> list[str]:
    return list(policy.__dict__.get("_sources", []))


def _load_policy_layers(path: Path, stack: tuple[Path, ...]) -> tuple[dict, list[Path]]:
    if path in stack:
        cycle = " -> ".join(str(item) for item in (*stack, path))
        raise PolicyError(f"Policy inheritance cycle: {cycle}")
    if not path.is_file():
        raise PolicyError(f"Policy path is not a file: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise PolicyError(f"Could not read policy {path}: {error}") from error
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"Policy {path} must contain a YAML mapping")
    parents = raw.get("extends", [])
    if isinstance(parents, str):
        parents = [parents]
    if not isinstance(parents, list) or not all(isinstance(item, str) for item in parents):
        raise PolicyError(f"Invalid policy {path}: extends must be a list of local paths")

    merged: dict = {}
    sources: list[Path] = []
    for parent in parents:
        if "://" in parent:
            raise PolicyError(f"Invalid policy {path}: remote policy packs are not supported")
        parent_path = Path(parent).expanduser()
        if not parent_path.is_absolute():
            parent_path = path.parent / parent_path
        parent_raw, parent_sources = _load_policy_layers(parent_path.resolve(), (*stack, path))
        merged = _merge_policy(merged, parent_raw)
        for source in parent_sources:
            if source not in sources:
                sources.append(source)
    child = dict(raw)
    child["extends"] = parents
    merged = _merge_policy(merged, child)
    sources.append(path)
    return merged, sources


def _merge_policy(base: dict, overlay: dict, prefix: tuple[str, ...] = ()) -> dict:
    merged = dict(base)
    additive_lists = {("exclude",), ("suppress",), ("ownership", "routes")}
    union_lists = {
        ("audit", "types"),
        ("ownership", "require_owner_for"),
        ("ownership", "require_due_date_for"),
    }
    sticky_requirements = {
        ("suppressions", "require_reason"),
        ("suppressions", "require_expiry"),
        ("suppressions", "require_approval"),
    }
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for key, value in overlay.items():
        route = (*prefix, key)
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _merge_policy(existing, value, route)
        elif route in additive_lists and isinstance(existing, list) and isinstance(value, list):
            merged[key] = [*existing, *value]
        elif route in union_lists and isinstance(existing, list) and isinstance(value, list):
            merged[key] = list(dict.fromkeys([*existing, *value]))
        elif (
            route in sticky_requirements and isinstance(existing, bool) and isinstance(value, bool)
        ):
            merged[key] = existing or value
        elif route == ("policy", "fail_on", "severity") and existing is not None:
            merged[key] = (
                existing
                if value is None or severity_order[existing] <= severity_order[value]
                else value
            )
        elif route == ("policy", "fail_on", "only_new") and isinstance(existing, bool):
            merged[key] = existing and bool(value)
        else:
            merged[key] = value
    return merged
