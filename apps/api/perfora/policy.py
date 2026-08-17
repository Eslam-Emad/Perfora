from __future__ import annotations

from datetime import date
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


class Suppression(_StrictModel):
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=1000)
    expires: date | None = None


class RepositoryPolicy(_StrictModel):
    version: Literal[1] = 1
    audit: AuditSelection = Field(default_factory=AuditSelection)
    policy: GatePolicy = Field(default_factory=GatePolicy)
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    suppressions: SuppressionRequirements = Field(default_factory=SuppressionRequirements)
    suppress: list[Suppression] = Field(default_factory=list)

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
        return self


def load_policy(path: Path | None) -> RepositoryPolicy:
    if path is None or not path.exists():
        return RepositoryPolicy()
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
    try:
        return RepositoryPolicy.model_validate(raw)
    except ValidationError as error:
        details = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in error.errors()
        )
        raise PolicyError(f"Invalid policy {path}: {details}") from error
