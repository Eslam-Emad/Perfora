from __future__ import annotations

import json
import re
import shlex
import tempfile
from pathlib import Path
from typing import Any

from .database import AuditStore
from .domain import FixApplyRequest, FixApplyResult, FixProposal, ProviderId
from .process import ProcessError, run_process
from .providers import ProviderRegistry
from .security import redact_secrets

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "risk": {"type": "string"},
        "patch": {"type": "string"},
    },
    "required": ["summary", "risk", "patch"],
    "additionalProperties": False,
}
DIFF_PATH = re.compile(r"^diff --git a/(.+) b/(.+)$", re.MULTILINE)
SAFE_COMMANDS = {
    ("dart", "analyze"),
    ("flutter", "analyze"),
    ("flutter", "test"),
}


class FixSafetyError(RuntimeError):
    pass


class FixService:
    def __init__(self, store: AuditStore, providers: ProviderRegistry):
        self.store = store
        self.providers = providers
        self._reverse_patches: dict[str, str] = {}

    async def propose(self, audit_id: str, finding_id: str) -> FixProposal:
        audit = self.store.get(audit_id)
        if not audit:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if not finding:
            raise KeyError(finding_id)
        repository = Path(audit.repository.path).resolve()
        source_path = (repository / finding.file).resolve()
        self._assert_within(repository, source_path)
        source = source_path.read_text(errors="replace")
        if len(source) > 50_000:
            raise FixSafetyError("Source file is too large for v0 patch generation")
        head = await self._head(repository)
        prompt = redact_secrets(
            f"""Generate one minimal unified Git patch for this confirmed Flutter finding.
Modify only {finding.file}. Preserve behavior unrelated to lifecycle cleanup.
Do not add dependencies. The patch must apply to the exact source below.

Finding: {finding.title}
Framework: {finding.framework}
Evidence: {json.dumps(finding.evidence)}
Recommendation: {finding.recommendation}

SOURCE {finding.file}
{source}
"""
        )
        result = await self.providers.generate_json(
            ProviderId(audit.provider), audit.model_id, prompt, FIX_SCHEMA
        )
        patch = result["patch"].strip()
        self._validate_patch(repository, patch, allowed_file=finding.file)
        finding.fix_status = "generated"
        self.store.save(audit)
        return FixProposal(
            finding_id=finding.id,
            audit_id=audit.id,
            summary=result["summary"],
            risk=result["risk"],
            patch=patch,
            expected_head=head,
        )

    async def apply(
        self, audit_id: str, finding_id: str, request: FixApplyRequest
    ) -> FixApplyResult:
        if not request.approved:
            raise FixSafetyError("Explicit approval is required")
        audit = self.store.get(audit_id)
        if not audit:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if not finding:
            raise KeyError(finding_id)
        repository = Path(audit.repository.path).resolve()
        current_head = await self._head(repository)
        if current_head != request.expected_head:
            raise FixSafetyError("Repository HEAD changed after patch generation")
        status = await run_process(["git", "status", "--porcelain"], cwd=repository, timeout=10)
        if status:
            raise FixSafetyError("Apply Fix requires a clean Git worktree")
        self._validate_patch(repository, request.patch, allowed_file=finding.file)
        branch = f"perfora/fix-{finding.id[:8]}"
        await run_process(["git", "switch", "-c", branch], cwd=repository, timeout=15)
        try:
            await self._apply_patch(repository, request.patch, check=True)
            await self._apply_patch(repository, request.patch, check=False)
        except Exception:
            await run_process(["git", "switch", "-"], cwd=repository, timeout=15)
            raise

        diff = await run_process(["git", "diff", "--binary"], cwd=repository, timeout=15)
        self._reverse_patches[finding.id] = diff
        verification = []
        verified = True
        for raw_command in request.verification_commands:
            command = tuple(shlex.split(raw_command))
            if command not in SAFE_COMMANDS:
                raise FixSafetyError(f"Verification command is not approved: {raw_command}")
            try:
                output = await run_process(list(command), cwd=repository, timeout=300)
                verification.append(
                    {"command": raw_command, "passed": True, "output": output[-4000:]}
                )
            except ProcessError as error:
                verified = False
                verification.append(
                    {
                        "command": raw_command,
                        "passed": False,
                        "output": error.output[-4000:],
                    }
                )
        finding.fix_status = "verified" if verified else "applied"
        self.store.save(audit)
        return FixApplyResult(
            finding_id=finding.id,
            branch=branch,
            applied=True,
            verified=verified,
            verification=verification,
            reverse_patch_available=True,
        )

    async def rollback(self, audit_id: str, finding_id: str) -> dict[str, Any]:
        audit = self.store.get(audit_id)
        if not audit:
            raise KeyError(audit_id)
        finding = next((item for item in audit.findings if item.id == finding_id), None)
        if not finding:
            raise KeyError(finding_id)
        repository = Path(audit.repository.path).resolve()
        patch = self._reverse_patches.get(finding.id)
        if not patch:
            raise FixSafetyError("No rollback patch is available in this session")
        with tempfile.NamedTemporaryFile("w", suffix=".patch") as handle:
            handle.write(patch)
            handle.flush()
            await run_process(
                ["git", "apply", "--reverse", handle.name], cwd=repository, timeout=30
            )
        finding.fix_status = "rolled_back"
        self.store.save(audit)
        return {"finding_id": finding.id, "rolled_back": True}

    async def _head(self, repository: Path) -> str:
        return await run_process(["git", "rev-parse", "HEAD"], cwd=repository, timeout=10)

    async def _apply_patch(self, repository: Path, patch: str, *, check: bool) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".patch") as handle:
            handle.write(patch)
            handle.flush()
            command = ["git", "apply"]
            if check:
                command.append("--check")
            command.append(handle.name)
            await run_process(command, cwd=repository, timeout=30)

    def _validate_patch(self, repository: Path, patch: str, *, allowed_file: str) -> None:
        paths = DIFF_PATH.findall(patch)
        if not paths:
            raise FixSafetyError("The generated output is not a unified Git patch")
        if len(paths) != 1:
            raise FixSafetyError("v0 fixes may modify exactly one file")
        for before, after in paths:
            if before != allowed_file or after != allowed_file:
                raise FixSafetyError("Patch modifies a file outside the approved finding")
            self._assert_within(repository, (repository / after).resolve())

    @staticmethod
    def _assert_within(repository: Path, target: Path) -> None:
        try:
            target.relative_to(repository)
        except ValueError:
            raise FixSafetyError("Path escapes the repository") from None
