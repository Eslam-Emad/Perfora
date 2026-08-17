from __future__ import annotations

import json
import shutil
from pathlib import Path

from .config import Settings
from .domain import AnalyzerResult, AuditType
from .process import ProcessError, run_process


class AnalyzerUnavailable(RuntimeError):
    pass


class AnalyzerTimeout(AnalyzerUnavailable):
    pass


class DartAnalyzerClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def analyze(
        self,
        repository: Path,
        audit_type: AuditType,
        *,
        include_paths: list[str] | None = None,
        exclude_paths: list[str] | None = None,
        timeout_seconds: float = 120,
    ) -> AnalyzerResult:
        dart = shutil.which("dart")
        if not dart:
            raise AnalyzerUnavailable("Dart SDK was not found")
        if not (self.settings.analyzer_root / ".dart_tool" / "package_config.json").exists():
            raise AnalyzerUnavailable(
                "Perfora analyzer dependencies are not installed; run dart pub get"
            )
        try:
            command = [
                dart,
                "run",
                "bin/perfora_analyzer.dart",
                "--root",
                str(repository),
                "--audit-type",
                audit_type.value,
            ]
            for pattern in include_paths or []:
                command.extend(["--include", pattern])
            for pattern in exclude_paths or []:
                command.extend(["--exclude", pattern])
            output = await run_process(
                command,
                cwd=self.settings.analyzer_root,
                timeout=timeout_seconds,
                env={"CI": "true"},
            )
        except ProcessError as error:
            if error.returncode == -1:
                raise AnalyzerTimeout(error.output or str(error)) from error
            raise AnalyzerUnavailable(error.output or str(error)) from error
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as error:
            raise AnalyzerUnavailable("Analyzer returned malformed JSON") from error
        if isinstance(payload, list):
            return AnalyzerResult(findings=payload)
        try:
            return AnalyzerResult.model_validate(payload)
        except (TypeError, ValueError) as error:
            raise AnalyzerUnavailable("Analyzer returned an unexpected payload") from error
