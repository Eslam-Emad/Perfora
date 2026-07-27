from __future__ import annotations

import json
import shutil
from pathlib import Path

from .config import Settings
from .process import ProcessError, run_process


class AnalyzerUnavailable(RuntimeError):
    pass


class DartAnalyzerClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def analyze(self, repository: Path) -> list[dict]:
        dart = shutil.which("dart")
        if not dart:
            raise AnalyzerUnavailable("Dart SDK was not found")
        if not (self.settings.analyzer_root / ".dart_tool" / "package_config.json").exists():
            raise AnalyzerUnavailable(
                "Perfora analyzer dependencies are not installed; run dart pub get"
            )
        try:
            output = await run_process(
                [
                    dart,
                    "run",
                    "bin/perfora_analyzer.dart",
                    "--root",
                    str(repository),
                ],
                cwd=self.settings.analyzer_root,
                timeout=120,
                env={"CI": "true"},
            )
        except ProcessError as error:
            raise AnalyzerUnavailable(error.output or str(error)) from error
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as error:
            raise AnalyzerUnavailable("Analyzer returned malformed JSON") from error
        if not isinstance(payload, list):
            raise AnalyzerUnavailable("Analyzer returned an unexpected payload")
        return payload
