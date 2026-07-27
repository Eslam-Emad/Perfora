from __future__ import annotations

import json
import shutil
from typing import Any

from ..domain import ModelInfo, ProviderCatalog, ProviderId
from ..process import ProcessError, run_process
from .base import ProviderAdapter


class OpenCodeAdapter(ProviderAdapter):
    id = ProviderId.OPENCODE
    locality = "unknown"

    async def catalog(self) -> ProviderCatalog:
        executable = shutil.which("opencode")
        if not executable:
            return ProviderCatalog(
                provider=self.id, available=False, detail="OpenCode CLI was not found"
            )
        try:
            output = await run_process([executable, "models"], timeout=20)
            unsupported_markers = (
                "audio",
                "embedding",
                "image",
                "moderation",
                "realtime",
                "transcribe",
                "tts",
                "whisper",
                "sora",
            )
            models = [
                ModelInfo(
                    provider=self.id,
                    id=line.strip(),
                    label=line.strip(),
                    compatible=not any(marker in line.lower() for marker in unsupported_markers),
                    capability_status=(
                        "unsupported"
                        if any(marker in line.lower() for marker in unsupported_markers)
                        else "unknown"
                    ),
                    locality="unknown",
                    metadata={"routing": "OpenCode-managed"},
                )
                for line in output.splitlines()
                if "/" in line and not line.startswith(("INFO", "WARN", "ERROR"))
            ]
            version = await run_process([executable, "--version"], timeout=5)
            return ProviderCatalog(
                provider=self.id,
                available=True,
                detail=f"OpenCode {version}; {len(models)} configured model(s)",
                models=models,
            )
        except ProcessError as error:
            return ProviderCatalog(
                provider=self.id,
                available=False,
                detail=f"OpenCode discovery failed: {error.returncode}",
            )

    async def generate_json(
        self, model_id: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        executable = shutil.which("opencode")
        if not executable:
            raise RuntimeError("OpenCode CLI was not found")
        schema_prompt = (
            f"{prompt}\n\nReturn only JSON matching this JSON Schema:\n"
            f"{json.dumps(schema, separators=(',', ':'))}"
        )
        output = await run_process(
            [
                executable,
                "run",
                "--model",
                model_id,
                "--format",
                "json",
                "--pure",
                schema_prompt,
            ],
            timeout=180,
        )
        chunks: list[str] = []
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            part = event.get("part", {})
            if part.get("type") == "text" and part.get("text"):
                chunks.append(part["text"])
            elif event.get("type") == "text" and event.get("text"):
                chunks.append(event["text"])
        text = "".join(chunks).strip()
        if text.startswith("```"):
            text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return json.loads(text)
