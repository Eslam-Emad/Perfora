from __future__ import annotations

import json
import os
import shutil
from typing import Any

from ..domain import ModelInfo, ProviderCatalog, ProviderId
from ..process import ProcessError, run_process
from .base import ProviderAdapter, ProviderStructuredOutputError

_GENERATION_AGENT = "perfora-json"


def _generation_environment() -> dict[str, str]:
    inline_config: dict[str, Any] = {}
    configured = os.getenv("OPENCODE_CONFIG_CONTENT")
    if configured:
        try:
            candidate = json.loads(configured)
            if isinstance(candidate, dict):
                inline_config = candidate
        except json.JSONDecodeError:
            pass
    agents = inline_config.setdefault("agent", {})
    if not isinstance(agents, dict):
        agents = {}
        inline_config["agent"] = agents
    agents[_GENERATION_AGENT] = {
        "description": "Single-step structured output for Perfora",
        "mode": "primary",
        "steps": 1,
        "permission": {"*": "deny"},
    }
    return {"OPENCODE_CONFIG_CONTENT": json.dumps(inline_config, separators=(",", ":"))}


def _text_from_json_events(output: str) -> str:
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
    return "".join(chunks).strip()


def _decode_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ProviderStructuredOutputError("OpenCode returned no valid JSON object")


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
            f"{prompt}\n\nReturn exactly one JSON object matching this JSON Schema:\n"
            f"{json.dumps(schema, separators=(',', ':'))}\n"
            "Do not use Markdown fences or add commentary. The response must be valid JSON. "
            "Escape every newline inside a string value as \\n."
        )
        output = await run_process(
            [
                executable,
                "run",
                "--model",
                model_id,
                "--format",
                "json",
                "--agent",
                _GENERATION_AGENT,
                "--pure",
            ],
            timeout=180,
            env=_generation_environment(),
            input_text=schema_prompt,
        )
        text = _text_from_json_events(output)
        return _decode_json_object(text)
