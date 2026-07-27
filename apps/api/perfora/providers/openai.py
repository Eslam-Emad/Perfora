from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import Settings
from ..domain import ModelInfo, ProviderCatalog, ProviderId
from .base import ProviderAdapter

TEXT_MODEL_PREFIXES = (
    "gpt-",
    "o1",
    "o3",
    "o4",
    "chatgpt-",
    "codex-",
)
NON_TEXT_MARKERS = (
    "audio",
    "realtime",
    "transcribe",
    "tts",
    "image",
    "embedding",
    "moderation",
    "whisper",
    "sora",
)


class OpenAIAdapter(ProviderAdapter):
    id = ProviderId.OPENAI
    locality = "remote"

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.openai_api_key}"}

    async def catalog(self) -> ProviderCatalog:
        if not self.settings.openai_api_key:
            return ProviderCatalog(
                provider=self.id,
                available=False,
                detail="OPENAI_API_KEY is not configured",
            )
        try:
            async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
                response = await client.get(
                    f"{self.settings.openai_base_url}/models", headers=self.headers
                )
                response.raise_for_status()
            models = []
            for model_payload in response.json().get("data", []):
                model_id = str(model_payload.get("id", ""))
                compatible = model_id.startswith(TEXT_MODEL_PREFIXES) and not any(
                    marker in model_id.lower() for marker in NON_TEXT_MARKERS
                )
                models.append(
                    ModelInfo(
                        provider=self.id,
                        id=model_id,
                        label=model_id,
                        compatible=compatible,
                        capability_status="compatible" if compatible else "unknown",
                        locality="remote",
                        metadata={
                            "owned_by": model_payload.get("owned_by"),
                            "created": model_payload.get("created"),
                        },
                    )
                )
            models.sort(key=lambda model: model.id, reverse=True)
            return ProviderCatalog(
                provider=self.id,
                available=True,
                detail=f"{len(models)} model(s) available to this API key",
                models=models,
            )
        except (httpx.HTTPError, ValueError) as error:
            return ProviderCatalog(
                provider=self.id,
                available=False,
                detail=f"OpenAI connection failed: {type(error).__name__}",
            )

    async def generate_json(
        self, model_id: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        if not self.settings.openai_api_key:
            raise RuntimeError("OpenAI is not configured")
        payload = {
            "model": model_id,
            "input": prompt,
            "store": False,
            "reasoning": {"effort": "medium"},
            "text": {
                "verbosity": "low",
                "format": {
                    "type": "json_schema",
                    "name": "perfora_result",
                    "strict": True,
                    "schema": schema,
                },
            },
        }
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{self.settings.openai_base_url}/responses",
                headers={**self.headers, "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
        body = response.json()
        for output in body.get("output", []):
            for content in output.get("content", []):
                if content.get("type") == "output_text":
                    return json.loads(content["text"])
        raise RuntimeError("OpenAI returned no structured text output")
