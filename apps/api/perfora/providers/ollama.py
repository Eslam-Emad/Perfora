from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import Settings
from ..domain import ModelInfo, ProviderCatalog, ProviderId
from .base import ProviderAdapter


class OllamaAdapter(ProviderAdapter):
    id = ProviderId.OLLAMA
    locality = "local"

    def __init__(self, settings: Settings):
        self.settings = settings

    async def catalog(self) -> ProviderCatalog:
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                response = await client.get(f"{self.settings.ollama_base_url}/api/tags")
                response.raise_for_status()
            models = [
                ModelInfo(
                    provider=self.id,
                    id=model_payload["name"],
                    label=model_payload.get("model") or model_payload["name"],
                    compatible="embed" not in model_payload["name"].lower(),
                    capability_status=(
                        "unsupported" if "embed" in model_payload["name"].lower() else "unknown"
                    ),
                    locality="remote" if ":cloud" in model_payload["name"] else "local",
                    metadata={
                        "size": model_payload.get("size"),
                        "modified_at": model_payload.get("modified_at"),
                        "details": model_payload.get("details", {}),
                    },
                )
                for model_payload in response.json().get("models", [])
                if model_payload.get("name")
            ]
            return ProviderCatalog(
                provider=self.id,
                available=True,
                detail=f"{len(models)} local model(s)",
                models=models,
            )
        except (httpx.HTTPError, ValueError, KeyError) as error:
            return ProviderCatalog(
                provider=self.id,
                available=False,
                detail=f"Ollama unavailable at {self.settings.ollama_base_url}: {type(error).__name__}",
            )

    async def generate_json(
        self, model_id: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=300) as client:
            response = await client.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json={
                    "model": model_id,
                    "prompt": prompt,
                    "stream": False,
                    "think": False,
                    "format": schema,
                    "options": {
                        "temperature": 0,
                        "num_ctx": 8192,
                        "num_predict": 1400,
                    },
                },
            )
            response.raise_for_status()
        return json.loads(response.json()["response"])
