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
                    id=item["name"],
                    label=item.get("model") or item["name"],
                    compatible=True,
                    capability_status="unknown",
                    locality="local",
                    metadata={
                        "size": item.get("size"),
                        "modified_at": item.get("modified_at"),
                        "details": item.get("details", {}),
                    },
                )
                for item in response.json().get("models", [])
                if item.get("name")
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
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(
                f"{self.settings.ollama_base_url}/api/generate",
                json={
                    "model": model_id,
                    "prompt": prompt,
                    "stream": False,
                    "format": schema,
                    "options": {"temperature": 0},
                },
            )
            response.raise_for_status()
        return json.loads(response.json()["response"])
