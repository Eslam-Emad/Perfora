from __future__ import annotations

import asyncio
from typing import Any

from ..config import Settings
from ..domain import ProviderCatalog, ProviderId
from .base import ProviderAdapter
from .ollama import OllamaAdapter
from .openai import OpenAIAdapter
from .opencode import OpenCodeAdapter


class ProviderRegistry:
    def __init__(self, settings: Settings):
        adapters: list[ProviderAdapter] = [
            OpenCodeAdapter(),
            OllamaAdapter(settings),
            OpenAIAdapter(settings),
        ]
        self.adapters = {adapter.id: adapter for adapter in adapters}

    async def catalogs(self) -> list[ProviderCatalog]:
        return list(
            await asyncio.gather(*(adapter.catalog() for adapter in self.adapters.values()))
        )

    def adapter(self, provider: ProviderId) -> ProviderAdapter:
        return self.adapters[provider]

    async def generate_json(
        self,
        provider: ProviderId,
        model_id: str,
        prompt: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.adapter(provider).generate_json(model_id, prompt, schema)
