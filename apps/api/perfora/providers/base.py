from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..domain import ProviderCatalog, ProviderId


class ProviderAdapter(ABC):
    id: ProviderId
    locality: str

    @abstractmethod
    async def catalog(self) -> ProviderCatalog:
        """Return current connection health and dynamically discovered models."""

    @abstractmethod
    async def generate_json(
        self, model_id: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate one schema-constrained JSON object."""
