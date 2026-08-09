from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..domain import ProviderCatalog, ProviderId


class ProviderRequestError(RuntimeError):
    """Sanitized provider failure safe to expose through the local API."""


class ProviderStructuredOutputError(RuntimeError):
    """The provider completed but did not return the requested JSON object."""


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
