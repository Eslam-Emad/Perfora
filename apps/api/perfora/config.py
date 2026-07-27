from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(WORKSPACE_ROOT / ".env.local")


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("PERFORA_DATABASE_PATH", str(WORKSPACE_ROOT / "perfora.db"))
        ).expanduser()
    )
    ollama_base_url: str = os.getenv("PERFORA_OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip(
        "/"
    )
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    analyzer_root: Path = WORKSPACE_ROOT / "tools" / "analyzer"
    request_timeout_seconds: float = 12.0


settings = Settings()
