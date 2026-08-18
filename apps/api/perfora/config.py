from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
_PROCESS_OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
_PROCESS_OLLAMA_BASE_URL = os.environ.get("PERFORA_OLLAMA_BASE_URL")
load_dotenv(WORKSPACE_ROOT / ".env.local")


@dataclass(slots=True)
class Settings:
    database_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("PERFORA_DATABASE_PATH", str(WORKSPACE_ROOT / "perfora.db"))
        ).expanduser()
    )
    ollama_base_url: str = os.getenv("PERFORA_OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip(
        "/"
    )
    openai_api_key: str | None = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY"), repr=False
    )
    report_signing_key: str | None = os.getenv("PERFORA_REPORT_SIGNING_KEY")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    analyzer_root: Path = WORKSPACE_ROOT / "tools" / "analyzer"
    local_env_path: Path = WORKSPACE_ROOT / ".env.local"
    request_timeout_seconds: float = 12.0
    process_openai_api_key: str | None = field(
        default=_PROCESS_OPENAI_API_KEY,
        repr=False,
    )
    process_ollama_base_url: str | None = _PROCESS_OLLAMA_BASE_URL


settings = Settings()
