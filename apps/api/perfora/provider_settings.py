from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit, urlunsplit

from .config import Settings
from .domain import (
    OllamaSettingsStatus,
    OpenAISettingsStatus,
    ProviderSettingsSnapshot,
    ProviderSettingsUpdate,
)

_ENV_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=")


class ProviderSettingsError(ValueError):
    pass


def normalize_ollama_base_url(value: str) -> tuple[str, str]:
    candidate = value.strip().rstrip("/")
    if any(character.isspace() for character in candidate):
        raise ProviderSettingsError("Ollama URL cannot contain whitespace")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ProviderSettingsError("Ollama URL has an invalid port") from error
    if parsed.scheme not in {"http", "https"}:
        raise ProviderSettingsError("Ollama URL must use http or https")
    if not parsed.hostname:
        raise ProviderSettingsError("Ollama URL must include a host")
    if parsed.username or parsed.password:
        raise ProviderSettingsError("Ollama URL cannot contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ProviderSettingsError("Ollama URL must not contain a path, query, or fragment")

    hostname = parsed.hostname.lower()
    local = hostname == "localhost" or hostname.endswith(".localhost")
    try:
        local = local or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        host = f"{host}:{port}"
    normalized = urlunsplit((parsed.scheme.lower(), host, "", "", ""))
    return normalized, "local" if local else "remote"


class ProviderSettingsService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = Lock()

    def snapshot(self) -> ProviderSettingsSnapshot:
        file_values = self._configured_names()
        _, ollama_locality = normalize_ollama_base_url(self.settings.ollama_base_url)
        return ProviderSettingsSnapshot(
            openai=OpenAISettingsStatus(
                configured=bool(self.settings.openai_api_key),
                source=(
                    "settings"
                    if "OPENAI_API_KEY" in file_values
                    else "environment"
                    if self.settings.openai_api_key
                    else "none"
                ),
            ),
            ollama=OllamaSettingsStatus(
                base_url=self.settings.ollama_base_url,
                source=(
                    "settings"
                    if "PERFORA_OLLAMA_BASE_URL" in file_values
                    else "environment"
                    if self.settings.process_ollama_base_url
                    else "default"
                ),
                locality=ollama_locality,
            ),
        )

    def update(self, request: ProviderSettingsUpdate) -> ProviderSettingsSnapshot:
        updates: dict[str, str | None] = {}
        if request.openai_api_key is not None:
            updates["OPENAI_API_KEY"] = request.openai_api_key.get_secret_value()
        elif request.clear_openai_api_key:
            updates["OPENAI_API_KEY"] = None
        if request.ollama_base_url is not None:
            normalized, _ = normalize_ollama_base_url(request.ollama_base_url)
            updates["PERFORA_OLLAMA_BASE_URL"] = normalized

        with self._lock:
            self._write_updates(updates)
            if "OPENAI_API_KEY" in updates:
                self.settings.openai_api_key = (
                    updates["OPENAI_API_KEY"] or self.settings.process_openai_api_key
                )
            if "PERFORA_OLLAMA_BASE_URL" in updates:
                self.settings.ollama_base_url = (
                    updates["PERFORA_OLLAMA_BASE_URL"]
                    or self.settings.process_ollama_base_url
                    or "http://127.0.0.1:11434"
                )
        return self.snapshot()

    def _configured_names(self) -> set[str]:
        path = self.settings.local_env_path
        if not path.exists() or not path.is_file() or path.is_symlink():
            return set()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return set()
        names = set()
        for line in lines:
            match = _ENV_ASSIGNMENT.match(line)
            if match and line[match.end() :].strip():
                names.add(match.group("name"))
        return names

    def _write_updates(self, updates: dict[str, str | None]) -> None:
        path = self.settings.local_env_path
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ProviderSettingsError("Local settings destination must be a regular file")
        try:
            existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        except (OSError, UnicodeError) as error:
            raise ProviderSettingsError("Local provider settings could not be read") from error

        output: list[str] = []
        handled: set[str] = set()
        for line in existing:
            match = _ENV_ASSIGNMENT.match(line)
            name = match.group("name") if match else None
            if name not in updates:
                output.append(line)
                continue
            if name in handled:
                continue
            handled.add(name)
            value = updates[name]
            if value is not None:
                output.append(f"{name}={self._quote(value)}")
        for name, value in updates.items():
            if name not in handled and value is not None:
                output.append(f"{name}={self._quote(value)}")

        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=".perfora-settings-",
            text=True,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write("\n".join(output) + ("\n" if output else ""))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise ProviderSettingsError("Local provider settings could not be saved") from error

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
