from __future__ import annotations

import shutil

from .domain import ToolStatus
from .process import ProcessError, run_process

TOOLS = {
    "git": ("Git", ["git", "--version"]),
    "dart": ("Dart", ["dart", "--version"]),
    "flutter": ("Flutter", ["flutter", "--version", "--machine"]),
    "opencode": ("OpenCode", ["opencode", "--version"]),
    "ollama": ("Ollama", ["ollama", "--version"]),
}


async def tool_health() -> list[ToolStatus]:
    results = []
    for tool_id, (label, command) in TOOLS.items():
        executable = shutil.which(tool_id)
        if not executable:
            results.append(
                ToolStatus(
                    id=tool_id,
                    label=label,
                    available=False,
                    detail=f"{label} was not found on PATH",
                )
            )
            continue
        try:
            output = await run_process([executable, *command[1:]], timeout=8)
            version = output.splitlines()[0][:160] if output else "installed"
            results.append(
                ToolStatus(
                    id=tool_id,
                    label=label,
                    available=True,
                    version=version,
                    detail=f"{label} is ready",
                )
            )
        except ProcessError as error:
            results.append(
                ToolStatus(
                    id=tool_id,
                    label=label,
                    available=False,
                    detail=f"{label} is installed but not ready: {error.output[-180:]}",
                )
            )
    return results
