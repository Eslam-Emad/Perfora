from __future__ import annotations

import asyncio
import os
from pathlib import Path


class ProcessError(RuntimeError):
    def __init__(self, command: list[str], returncode: int, output: str):
        super().__init__(f"{command[0]} exited with {returncode}: {output[-500:]}")
        self.command = command
        self.returncode = returncode
        self.output = output


async def run_process(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 30,
    env: dict[str, str] | None = None,
) -> str:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise ProcessError(command, -1, f"timed out after {timeout:.0f}s") from None
    output = stdout.decode(errors="replace").strip()
    if process.returncode:
        raise ProcessError(command, process.returncode or 1, output)
    return output
