from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .domain import RepositorySnapshot
from .process import ProcessError, run_process

IGNORED_PARTS = {".git", ".dart_tool", "build", "node_modules"}


def _safe_resolve(raw_path: str) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.is_absolute():
        raise ValueError("Repository path must be absolute")
    return path


async def inspect_repository(raw_path: str) -> RepositorySnapshot:
    try:
        path = _safe_resolve(raw_path)
    except (OSError, ValueError) as error:
        return RepositorySnapshot(
            path=raw_path,
            name=Path(raw_path).name or raw_path,
            valid=False,
            detail=str(error),
        )

    if not path.is_dir():
        return RepositorySnapshot(
            path=str(path), name=path.name, valid=False, detail="Directory does not exist"
        )

    pubspecs = [
        candidate
        for candidate in path.rglob("pubspec.yaml")
        if not IGNORED_PARTS.intersection(candidate.relative_to(path).parts)
    ]
    root_pubspec = path / "pubspec.yaml"
    is_flutter = any(
        "flutter:" in candidate.read_text(errors="ignore") for candidate in pubspecs[:100]
    )
    if not root_pubspec.exists() and not pubspecs:
        return RepositorySnapshot(
            path=str(path),
            name=path.name,
            valid=False,
            detail="No pubspec.yaml was found",
        )
    if not is_flutter:
        return RepositorySnapshot(
            path=str(path),
            name=path.name,
            valid=False,
            detail="The directory contains Dart packages but no Flutter dependency",
        )

    is_git = (path / ".git").exists() and shutil.which("git") is not None
    branch = commit = None
    clean = None
    if is_git:
        try:
            branch = await run_process(["git", "branch", "--show-current"], cwd=path, timeout=5)
            commit = await run_process(["git", "rev-parse", "HEAD"], cwd=path, timeout=5)
            clean = not bool(
                await run_process(["git", "status", "--porcelain"], cwd=path, timeout=5)
            )
        except ProcessError:
            is_git = False

    digest = hashlib.sha256()
    for pubspec in sorted(pubspecs)[:100]:
        digest.update(str(pubspec.relative_to(path)).encode())
        digest.update(pubspec.read_bytes())
    if commit:
        digest.update(commit.encode())

    return RepositorySnapshot(
        path=str(path),
        name=path.name,
        valid=True,
        detail=f"Flutter repository with {len(pubspecs)} package(s)",
        is_flutter=True,
        is_git=is_git,
        branch=branch or None,
        commit_sha=commit or None,
        clean=clean,
        fingerprint=digest.hexdigest(),
        packages=[str(item.parent.relative_to(path)) or "." for item in sorted(pubspecs)],
    )
