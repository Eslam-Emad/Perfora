from __future__ import annotations

import hashlib


def fingerprint_basis(raw: dict) -> str:
    file = str(raw.get("file", "")).replace("\\", "/")
    symbol = " ".join(str(raw.get("symbol") or "").split())
    return "\0".join(
        [
            str(raw.get("rule_id", "unknown")),
            file,
            symbol,
            str(raw.get("framework", "unknown")),
        ]
    )


def finding_fingerprint(basis: str, occurrence: int = 0) -> str:
    identity = basis if occurrence == 0 else f"{basis}\0occurrence:{occurrence}"
    return f"sha256:{hashlib.sha256(identity.encode()).hexdigest()}"


def assign_fingerprints(findings: list[dict]) -> list[dict]:
    occurrences: dict[str, int] = {}
    result: list[dict] = []
    for raw in findings:
        basis = fingerprint_basis(raw)
        occurrence = occurrences.get(basis, 0)
        occurrences[basis] = occurrence + 1
        result.append({**raw, "fingerprint": finding_fingerprint(basis, occurrence)})
    return result
