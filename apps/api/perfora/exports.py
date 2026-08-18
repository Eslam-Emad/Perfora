from __future__ import annotations

import hashlib
import hmac
import html
import io
import json
import zipfile
from datetime import UTC, datetime

from . import __version__
from .ci_report import export_cyclonedx
from .domain import AuditRecord
from .security import redact_secrets


def export_json(audit: AuditRecord) -> str:
    return audit.model_dump_json(indent=2)


def export_evidence_package(audit: AuditRecord, signing_key: str | None = None) -> bytes:
    """Create a redacted, checksummed ZIP with an optional HMAC authenticity signature."""
    redacted_audit = AuditRecord.model_validate(_redact_value(audit.model_dump(mode="json")))
    artifacts = {
        "audit.json": export_json(redacted_audit).encode(),
        "report.html": export_html(redacted_audit).encode(),
        "results.sarif.json": export_sarif(redacted_audit).encode(),
        "dependencies.cdx.json": export_audit_cyclonedx(redacted_audit).encode(),
    }
    manifest = {
        "schema_version": 1,
        "audit_id": audit.id,
        "generated_at": datetime.now(UTC).isoformat(),
        "redacted": True,
        "files": {
            name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
            for name, content in artifacts.items()
        },
    }
    signature_payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["signature"] = (
        {
            "algorithm": "hmac-sha256",
            "value": hmac.new(signing_key.encode(), signature_payload, hashlib.sha256).hexdigest(),
        }
        if signing_key
        else {"algorithm": "none", "value": None}
    )
    artifacts["manifest.json"] = json.dumps(manifest, indent=2).encode()

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(artifacts):
            archive.writestr(name, artifacts[name])
    return output.getvalue()


def _redact_value(value):
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return value


def export_audit_cyclonedx(audit: AuditRecord) -> str:
    return export_cyclonedx(
        {
            "tool": {"version": __version__},
            "generated_at": datetime.now(UTC).isoformat(),
            "repository": {
                "name": audit.repository.name,
                "path": audit.repository.path,
                "commit": audit.repository.commit_sha,
            },
            "dependency_inventory": audit.dependency_inventory.model_dump(mode="json"),
        }
    )


def export_sarif(audit: AuditRecord) -> str:
    rules = {}
    results = []
    level = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in audit.findings:
        latest_verification = (
            finding.verification_attempts[-1] if finding.verification_attempts else None
        )
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.explanation},
            "help": {"text": finding.recommendation},
            "properties": {
                "version": finding.rule_version,
                "controlGroup": finding.control_group,
                "standards": [item.id for item in finding.standards],
            },
        }
        result = {
            "ruleId": finding.rule_id,
            "level": level[finding.severity],
            "message": {"text": finding.explanation},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line},
                    }
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "framework": finding.framework,
                "status": finding.status,
                "auditType": audit.audit_type.value,
                "ruleVersion": finding.rule_version,
                "triageStatus": finding.triage_status.value,
                "comparisonStatus": (
                    finding.comparison_status.value if finding.comparison_status else None
                ),
                "owner": finding.owner,
                "dueAt": finding.due_at.isoformat() if finding.due_at else None,
                "ticketUrl": finding.ticket_url,
                "suppressionExpiresAt": (
                    finding.suppression_expires_at.isoformat()
                    if finding.suppression_expires_at
                    else None
                ),
                "verificationOutcome": (
                    latest_verification.outcome.value if latest_verification else None
                ),
                "verificationCompletedAt": (
                    latest_verification.completed_at.isoformat() if latest_verification else None
                ),
                "controlGroup": finding.control_group,
                "platforms": finding.platforms,
                "standards": [item.model_dump(mode="json") for item in finding.standards],
                "detectionLimitations": finding.detection_limitations,
                "manualVerification": finding.manual_verification,
                "falsePositiveGuidance": finding.false_positive_guidance,
            },
        }
        if finding.fingerprint:
            result["partialFingerprints"] = {
                "perforaFindingFingerprint": finding.fingerprint,
            }
        results.append(result)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Perfora",
                        "informationUri": "https://github.com/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def export_html(audit: AuditRecord) -> str:
    rows = "".join(
        f"""
        <article>
          <p class="eyebrow">{html.escape(finding.framework)} · {html.escape(finding.severity)}</p>
          <h2>{html.escape(finding.title)}</h2>
          <p><code>{html.escape(finding.file)}:{finding.line}</code></p>
          <p><strong>Triage:</strong> {html.escape(finding.triage_status.value)} ·
          <strong>Change:</strong> {
            html.escape(
                finding.comparison_status.value if finding.comparison_status else "not classified"
            )
        } ·
          <strong>Owner:</strong> {html.escape(finding.owner or "unassigned")}</p>
          <p><strong>Latest verification:</strong> {
            html.escape(finding.verification_attempts[-1].outcome.value)
            if finding.verification_attempts
            else "not run"
        }</p>
          <p>{html.escape(finding.explanation)}</p>
          {
            f'''<h3>Standards mapping</h3>
          <p>{html.escape(finding.control_group or "Unmapped")} · {
                html.escape(", ".join(item.id for item in finding.standards) or "No references")
            }</p>
          <h3>Detection limitations</h3>
          <ul>{
                "".join(f"<li>{html.escape(item)}</li>" for item in finding.detection_limitations)
            }</ul>
          <h3>Manual verification</h3>
          <ul>{
                "".join(f"<li>{html.escape(item)}</li>" for item in finding.manual_verification)
            }</ul>'''
            if finding.control_group
            else ""
        }
          <h3>Evidence</h3>
          <ul>{"".join(f"<li>{html.escape(item)}</li>" for item in finding.evidence)}</ul>
          <h3>Deterministic recommendation</h3>
          <p>{html.escape(finding.recommendation)}</p>
          {
            f'''<h3>Model perspective</h3>
          <p>{html.escape(finding.model_enrichment.explanation)}</p>
          <p>{html.escape(finding.model_enrichment.recommendation or "")}</p>'''
            if finding.model_enrichment
            else ""
        }
        </article>
        """
        for finding in audit.findings
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Perfora audit {audit.id}</title>
<style>
body{{font:16px/1.55 system-ui;max-width:900px;margin:56px auto;padding:0 24px;color:#10201d}}
header{{border-bottom:1px solid #d5dfdc;padding-bottom:24px}}article{{margin:36px 0;padding:28px;
border:1px solid #d5dfdc;border-radius:18px}}.eyebrow{{color:#147d64;text-transform:uppercase;
letter-spacing:.12em;font-size:12px;font-weight:700}}code{{background:#edf4f1;padding:3px 6px;border-radius:6px}}
</style></head><body><header><p class="eyebrow">Perfora evidence report</p>
<h1>{html.escape(audit.repository.name)}</h1>
<p>{html.escape(audit.audit_type.value)} · {html.escape(audit.provider.value)}/{html.escape(audit.model_id)} ·
{html.escape(audit.status)}</p></header>{rows or f"<p>No {html.escape(audit.audit_type.value)} findings.</p>"}</body></html>"""
