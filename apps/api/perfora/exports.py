from __future__ import annotations

import html
import json

from .domain import AuditRecord


def export_json(audit: AuditRecord) -> str:
    return audit.model_dump_json(indent=2)


def export_sarif(audit: AuditRecord) -> str:
    rules = {}
    results = []
    level = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in audit.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.explanation},
            "help": {"text": finding.recommendation},
        }
        results.append(
            {
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
                },
            }
        )
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
          <p>{html.escape(finding.model_explanation or finding.explanation)}</p>
          <h3>Evidence</h3>
          <ul>{"".join(f"<li>{html.escape(item)}</li>" for item in finding.evidence)}</ul>
          <h3>Recommendation</h3>
          <p>{html.escape(finding.recommendation)}</p>
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
<p>{html.escape(audit.provider.value)}/{html.escape(audit.model_id)} ·
{html.escape(audit.status)}</p></header>{rows or "<p>No lifecycle findings.</p>"}</body></html>"""
