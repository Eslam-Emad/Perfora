from __future__ import annotations

import html
import json
import uuid
from collections.abc import Iterable


def export_ci_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def export_ci_sarif(report: dict) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    level = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
    for finding in [*report["findings"], *report["resolved_findings"]]:
        rule_id = finding["rule_id"]
        rules[rule_id] = {
            "id": rule_id,
            "name": finding["title"],
            "shortDescription": {"text": finding["explanation"]},
            "help": {"text": finding["recommendation"]},
            "properties": {
                "version": finding["rule_version"],
                "controlGroup": finding.get("control_group"),
                "standards": [item["id"] for item in finding.get("standards", [])],
            },
        }
        result = {
            "ruleId": rule_id,
            "level": level[finding["severity"]],
            "message": {"text": finding["explanation"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["file"]},
                        "region": {"startLine": finding["line"]},
                    }
                }
            ],
            "partialFingerprints": {
                "perforaFindingFingerprint": finding["fingerprint"],
            },
            "properties": {
                "auditType": finding["audit_type"],
                "confidence": finding["confidence"],
                "framework": finding["framework"],
                "ruleVersion": finding["rule_version"],
                "suppressed": finding.get("suppressed", False),
                "suppressionExpires": finding.get("suppression_expires"),
                "suppressionPolicyManaged": finding.get("suppression_policy_managed", False),
                "controlGroup": finding.get("control_group"),
                "platforms": finding.get("platforms", []),
                "standards": finding.get("standards", []),
                "detectionLimitations": finding.get("detection_limitations", []),
                "manualVerification": finding.get("manual_verification", []),
                "falsePositiveGuidance": finding.get("false_positive_guidance"),
            },
        }
        if report["repository"].get("baseline_ref"):
            result["baselineState"] = finding["baseline_status"]
        if finding.get("suppressed"):
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": finding.get("suppression_reason") or "Repository policy",
                }
            ]
        results.append(result)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "automationDetails": {"id": "perfora/deterministic-audit"},
                "tool": {
                    "driver": {
                        "name": "Perfora",
                        "version": report["tool"]["version"],
                        "informationUri": "https://github.com/Eslam-Emad/Perfora",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def export_cyclonedx(report: dict) -> str:
    inventory = report.get("dependency_inventory", {})
    components = []
    refs = []
    for component in inventory.get("components", []):
        item = {
            "type": "library",
            "bom-ref": component["bom_ref"],
            "name": component["name"],
            "version": component["version"],
            "scope": component["scope"] if component["scope"] != "unknown" else "required",
            "properties": [
                {"name": "perfora:ecosystem", "value": component["ecosystem"]},
                {"name": "perfora:source-file", "value": component["source_file"]},
                {
                    "name": "perfora:license-status",
                    "value": component.get("license") or "unknown",
                },
                {
                    "name": "perfora:privacy-sensitive",
                    "value": str(component.get("privacy_sensitive", False)).lower(),
                },
            ],
        }
        if component.get("purl"):
            item["purl"] = component["purl"]
        if component.get("license"):
            item["licenses"] = [{"license": {"name": component["license"]}}]
        if component.get("privacy_category"):
            item["properties"].append(
                {"name": "perfora:privacy-category", "value": component["privacy_category"]}
            )
        components.append(item)
        refs.append(component["bom_ref"])

    repository = report["repository"]
    root_ref = f"application:{repository['name']}"
    serial_seed = "\0".join(
        [repository["path"], repository.get("commit") or "working-tree", report["generated_at"]]
    )
    payload = {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": report["generated_at"],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Perfora",
                        "version": report["tool"]["version"],
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": repository["name"],
                "version": repository.get("commit") or "working-tree",
            },
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": refs}],
        "compositions": [{"aggregate": "unknown", "assemblies": [root_ref]}],
    }
    return json.dumps(payload, indent=2)


def export_ci_html(report: dict) -> str:
    rows = "".join(_finding_html(finding) for finding in report["findings"])
    summary = report["summary"]
    audit_types = ", ".join(report["audit_types"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Perfora deterministic audit</title>
<style>
body{{font:16px/1.55 system-ui;max-width:960px;margin:48px auto;padding:0 24px;color:#10201d}}
header{{border-bottom:1px solid #d5dfdc;padding-bottom:24px}}article{{margin:28px 0;padding:24px;
border:1px solid #d5dfdc;border-radius:16px}}.eyebrow{{color:#147d64;text-transform:uppercase;
letter-spacing:.12em;font-size:12px;font-weight:700}}code{{background:#edf4f1;padding:3px 6px;
border-radius:6px}}.suppressed{{opacity:.68}}table{{border-collapse:collapse}}td,th{{padding:8px 16px;
border:1px solid #d5dfdc;text-align:left}}
</style></head><body><header><p class="eyebrow">Perfora deterministic audit</p>
<h1>{html.escape(report["repository"]["name"])}</h1><p>{html.escape(audit_types)} · analyzer-only ·
{html.escape(report["generated_at"])}</p><table><tr><th>Total</th><th>New</th><th>Unchanged</th>
<th>Resolved</th><th>Suppressed</th><th>Policy violations</th></tr><tr>
<td>{summary["total"]}</td><td>{summary["new"]}</td><td>{summary["unchanged"]}</td>
<td>{summary["resolved"]}</td><td>{summary["suppressed"]}</td><td>{summary["policy_violations"]}</td>
</tr></table></header>{rows or "<p>No findings detected.</p>"}</body></html>"""


def export_ci_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "## Perfora deterministic audit",
        "",
        (
            f"**{summary['total']}** finding(s): **{summary['new']} new**, "
            f"**{summary['unchanged']} unchanged**, **{summary['resolved']} resolved**, "
            f"and **{summary['suppressed']} suppressed**."
        ),
        "",
        (
            f"Policy result: **{summary['policy_violations']} violation(s)** at "
            f"`{report['policy']['severity'] or 'none'}` or above"
            f"{' among new findings only' if report['policy']['only_new'] else ''}."
        ),
        "",
        "| Severity | Status | Rule | Location |",
        "| --- | --- | --- | --- |",
    ]
    for finding in report["findings"][:20]:
        state = "suppressed" if finding.get("suppressed") else finding["baseline_status"]
        location = f"`{finding['file']}:{finding['line']}`"
        lines.append(f"| {finding['severity']} | {state} | `{finding['rule_id']}` | {location} |")
    if len(report["findings"]) > 20:
        lines.extend(["", f"_Showing 20 of {len(report['findings'])} findings._"])
    return "\n".join(lines) + "\n"


def _finding_html(finding: dict) -> str:
    css_class = ' class="suppressed"' if finding.get("suppressed") else ""
    evidence = "".join(f"<li>{html.escape(item)}</li>" for item in finding["evidence"])
    suppression = ""
    if finding.get("suppressed"):
        suppression = (
            f"<p><strong>Suppressed:</strong> {html.escape(finding['suppression_reason'])} "
            f"(expires {html.escape(finding['suppression_expires'] or 'never')})</p>"
        )
    return f"""<article{css_class}><p class="eyebrow">{html.escape(finding["audit_type"])} ·
{html.escape(finding["severity"])} · {html.escape(finding["baseline_status"])}</p>
<h2>{html.escape(finding["title"])}</h2><p><code>{html.escape(finding["file"])}:{finding["line"]}</code></p>
<p>{html.escape(finding["explanation"])}</p><h3>Evidence</h3><ul>{evidence}</ul>
<h3>Recommendation</h3><p>{html.escape(finding["recommendation"])}</p>{suppression}</article>"""


def render_ci_report(report: dict, output_format: str) -> str:
    exporters = {
        "json": export_ci_json,
        "sarif": export_ci_sarif,
        "html": export_ci_html,
        "cyclonedx": export_cyclonedx,
    }
    return exporters[output_format](report)


def unique_rules(findings: Iterable[dict]) -> set[str]:
    return {finding["rule_id"] for finding in findings}
