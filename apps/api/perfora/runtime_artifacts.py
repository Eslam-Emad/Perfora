from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .database import AuditStore
from .domain import (
    RepositorySnapshot,
    RuntimeArtifactKind,
    RuntimeArtifactProvenance,
    RuntimeBreakdownItem,
    RuntimeBuildMode,
    RuntimeCapture,
    RuntimeCaptureComparison,
    RuntimeEvidence,
    RuntimeFinding,
    RuntimeImportRequest,
    RuntimeMetricDelta,
    RuntimeReliability,
)
from .security import redact_secrets

RUNTIME_RULE_PACK_VERSION = "1.0.0"
_FRAME_BUDGET_US = 1_000_000 / 60
_MAX_EVIDENCE = 500
_HIGHER_IS_WORSE = {
    "average_frame_build_time_ms",
    "average_frame_raster_time_ms",
    "worst_frame_build_time_ms",
    "worst_frame_raster_time_ms",
    "janky_frame_count",
    "missed_frame_build_budget_count",
    "missed_frame_raster_budget_count",
    "memory_growth_bytes",
    "peak_heap_bytes",
    "final_heap_bytes",
    "total_size_bytes",
    "failed_request_count",
    "slow_request_count",
    "average_request_duration_ms",
    "total_transfer_bytes",
}


class RuntimeArtifactError(ValueError):
    pass


class RuntimeArtifactService:
    def __init__(self, store: AuditStore):
        self.store = store

    def import_capture(
        self,
        request: RuntimeImportRequest,
        repository: RepositorySnapshot,
    ) -> RuntimeCapture:
        try:
            payload = json.loads(request.content)
        except json.JSONDecodeError as error:
            raise RuntimeArtifactError(
                f"Artifact is not valid JSON at line {error.lineno}, column {error.colno}"
            ) from None
        if not isinstance(payload, dict):
            raise RuntimeArtifactError("Artifact JSON must contain an object at its root")

        kind = request.kind if request.kind != RuntimeArtifactKind.AUTO else _detect_kind(payload)
        if kind == RuntimeArtifactKind.AUTO:
            raise RuntimeArtifactError(
                "Artifact type was not recognized; choose a type and confirm the exported format"
            )

        provenance, warnings = _provenance(request, payload, kind)
        reliability, reliability_warning = _reliability(kind, provenance.build_mode)
        if reliability_warning:
            warnings.append(reliability_warning)

        metrics, units, breakdowns, evidence, findings = _parse(kind, payload)
        if reliability != RuntimeReliability.TRUSTED and findings:
            warnings.append(
                "Threshold findings were withheld because this capture lacks trusted profile-mode "
                "or release app-size provenance."
            )
            findings = []

        capture = RuntimeCapture(
            id=uuid.uuid4().hex,
            repository=repository,
            label=request.label.strip()
            if request.label and request.label.strip()
            else Path(request.filename).stem,
            kind=kind,
            reliability=reliability,
            provenance=provenance,
            metrics=metrics,
            metric_units=units,
            breakdowns=breakdowns,
            evidence=evidence,
            findings=findings,
            warnings=warnings,
        )
        self.store.save_runtime_capture(capture)
        return capture

    def compare(self, baseline_id: str, current_id: str) -> RuntimeCaptureComparison:
        baseline = self.store.get_runtime_capture(baseline_id)
        current = self.store.get_runtime_capture(current_id)
        if baseline is None or current is None:
            raise KeyError(baseline_id if baseline is None else current_id)

        warnings: list[str] = []
        compatible = True
        if baseline.repository.path != current.repository.path:
            compatible = False
            warnings.append("Captures belong to different repositories.")
        if baseline.kind != current.kind:
            compatible = False
            warnings.append("Captures use different artifact types.")
        if baseline.reliability != RuntimeReliability.TRUSTED:
            warnings.append("Baseline capture is not trusted performance evidence.")
        if current.reliability != RuntimeReliability.TRUSTED:
            warnings.append("Current capture is not trusted performance evidence.")
        if (
            baseline.provenance.flutter_version
            and current.provenance.flutter_version
            and baseline.provenance.flutter_version != current.provenance.flutter_version
        ):
            warnings.append("Flutter versions differ; interpret deltas with caution.")
        if (
            baseline.provenance.devtools_version
            and current.provenance.devtools_version
            and baseline.provenance.devtools_version != current.provenance.devtools_version
        ):
            warnings.append(
                "DevTools versions differ; artifact schemas or measurements may differ."
            )

        deltas = _metric_deltas(baseline, current) if compatible else []
        baseline_rules = {finding.rule_id for finding in baseline.findings}
        current_rules = {finding.rule_id for finding in current.findings}
        return RuntimeCaptureComparison(
            baseline_capture_id=baseline.id,
            current_capture_id=current.id,
            compatible=compatible,
            warnings=warnings,
            metric_deltas=deltas,
            new_finding_rule_ids=sorted(current_rules - baseline_rules),
            resolved_finding_rule_ids=sorted(baseline_rules - current_rules),
        )


def _detect_kind(payload: dict[str, Any]) -> RuntimeArtifactKind:
    for candidate in _mapping_candidates(payload):
        log = candidate.get("log")
        if isinstance(log, dict) and isinstance(log.get("entries"), list):
            return RuntimeArtifactKind.NETWORK_TRACE
        if _has_frame_summary(candidate):
            return RuntimeArtifactKind.FRAME_TIMING
        if isinstance(candidate.get("traceEvents"), list):
            return RuntimeArtifactKind.TIMELINE
        if isinstance(candidate.get("nodes"), list) and (
            isinstance(candidate.get("samples"), list) or "startTime" in candidate
        ):
            return RuntimeArtifactKind.CPU_PROFILE
        if _looks_like_memory(candidate):
            return RuntimeArtifactKind.MEMORY_SNAPSHOT
        if _looks_like_app_size(candidate):
            return RuntimeArtifactKind.APP_SIZE
    return RuntimeArtifactKind.AUTO


def _parse(
    kind: RuntimeArtifactKind,
    payload: dict[str, Any],
) -> tuple[
    dict[str, float | int],
    dict[str, str],
    dict[str, list[RuntimeBreakdownItem]],
    list[RuntimeEvidence],
    list[RuntimeFinding],
]:
    parsers = {
        RuntimeArtifactKind.TIMELINE: _parse_timeline,
        RuntimeArtifactKind.CPU_PROFILE: _parse_cpu,
        RuntimeArtifactKind.MEMORY_SNAPSHOT: _parse_memory,
        RuntimeArtifactKind.HEAP_COMPARISON: _parse_heap_comparison,
        RuntimeArtifactKind.APP_SIZE: _parse_app_size,
        RuntimeArtifactKind.FRAME_TIMING: _parse_frame_timing,
        RuntimeArtifactKind.NETWORK_TRACE: _parse_network,
    }
    try:
        return parsers[kind](payload)
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise RuntimeArtifactError(
            f"The selected {kind.value.replace('_', ' ')} artifact is malformed: {error}"
        ) from None


def _provenance(
    request: RuntimeImportRequest,
    payload: dict[str, Any],
    kind: RuntimeArtifactKind,
) -> tuple[RuntimeArtifactProvenance, list[str]]:
    metadata = _metadata(payload)
    artifact_mode = _build_mode(
        metadata.get("build_mode") or metadata.get("buildMode") or metadata.get("mode")
    )
    warnings: list[str] = []
    if artifact_mode != RuntimeBuildMode.UNKNOWN:
        build_mode = artifact_mode
        mode_source = "artifact"
        if request.build_mode not in {RuntimeBuildMode.UNKNOWN, artifact_mode}:
            warnings.append(
                f"Declared {request.build_mode.value} mode conflicts with artifact metadata; "
                f"using {artifact_mode.value}."
            )
    elif request.build_mode != RuntimeBuildMode.UNKNOWN:
        build_mode = request.build_mode
        mode_source = "declared"
        warnings.append(
            "Build mode was declared during import and was not verified from the artifact."
        )
    else:
        build_mode = RuntimeBuildMode.UNKNOWN
        mode_source = "unknown"

    captured_at = _datetime(
        metadata.get("captured_at") or metadata.get("capturedAt") or metadata.get("timestamp")
    )
    filename = Path(request.filename).name
    return (
        RuntimeArtifactProvenance(
            filename=filename,
            sha256=f"sha256:{hashlib.sha256(request.content.encode()).hexdigest()}",
            artifact_format=_format_name(kind, payload),
            build_mode=build_mode,
            build_mode_source=mode_source,
            flutter_version=_text(
                metadata.get("flutter_version")
                or metadata.get("flutterVersion")
                or request.flutter_version
            ),
            devtools_version=_text(
                metadata.get("devtools_version")
                or metadata.get("devToolsVersion")
                or request.devtools_version
            ),
            dart_version=_text(
                metadata.get("dart_version")
                or metadata.get("dartVersion")
                or metadata.get("dartSdkVersion")
                or request.dart_version
            ),
            captured_at=captured_at,
        ),
        warnings,
    )


def _reliability(
    kind: RuntimeArtifactKind, build_mode: RuntimeBuildMode
) -> tuple[RuntimeReliability, str | None]:
    if kind == RuntimeArtifactKind.APP_SIZE and build_mode in {
        RuntimeBuildMode.RELEASE,
        RuntimeBuildMode.PROFILE,
    }:
        return RuntimeReliability.TRUSTED, None
    if build_mode == RuntimeBuildMode.PROFILE:
        return RuntimeReliability.TRUSTED, None
    if build_mode == RuntimeBuildMode.DEBUG:
        return (
            RuntimeReliability.UNRELIABLE,
            (
                "Debug-mode timings are distorted by assertions, service extensions, and JIT "
                "behavior; capture again in profile mode before making a performance decision."
            ),
        )
    return (
        RuntimeReliability.UNVERIFIED,
        "Profile-mode provenance is required before runtime measurements can produce findings.",
    )


def _parse_frame_timing(payload: dict[str, Any]):
    data = _find_mapping(payload, _has_frame_summary)
    build = _numbers(data.get("frame_build_times"))
    raster = _numbers(data.get("frame_rasterizer_times"))
    evidence: list[RuntimeEvidence] = []
    janky_ids: list[str] = []
    for label, values in (("UI frame", build), ("Raster frame", raster)):
        for index, duration in enumerate(values[:_MAX_EVIDENCE]):
            if duration <= _FRAME_BUDGET_US:
                continue
            item = _evidence(
                "frame",
                label,
                f"$.{('frame_build_times' if label.startswith('UI') else 'frame_rasterizer_times')}[{index}]",
                duration_us=duration,
                value=duration / 1000,
                unit="ms",
                details={"budget_ms": round(_FRAME_BUDGET_US / 1000, 3)},
            )
            evidence.append(item)
            janky_ids.append(item.id)

    metrics = {
        "frame_count": _number(data.get("frame_count"), max(len(build), len(raster))),
        "average_frame_build_time_ms": _number(
            data.get("average_frame_build_time_millis"), _average(build) / 1000
        ),
        "worst_frame_build_time_ms": _number(
            data.get("worst_frame_build_time_millis"), max(build, default=0) / 1000
        ),
        "missed_frame_build_budget_count": _number(
            data.get("missed_frame_build_budget_count"),
            sum(value > _FRAME_BUDGET_US for value in build),
        ),
        "average_frame_raster_time_ms": _number(
            data.get("average_frame_rasterizer_time_millis"), _average(raster) / 1000
        ),
        "worst_frame_raster_time_ms": _number(
            data.get("worst_frame_rasterizer_time_millis"), max(raster, default=0) / 1000
        ),
        "missed_frame_raster_budget_count": _number(
            data.get("missed_frame_rasterizer_budget_count"),
            sum(value > _FRAME_BUDGET_US for value in raster),
        ),
        "janky_frame_count": len(janky_ids),
    }
    findings = []
    if janky_ids:
        findings.append(
            _finding(
                "runtime.frame.jank",
                "Observed frames exceeded the 60 Hz frame budget",
                "high" if len(janky_ids) >= 5 else "medium",
                "The imported frame timing artifact contains UI or raster work longer than 16.67 ms.",
                "Reproduce the recorded interaction in profile mode and inspect the linked UI/raster frames before optimizing the responsible build, layout, paint, or shader work.",
                janky_ids,
            )
        )
    return (
        metrics,
        _units(
            metrics,
            "ms",
            counters={
                "frame_count",
                "janky_frame_count",
                "missed_frame_build_budget_count",
                "missed_frame_raster_budget_count",
            },
        ),
        {},
        evidence,
        findings,
    )


def _parse_timeline(payload: dict[str, Any]):
    data = _find_mapping(payload, lambda item: isinstance(item.get("traceEvents"), list))
    events = data["traceEvents"]
    evidence: list[RuntimeEvidence] = []
    janky: list[str] = []
    expensive: list[str] = []
    ui_durations: list[float] = []
    raster_durations: list[float] = []
    complete_count = 0
    for index, event in enumerate(events):
        if not isinstance(event, dict) or event.get("ph") not in {None, "X"}:
            continue
        duration = _optional_number(event.get("dur") or event.get("duration"))
        if duration is None:
            continue
        complete_count += 1
        name = redact_secrets(str(event.get("name") or "Timeline event"))[:300]
        category = str(event.get("cat") or "")
        lower = f"{name} {category}".lower()
        if "raster" in lower:
            raster_durations.append(duration)
        elif any(marker in lower for marker in ("build", "layout", "paint", "ui", "frame")):
            ui_durations.append(duration)
        is_frame = "frame" in lower
        is_expensive = any(marker in lower for marker in ("build", "layout", "paint"))
        if duration <= _FRAME_BUDGET_US or not (is_frame or is_expensive):
            continue
        arguments = event.get("args") if isinstance(event.get("args"), dict) else {}
        source_file = _safe_source(
            arguments.get("file") or arguments.get("source") or arguments.get("url")
        )
        source_line = _source_line(arguments.get("line") or arguments.get("lineNumber"))
        item = _evidence(
            "timeline_event",
            name,
            f"$.traceEvents[{index}]",
            timestamp_us=_optional_number(event.get("ts")),
            duration_us=duration,
            value=duration / 1000,
            unit="ms",
            thread=_text(event.get("tid")),
            source_file=source_file,
            source_line=source_line,
            details={"category": redact_secrets(category)[:200]},
        )
        evidence.append(item)
        (janky if is_frame else expensive).append(item.id)
        if len(evidence) >= _MAX_EVIDENCE:
            break
    metrics: dict[str, float | int] = {
        "timeline_event_count": len(events),
        "complete_event_count": complete_count,
        "janky_frame_count": len(janky),
        "expensive_render_event_count": len(expensive),
        "average_ui_event_time_ms": _average(ui_durations) / 1000,
        "average_raster_event_time_ms": _average(raster_durations) / 1000,
    }
    findings: list[RuntimeFinding] = []
    if janky:
        source = next((item for item in evidence if item.id in janky), None)
        findings.append(
            _finding(
                "runtime.frame.jank",
                "Observed timeline frames exceeded the frame budget",
                "high" if len(janky) >= 5 else "medium",
                "Complete frame events in the imported timeline exceeded 16.67 ms.",
                "Inspect the linked events and their neighboring build and raster work in DevTools.",
                janky,
                source_file=source.source_file if source else None,
                source_line=source.source_line if source else None,
            )
        )
    if expensive:
        source = next((item for item in evidence if item.id in expensive), None)
        findings.append(
            _finding(
                "runtime.render.expensive_event",
                "Observed build, layout, or paint event exceeded the frame budget",
                "medium",
                "The trace contains rendering work whose observed duration alone exceeded one 60 Hz frame budget.",
                "Use the linked trace event and source correlation, when present, to reduce or move the measured work.",
                expensive,
                source_file=source.source_file if source else None,
                source_line=source.source_line if source else None,
            )
        )
    units = _units(
        metrics,
        "ms",
        counters={
            "timeline_event_count",
            "complete_event_count",
            "janky_frame_count",
            "expensive_render_event_count",
        },
    )
    return metrics, units, {}, evidence, findings


def _parse_cpu(payload: dict[str, Any]):
    data = _find_mapping(
        payload,
        lambda item: (
            isinstance(item.get("nodes"), list)
            and (isinstance(item.get("samples"), list) or "startTime" in item)
        ),
    )
    nodes = data.get("nodes", [])
    sample_counts: dict[int, int] = {}
    for sample in data.get("samples", []):
        try:
            sample_id = int(sample)
        except (TypeError, ValueError):
            continue
        sample_counts[sample_id] = sample_counts.get(sample_id, 0) + 1
    ranked: list[tuple[int, str, str | None, int | None, int]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = int(_number(node.get("id"), -1))
        frame = node.get("callFrame") if isinstance(node.get("callFrame"), dict) else node
        hits = sample_counts.get(node_id, int(_number(node.get("hitCount"), 0)))
        if hits <= 0:
            continue
        ranked.append(
            (
                hits,
                redact_secrets(str(frame.get("functionName") or "anonymous"))[:300],
                _safe_source(frame.get("url")),
                _source_line(frame.get("lineNumber")),
                node_id,
            )
        )
    ranked.sort(reverse=True)
    total_samples = max(len(data.get("samples", [])), sum(item[0] for item in ranked), 1)
    evidence = []
    breakdown = []
    for hits, name, source, line, node_id in ranked[:20]:
        share = hits / total_samples * 100
        item = _evidence(
            "cpu_hot_path",
            name,
            f"$.nodes[id={node_id}]",
            value=round(share, 3),
            unit="percent_samples",
            source_file=source,
            source_line=line,
            details={"samples": hits},
        )
        evidence.append(item)
        breakdown.append(
            RuntimeBreakdownItem(
                name=name,
                value=round(share, 3),
                unit="percent_samples",
                trace_reference=item.trace_reference,
            )
        )
    duration = max(
        0,
        _number(data.get("endTime"), 0) - _number(data.get("startTime"), 0),
    )
    metrics = {
        "cpu_sample_count": total_samples,
        "profile_duration_us": duration,
        "top_function_sample_percent": breakdown[0].value if breakdown else 0,
    }
    findings = []
    if evidence and breakdown[0].value >= 20 and total_samples >= 10:
        findings.append(
            _finding(
                "runtime.cpu.hot_path",
                "Observed CPU samples concentrate in one hot path",
                "medium",
                f"The leading stack frame accounts for {breakdown[0].value:.1f}% of imported CPU samples.",
                "Inspect callers and inclusive time around the linked CPU node before changing the sampled function.",
                [evidence[0].id],
                source_file=evidence[0].source_file,
                source_line=evidence[0].source_line,
            )
        )
    return (
        metrics,
        {
            "cpu_sample_count": "count",
            "profile_duration_us": "us",
            "top_function_sample_percent": "percent_samples",
        },
        {"cpu_hot_paths": breakdown},
        evidence,
        findings,
    )


def _parse_memory(payload: dict[str, Any]):
    data = _find_mapping(payload, _looks_like_memory)
    raw_samples = data.get("samples") or data.get("memorySamples") or []
    samples = []
    for index, sample in enumerate(raw_samples):
        if not isinstance(sample, dict):
            continue
        heap = _first_number(sample, "heapUsage", "heap_usage", "usedBytes", "used")
        if heap is None:
            continue
        samples.append(
            (
                index,
                heap,
                _first_number(sample, "heapCapacity", "heap_capacity", "capacityBytes"),
                _first_number(sample, "externalUsage", "external_usage", "externalBytes"),
                _first_number(sample, "timestamp", "timestampUs", "ts"),
            )
        )
    if not samples:
        raise ValueError("no heap-usage samples were found")
    evidence = [
        _evidence(
            "memory_sample",
            "Heap usage sample",
            f"$.samples[{index}]",
            timestamp_us=timestamp,
            value=heap,
            unit="bytes",
            details={
                "heap_capacity_bytes": capacity,
                "external_bytes": external,
            },
        )
        for index, heap, capacity, external, timestamp in samples[:_MAX_EVIDENCE]
    ]
    initial = samples[0][1]
    final = samples[-1][1]
    growth = final - initial
    metrics = {
        "memory_sample_count": len(samples),
        "initial_heap_bytes": initial,
        "final_heap_bytes": final,
        "peak_heap_bytes": max(item[1] for item in samples),
        "memory_growth_bytes": growth,
    }
    findings = []
    if growth > 10 * 1024 * 1024 and growth > initial * 0.2:
        findings.append(
            _finding(
                "runtime.memory.growth",
                "Observed heap usage grew materially during the capture",
                "medium",
                f"Heap usage increased by {growth / 1024 / 1024:.1f} MiB between the first and last imported samples.",
                "Repeat the same interaction, force garbage collection at stable checkpoints, and inspect retaining paths for objects that continue growing.",
                [evidence[0].id, evidence[-1].id],
            )
        )
    return (
        metrics,
        {key: "count" if key == "memory_sample_count" else "bytes" for key in metrics},
        {},
        evidence,
        findings,
    )


def _parse_heap_comparison(payload: dict[str, Any]):
    data = _find_mapping(
        payload,
        lambda item: (
            isinstance(item.get("baseline"), dict) and isinstance(item.get("current"), dict)
        ),
    )
    baseline = _first_number(data["baseline"], "usedBytes", "heapUsage", "size")
    current = _first_number(data["current"], "usedBytes", "heapUsage", "size")
    if baseline is None or current is None:
        raise ValueError("baseline and current heap sizes are required")
    evidence = [
        _evidence("heap_snapshot", "Baseline heap", "$.baseline", value=baseline, unit="bytes"),
        _evidence("heap_snapshot", "Current heap", "$.current", value=current, unit="bytes"),
    ]
    growth = current - baseline
    metrics = {
        "baseline_heap_bytes": baseline,
        "current_heap_bytes": current,
        "memory_growth_bytes": growth,
    }
    findings = []
    if growth > 10 * 1024 * 1024 and growth > baseline * 0.2:
        findings.append(
            _finding(
                "runtime.memory.heap_regression",
                "Observed heap snapshot grew materially",
                "medium",
                f"The current snapshot is {growth / 1024 / 1024:.1f} MiB larger than the baseline snapshot.",
                "Inspect class-level diffs and retaining paths; confirm both snapshots were taken at equivalent stable checkpoints.",
                [item.id for item in evidence],
            )
        )
    return metrics, {key: "bytes" for key in metrics}, {}, evidence, findings


def _parse_app_size(payload: dict[str, Any]):
    root = _find_mapping(payload, _looks_like_app_size)
    items: list[tuple[str, float, str]] = []

    def visit(node: dict[str, Any], reference: str, parent: str = "") -> float:
        name = redact_secrets(str(node.get("name") or node.get("n") or parent or "artifact"))[:300]
        children = node.get("children") or node.get("c") or []
        size = _first_number(node, "size", "value", "bytes", "v")
        child_total = 0.0
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    child_total += visit(child, f"{reference}.children[{index}]", name)
        resolved = size if size is not None else child_total
        if resolved > 0 and not children:
            items.append((name, resolved, reference))
        return resolved

    total = visit(root, "$")
    if total <= 0:
        raise ValueError("no positive size values were found")
    items.sort(key=lambda item: item[1], reverse=True)
    breakdown = [
        RuntimeBreakdownItem(name=name, value=size, unit="bytes", trace_reference=reference)
        for name, size, reference in items[:30]
    ]
    evidence = [
        _evidence(
            "app_size_item", item.name, item.trace_reference or "$", value=item.value, unit="bytes"
        )
        for item in breakdown
    ]
    metrics = {"total_size_bytes": total, "size_item_count": len(items)}
    return (
        metrics,
        {"total_size_bytes": "bytes", "size_item_count": "count"},
        {"largest_items": breakdown},
        evidence,
        [],
    )


def _parse_network(payload: dict[str, Any]):
    data = _find_mapping(
        payload,
        lambda item: (
            isinstance(item.get("log"), dict) and isinstance(item["log"].get("entries"), list)
        ),
    )
    entries = data["log"]["entries"]
    evidence: list[RuntimeEvidence] = []
    slow: list[str] = []
    failed: list[str] = []
    durations: list[float] = []
    total_bytes = 0.0
    for index, entry in enumerate(entries[:_MAX_EVIDENCE]):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        duration = _number(entry.get("time"), 0)
        status = int(_number(response.get("status"), 0))
        size = max(
            0,
            _number(response.get("bodySize"), 0),
            _number(
                response.get("content", {}).get("size")
                if isinstance(response.get("content"), dict)
                else 0,
                0,
            ),
        )
        total_bytes += size
        durations.append(duration)
        method = str(request.get("method") or "GET")[:20]
        url = _safe_url(request.get("url"))
        item = _evidence(
            "network_request",
            f"{method} {url}",
            f"$.log.entries[{index}]",
            duration_us=duration * 1000,
            value=duration,
            unit="ms",
            details={"status": status, "transfer_bytes": size},
        )
        evidence.append(item)
        if duration >= 1000:
            slow.append(item.id)
        if status >= 400 or status == 0:
            failed.append(item.id)
    metrics = {
        "request_count": len(evidence),
        "failed_request_count": len(failed),
        "slow_request_count": len(slow),
        "average_request_duration_ms": _average(durations),
        "total_transfer_bytes": total_bytes,
    }
    findings = []
    if slow:
        findings.append(
            _finding(
                "runtime.network.slow_request",
                "Observed network requests exceeded one second",
                "medium",
                f"{len(slow)} imported request(s) took at least 1000 ms.",
                "Inspect server timing, connection phases, payload size, retries, and whether the request blocks a user-visible interaction.",
                slow,
            )
        )
    if failed:
        findings.append(
            _finding(
                "runtime.network.failed_request",
                "Observed network requests failed",
                "medium",
                f"{len(failed)} imported request(s) returned an error status or no response status.",
                "Correlate the linked request with application retry, timeout, and user-facing failure handling.",
                failed,
            )
        )
    units = {
        "request_count": "count",
        "failed_request_count": "count",
        "slow_request_count": "count",
        "average_request_duration_ms": "ms",
        "total_transfer_bytes": "bytes",
    }
    return metrics, units, {}, evidence, findings


def _metric_deltas(baseline: RuntimeCapture, current: RuntimeCapture) -> list[RuntimeMetricDelta]:
    result = []
    for metric in sorted(baseline.metrics.keys() & current.metrics.keys()):
        before = float(baseline.metrics[metric])
        after = float(current.metrics[metric])
        delta = after - before
        percent = None if before == 0 else delta / abs(before) * 100
        if math.isclose(delta, 0, abs_tol=1e-9):
            direction = "unchanged"
        elif metric in _HIGHER_IS_WORSE:
            direction = "regressed" if delta > 0 else "improved"
        else:
            direction = "informational"
        result.append(
            RuntimeMetricDelta(
                metric=metric,
                unit=current.metric_units.get(metric)
                or baseline.metric_units.get(metric)
                or "value",
                baseline=before,
                current=after,
                delta=delta,
                percent_change=percent,
                direction=direction,
            )
        )
    return result


def _mapping_candidates(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    queue: list[tuple[dict[str, Any], int]] = [(payload, 0)]
    seen: set[int] = set()
    while queue:
        item, depth = queue.pop(0)
        if id(item) in seen:
            continue
        seen.add(id(item))
        yield item
        if depth >= 4:
            continue
        for key in (
            "data",
            "timeline",
            "profile",
            "cpuProfile",
            "memory",
            "snapshot",
            "summary",
            "analysis",
        ):
            child = item.get(key)
            if isinstance(child, dict):
                queue.append((child, depth + 1))


def _find_mapping(payload: dict[str, Any], predicate) -> dict[str, Any]:
    for candidate in _mapping_candidates(payload):
        if predicate(candidate):
            return candidate
    raise ValueError("expected data structure was not found")


def _metadata(payload: dict[str, Any]) -> dict[str, Any]:
    combined: dict[str, Any] = {}
    for candidate in _mapping_candidates(payload):
        metadata = candidate.get("metadata")
        if isinstance(metadata, dict):
            combined.update(metadata)
        for key in (
            "build_mode",
            "buildMode",
            "mode",
            "flutter_version",
            "flutterVersion",
            "devtools_version",
            "devToolsVersion",
            "dart_version",
            "dartVersion",
            "dartSdkVersion",
            "captured_at",
            "capturedAt",
            "timestamp",
        ):
            if key in candidate and not isinstance(candidate[key], (dict, list)):
                combined.setdefault(key, candidate[key])
    return combined


def _has_frame_summary(item: dict[str, Any]) -> bool:
    return "frame_count" in item and (
        "frame_build_times" in item or "average_frame_build_time_millis" in item
    )


def _looks_like_memory(item: dict[str, Any]) -> bool:
    samples = item.get("samples") or item.get("memorySamples")
    if not isinstance(samples, list) or not samples:
        return False
    return any(
        isinstance(sample, dict)
        and any(key in sample for key in ("heapUsage", "heap_usage", "usedBytes"))
        for sample in samples[:10]
    )


def _looks_like_app_size(item: dict[str, Any]) -> bool:
    children = item.get("children") or item.get("c")
    return isinstance(children, list) and any(
        key in item for key in ("size", "value", "bytes", "v", "name", "n")
    )


def _format_name(kind: RuntimeArtifactKind, payload: dict[str, Any]) -> str:
    if kind == RuntimeArtifactKind.NETWORK_TRACE:
        return "HAR 1.x"
    if kind == RuntimeArtifactKind.TIMELINE:
        return "Chrome trace event JSON"
    if kind == RuntimeArtifactKind.FRAME_TIMING:
        return "Flutter TimelineSummary JSON"
    if kind == RuntimeArtifactKind.CPU_PROFILE:
        return "DevTools/Chrome CPU profile JSON"
    if kind in {RuntimeArtifactKind.MEMORY_SNAPSHOT, RuntimeArtifactKind.HEAP_COMPARISON}:
        return "Flutter memory summary JSON"
    if kind == RuntimeArtifactKind.APP_SIZE:
        return "Flutter analyze-size JSON"
    return str(payload.get("type") or "JSON")


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    explanation: str,
    recommendation: str,
    evidence_ids: list[str],
    *,
    source_file: str | None = None,
    source_line: int | None = None,
) -> RuntimeFinding:
    return RuntimeFinding(
        id=uuid.uuid4().hex,
        rule_id=rule_id,
        rule_version=RUNTIME_RULE_PACK_VERSION,
        title=title,
        severity=severity,
        confidence=0.98,
        explanation=explanation,
        recommendation=recommendation,
        evidence_ids=evidence_ids,
        source_file=source_file,
        source_line=source_line,
    )


def _evidence(
    kind: str,
    name: str,
    reference: str,
    *,
    timestamp_us: float | None = None,
    duration_us: float | None = None,
    value: float | None = None,
    unit: str | None = None,
    thread: str | None = None,
    source_file: str | None = None,
    source_line: int | None = None,
    details: dict[str, Any] | None = None,
) -> RuntimeEvidence:
    identity = f"{kind}\0{reference}\0{name}"
    return RuntimeEvidence(
        id=f"evidence:{hashlib.sha256(identity.encode()).hexdigest()[:24]}",
        kind=kind,
        name=redact_secrets(name),
        trace_reference=reference,
        timestamp_us=timestamp_us,
        duration_us=duration_us,
        value=value,
        unit=unit,
        thread=thread,
        source_file=source_file,
        source_line=source_line,
        details={key: _safe_detail(value) for key, value in (details or {}).items()},
    )


def _units(metrics: dict[str, float | int], default: str, *, counters: set[str]) -> dict[str, str]:
    return {key: "count" if key in counters else default for key in metrics}


def _numbers(value: Any) -> list[float]:
    if not isinstance(value, list):
        return []
    return [number for item in value if (number := _optional_number(item)) is not None]


def _number(value: Any, default: float) -> float:
    number = _optional_number(value)
    return float(default) if number is None else number


def _optional_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _first_number(item: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = _optional_number(item.get(key))
        if value is not None:
            return value
    return None


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _build_mode(value: Any) -> RuntimeBuildMode:
    normalized = str(value or "").strip().lower()
    return (
        RuntimeBuildMode(normalized)
        if normalized in {item.value for item in RuntimeBuildMode}
        else RuntimeBuildMode.UNKNOWN
    )


def _datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = redact_secrets(str(value)).strip()
    return text[:300] or None


def _source_line(value: Any) -> int | None:
    number = _optional_number(value)
    return max(1, int(number) + 1) if number is not None and number >= 0 else None


def _safe_source(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    if text.startswith("file://"):
        return urlsplit(text).path
    return text


def _safe_url(value: Any) -> str:
    text = str(value or "unknown")
    try:
        parsed = urlsplit(text)
        if parsed.scheme and parsed.netloc:
            return redact_secrets(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))[
                :500
            ]
    except ValueError:
        pass
    return redact_secrets(text.split("?", 1)[0].split("#", 1)[0])[:500]


def _safe_detail(value: Any) -> str | float | int | bool | None:
    if value is None or isinstance(value, (float, int, bool)):
        return value
    return redact_secrets(str(value))[:500]
