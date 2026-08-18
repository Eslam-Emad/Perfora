import json
from pathlib import Path

import pytest

from perfora.database import AuditStore
from perfora.domain import (
    RepositorySnapshot,
    RuntimeArtifactKind,
    RuntimeBuildMode,
    RuntimeImportRequest,
    RuntimeReliability,
)
from perfora.runtime_artifacts import RuntimeArtifactService

FIXTURES = Path(__file__).parent / "fixtures" / "runtime"


def _repository(path: Path) -> RepositorySnapshot:
    return RepositorySnapshot(
        path=str(path),
        name="runtime_fixture",
        valid=True,
        detail="Flutter repository",
        is_flutter=True,
        is_git=True,
        branch="main",
        commit_sha="abc123",
    )


def _service(tmp_path: Path) -> RuntimeArtifactService:
    return RuntimeArtifactService(AuditStore(tmp_path / "runtime.db"))


def _request(
    tmp_path: Path,
    payload: dict,
    *,
    filename: str = "capture.json",
    kind: RuntimeArtifactKind = RuntimeArtifactKind.AUTO,
    mode: RuntimeBuildMode = RuntimeBuildMode.PROFILE,
) -> RuntimeImportRequest:
    return RuntimeImportRequest(
        repository_path=str(tmp_path),
        filename=filename,
        content=json.dumps(payload),
        kind=kind,
        build_mode=mode,
        flutter_version="3.35.0",
        devtools_version="2.48.0",
    )


@pytest.mark.parametrize(
    ("filename", "selected_kind", "expected_kind"),
    [
        ("frame_timing.json", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.FRAME_TIMING),
        ("timeline.json", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.TIMELINE),
        ("cpu_profile.json", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.CPU_PROFILE),
        ("memory_snapshot.json", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.MEMORY_SNAPSHOT),
        (
            "heap_comparison.json",
            RuntimeArtifactKind.HEAP_COMPARISON,
            RuntimeArtifactKind.HEAP_COMPARISON,
        ),
        ("app_size.json", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.APP_SIZE),
        ("network.har", RuntimeArtifactKind.AUTO, RuntimeArtifactKind.NETWORK_TRACE),
    ],
)
def test_runtime_fixture_families_import_with_embedded_provenance(
    tmp_path: Path,
    filename: str,
    selected_kind: RuntimeArtifactKind,
    expected_kind: RuntimeArtifactKind,
) -> None:
    service = _service(tmp_path)
    capture = service.import_capture(
        RuntimeImportRequest(
            repository_path=str(tmp_path),
            filename=filename,
            content=(FIXTURES / filename).read_text(),
            kind=selected_kind,
        ),
        _repository(tmp_path),
    )

    assert capture.kind == expected_kind
    assert capture.reliability == RuntimeReliability.TRUSTED
    assert capture.provenance.build_mode_source == "artifact"
    assert capture.metrics


def test_imports_profile_frame_timings_with_observed_evidence(tmp_path: Path) -> None:
    service = _service(tmp_path)
    capture = service.import_capture(
        _request(
            tmp_path,
            {
                "frame_count": 4,
                "average_frame_build_time_millis": 8.0,
                "worst_frame_build_time_millis": 24.0,
                "missed_frame_build_budget_count": 1,
                "average_frame_rasterizer_time_millis": 13.0,
                "worst_frame_rasterizer_time_millis": 31.0,
                "missed_frame_rasterizer_budget_count": 1,
                "frame_build_times": [4000, 24000, 5000, 6000],
                "frame_rasterizer_times": [5000, 6000, 31000, 8000],
            },
        ),
        _repository(tmp_path),
    )

    assert capture.kind == RuntimeArtifactKind.FRAME_TIMING
    assert capture.reliability == RuntimeReliability.TRUSTED
    assert capture.provenance.flutter_version == "3.35.0"
    assert capture.provenance.devtools_version == "2.48.0"
    assert capture.metrics["janky_frame_count"] == 2
    assert capture.findings[0].rule_id == "runtime.frame.jank"
    assert set(capture.findings[0].evidence_ids) == {item.id for item in capture.evidence}
    assert all(item.trace_reference.startswith("$.") for item in capture.evidence)


def test_debug_capture_is_labeled_unreliable_and_withholds_findings(tmp_path: Path) -> None:
    service = _service(tmp_path)
    capture = service.import_capture(
        _request(
            tmp_path,
            {
                "metadata": {"buildMode": "debug"},
                "frame_count": 1,
                "frame_build_times": [40000],
                "frame_rasterizer_times": [5000],
            },
            mode=RuntimeBuildMode.PROFILE,
        ),
        _repository(tmp_path),
    )

    assert capture.reliability == RuntimeReliability.UNRELIABLE
    assert capture.provenance.build_mode == RuntimeBuildMode.DEBUG
    assert capture.provenance.build_mode_source == "artifact"
    assert capture.findings == []
    assert any("conflicts" in warning for warning in capture.warnings)
    assert any("Debug-mode" in warning for warning in capture.warnings)
    assert any("withheld" in warning for warning in capture.warnings)


def test_har_import_never_persists_query_secrets_headers_or_bodies(tmp_path: Path) -> None:
    service = _service(tmp_path)
    payload = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "time": 1450,
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/users?access_token=secret-value",
                        "headers": [{"name": "Authorization", "value": "Bearer secret"}],
                    },
                    "response": {
                        "status": 503,
                        "bodySize": 512,
                        "content": {"size": 512, "text": "private response"},
                    },
                }
            ],
        }
    }
    capture = service.import_capture(
        _request(tmp_path, payload, filename="network.har"),
        _repository(tmp_path),
    )

    serialized = capture.model_dump_json()
    assert "access_token" not in serialized
    assert "secret-value" not in serialized
    assert "Authorization" not in serialized
    assert "private response" not in serialized
    assert capture.evidence[0].name == "GET https://api.example.test/users"
    assert {item.rule_id for item in capture.findings} == {
        "runtime.network.failed_request",
        "runtime.network.slow_request",
    }


def test_imports_cpu_memory_and_app_size_artifact_families(tmp_path: Path) -> None:
    service = _service(tmp_path)
    repository = _repository(tmp_path)
    cpu = service.import_capture(
        _request(
            tmp_path,
            {
                "nodes": [
                    {
                        "id": 1,
                        "callFrame": {
                            "functionName": "buildDashboard",
                            "url": "lib/dashboard.dart",
                            "lineNumber": 41,
                        },
                    },
                    {"id": 2, "callFrame": {"functionName": "idle"}},
                ],
                "samples": [1] * 8 + [2] * 2,
                "startTime": 0,
                "endTime": 20000,
            },
        ),
        repository,
    )
    memory = service.import_capture(
        _request(
            tmp_path,
            {
                "samples": [
                    {"timestampUs": 1, "heapUsage": 20_000_000},
                    {"timestampUs": 2, "heapUsage": 45_000_000},
                ]
            },
        ),
        repository,
    )
    app_size = service.import_capture(
        _request(
            tmp_path,
            {
                "name": "app",
                "children": [
                    {"name": "package:feature", "size": 7_000_000},
                    {"name": "assets", "size": 3_000_000},
                ],
            },
            mode=RuntimeBuildMode.RELEASE,
        ),
        repository,
    )

    assert cpu.kind == RuntimeArtifactKind.CPU_PROFILE
    assert cpu.findings[0].source_file == "lib/dashboard.dart"
    assert cpu.findings[0].source_line == 42
    assert memory.kind == RuntimeArtifactKind.MEMORY_SNAPSHOT
    assert memory.metrics["memory_growth_bytes"] == 25_000_000
    assert memory.findings[0].rule_id == "runtime.memory.growth"
    assert app_size.kind == RuntimeArtifactKind.APP_SIZE
    assert app_size.reliability == RuntimeReliability.TRUSTED
    assert app_size.metrics["total_size_bytes"] == 10_000_000
    assert app_size.breakdowns["largest_items"][0].name == "package:feature"


def test_imports_timeline_source_correlation_and_heap_comparison(tmp_path: Path) -> None:
    service = _service(tmp_path)
    repository = _repository(tmp_path)
    timeline = service.import_capture(
        _request(
            tmp_path,
            {
                "traceEvents": [
                    {
                        "ph": "X",
                        "name": "Flutter.Frame",
                        "cat": "UI",
                        "ts": 1000,
                        "dur": 28000,
                        "tid": "ui",
                        "args": {"file": "lib/checkout.dart", "lineNumber": 27},
                    },
                    {
                        "ph": "X",
                        "name": "Rasterizer::Draw",
                        "cat": "Raster",
                        "ts": 30000,
                        "dur": 9000,
                        "tid": "raster",
                    },
                ]
            },
        ),
        repository,
    )
    heap = service.import_capture(
        _request(
            tmp_path,
            {
                "baseline": {"usedBytes": 20_000_000},
                "current": {"usedBytes": 50_000_000},
            },
            kind=RuntimeArtifactKind.HEAP_COMPARISON,
        ),
        repository,
    )

    assert timeline.kind == RuntimeArtifactKind.TIMELINE
    assert timeline.findings[0].source_file == "lib/checkout.dart"
    assert timeline.findings[0].source_line == 28
    assert timeline.findings[0].evidence_ids == [timeline.evidence[0].id]
    assert heap.kind == RuntimeArtifactKind.HEAP_COMPARISON
    assert heap.metrics["memory_growth_bytes"] == 30_000_000
    assert heap.findings[0].evidence_ids == [item.id for item in heap.evidence]


def test_persists_and_compares_compatible_runtime_captures(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "runtime.db")
    service = RuntimeArtifactService(store)
    repository = _repository(tmp_path)
    baseline = service.import_capture(
        _request(
            tmp_path,
            {
                "frame_count": 2,
                "frame_build_times": [5000, 18000],
                "frame_rasterizer_times": [5000, 6000],
            },
            filename="before.json",
        ),
        repository,
    )
    current = service.import_capture(
        _request(
            tmp_path,
            {
                "frame_count": 2,
                "frame_build_times": [4000, 8000],
                "frame_rasterizer_times": [4000, 5000],
            },
            filename="after.json",
        ),
        repository,
    )

    comparison = service.compare(baseline.id, current.id)

    assert store.schema_version == 2
    assert store.get_runtime_capture(current.id) == current
    assert [item.id for item in store.list_runtime_captures(str(tmp_path))] == [
        current.id,
        baseline.id,
    ]
    assert comparison.compatible is True
    jank = next(item for item in comparison.metric_deltas if item.metric == "janky_frame_count")
    assert jank.delta == -1
    assert jank.direction == "improved"
    assert comparison.resolved_finding_rule_ids == ["runtime.frame.jank"]
