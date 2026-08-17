import json
from pathlib import Path

from perfora.ci_report import export_cyclonedx
from perfora.supply_chain import compare_dependencies, inventory_dependencies


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_inventories_flutter_and_native_dependency_managers_without_network(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "pubspec.lock",
        """packages:
  firebase_analytics:
    dependency: "direct main"
    source: hosted
    version: "12.0.0"
  collection:
    dependency: transitive
    source: hosted
    version: "1.19.1"
""",
    )
    _write(
        tmp_path / "ios" / "Podfile.lock",
        """PODS:
  - FirebaseAnalytics (12.0.0)
  - Sentry/HybridSDK (8.0.0)
DEPENDENCIES:
  - FirebaseAnalytics
""",
    )
    _write(
        tmp_path / "android" / "gradle.lockfile",
        "com.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\n",
    )
    _write(
        tmp_path / "ios" / "Package.resolved",
        json.dumps(
            {
                "version": 2,
                "pins": [
                    {
                        "identity": "swift-collections",
                        "state": {"version": "1.1.4"},
                    }
                ],
            }
        ),
    )
    _write(
        tmp_path / ".flutter-plugins-dependencies",
        json.dumps(
            {
                "plugins": {
                    "android": [{"name": "dynatrace_flutter_plugin"}],
                    "ios": [{"name": "dynatrace_flutter_plugin"}],
                }
            }
        ),
    )
    (tmp_path / "ios" / "Vendor" / "Telemetry.xcframework").mkdir(parents=True)

    inventory = inventory_dependencies(tmp_path)

    assert inventory.vulnerability_matching == "not_requested"
    assert set(inventory.coverage_by_ecosystem) == {
        "apple-framework",
        "cocoapods",
        "flutter-plugin",
        "gradle",
        "pub",
        "swift",
    }
    assert inventory.license_counts["unknown"] == len(inventory.components)
    assert inventory.privacy_sdk_counts == {
        "analytics": 2,
        "crash_and_performance": 2,
    }
    firebase = next(
        item
        for item in inventory.components
        if item.ecosystem == "pub" and item.name == "firebase_analytics"
    )
    assert firebase.direct is True
    assert firebase.purl == "pkg:pub/firebase_analytics@12.0.0"


def test_reports_dependency_add_remove_and_version_change(tmp_path: Path) -> None:
    baseline_root = tmp_path / "baseline"
    current_root = tmp_path / "current"
    _write(
        baseline_root / "pubspec.lock",
        """packages:
  alpha:
    dependency: "direct main"
    version: "1.0.0"
  removed:
    dependency: transitive
    version: "1.0.0"
""",
    )
    _write(
        current_root / "pubspec.lock",
        """packages:
  alpha:
    dependency: "direct main"
    version: "2.0.0"
  added:
    dependency: transitive
    version: "1.0.0"
""",
    )

    changes = compare_dependencies(
        inventory_dependencies(current_root), inventory_dependencies(baseline_root)
    )

    assert [item.name for item in changes.added] == ["added"]
    assert [item.name for item in changes.removed] == ["removed"]
    assert changes.updated[0].name == "alpha"
    assert changes.updated[0].from_version == "1.0.0"
    assert changes.updated[0].to_version == "2.0.0"


def test_uses_local_package_metadata_for_license_inventory(tmp_path: Path) -> None:
    _write(
        tmp_path / "pubspec.lock",
        """packages:
  local_package:
    dependency: transitive
    version: "1.0.0"
""",
    )
    _write(
        tmp_path / ".dart_tool" / "package_config.json",
        json.dumps(
            {
                "configVersion": 2,
                "packages": [
                    {
                        "name": "local_package",
                        "rootUri": "../local_package",
                        "packageUri": "lib/",
                    }
                ],
            }
        ),
    )
    _write(
        tmp_path / "local_package" / "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge, to any person...",
    )

    inventory = inventory_dependencies(tmp_path)

    component = next(item for item in inventory.components if item.name == "local_package")
    assert component.license == "MIT"
    assert inventory.license_counts == {"MIT": 1}


def test_exports_cyclonedx_17_with_provenance_and_privacy_properties(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "pubspec.lock",
        """packages:
  firebase_analytics:
    dependency: "direct main"
    version: "12.0.0"
""",
    )
    inventory = inventory_dependencies(tmp_path)
    report = {
        "tool": {"version": "0.3.0"},
        "generated_at": "2026-08-17T12:00:00+00:00",
        "repository": {
            "name": "fixture",
            "path": str(tmp_path),
            "commit": "abc123",
        },
        "dependency_inventory": inventory.model_dump(mode="json"),
    }

    payload = json.loads(export_cyclonedx(report))

    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.7"
    assert payload["serialNumber"].startswith("urn:uuid:")
    assert payload["metadata"]["component"]["name"] == "fixture"
    assert payload["components"][0]["purl"] == "pkg:pub/firebase_analytics@12.0.0"
    properties = {item["name"]: item["value"] for item in payload["components"][0]["properties"]}
    assert properties["perfora:privacy-sensitive"] == "true"
    assert properties["perfora:license-status"] == "unknown"
