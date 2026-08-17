from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import yaml

from .domain import (
    DependencyChangeReport,
    DependencyComponent,
    DependencyInventory,
    DependencyVersionChange,
)

_IGNORED_PARTS = {
    ".git",
    ".dart_tool",
    ".gradle",
    ".perfora-tool",
    ".pub-cache",
    ".symlinks",
    "build",
    "DerivedData",
    "node_modules",
}
_PRIVACY_SDKS = {
    "advertising": ("appsflyer", "adjust", "facebook_app_events", "google_mobile_ads"),
    "analytics": (
        "firebase_analytics",
        "amplitude",
        "mixpanel",
        "segment",
        "medallia",
    ),
    "crash_and_performance": (
        "firebase_crashlytics",
        "dynatrace",
        "newrelic",
        "datadog",
        "sentry",
    ),
    "location": ("geolocator", "location", "google_maps"),
    "engagement": ("braze", "clevertap", "moengage", "onesignal"),
}


def inventory_dependencies(repository: Path) -> DependencyInventory:
    repository = repository.resolve()
    components: dict[tuple[str, str], DependencyComponent] = {}
    manifests: set[str] = set()

    for file in _files(repository, "pubspec.lock"):
        manifests.add(_relative(file, repository))
        _merge(components, _pub_components(file, repository))
    for file in _files(repository, "Podfile.lock"):
        manifests.add(_relative(file, repository))
        _merge(components, _pod_components(file, repository))
    for file in _files(repository, "gradle.lockfile"):
        manifests.add(_relative(file, repository))
        _merge(components, _gradle_lock_components(file, repository))
    for pattern in ("build.gradle", "build.gradle.kts"):
        for file in _files(repository, pattern):
            manifests.add(_relative(file, repository))
            _merge(components, _gradle_build_components(file, repository))
    for file in _files(repository, "Package.resolved"):
        manifests.add(_relative(file, repository))
        _merge(components, _swift_components(file, repository))
    for file in _files(repository, ".flutter-plugins-dependencies"):
        manifests.add(_relative(file, repository))
        _merge(components, _flutter_plugin_components(file, repository))

    for candidate in repository.rglob("*"):
        if not candidate.is_dir() or _ignored(candidate, repository):
            continue
        if candidate.suffix not in {".framework", ".xcframework"}:
            continue
        relative = _relative(candidate, repository)
        manifests.add(relative)
        component = _component(
            candidate.stem,
            "unknown",
            "apple-framework",
            relative,
            scope="required",
        )
        components.setdefault((component.ecosystem, component.name.lower()), component)

    license_evidence = {
        **{("pub", name.lower()): license_id for name, license_id in _pub_licenses(repository).items()},
        **{
            ("cocoapods", name.lower()): license_id
            for name, license_id in _pod_licenses(repository).items()
        },
    }
    for key, component in components.items():
        component.license = license_evidence.get(key)

    ordered = sorted(components.values(), key=lambda item: (item.ecosystem, item.name.lower()))
    coverage = Counter(item.ecosystem for item in ordered)
    licenses = Counter(item.license or "unknown" for item in ordered)
    privacy = Counter(
        item.privacy_category for item in ordered if item.privacy_sensitive and item.privacy_category
    )
    return DependencyInventory(
        components=ordered,
        manifests=sorted(manifests),
        coverage_by_ecosystem=dict(sorted(coverage.items())),
        license_counts=dict(sorted(licenses.items())),
        privacy_sdk_counts=dict(sorted(privacy.items())),
    )


def compare_dependencies(
    current: DependencyInventory, baseline: DependencyInventory
) -> DependencyChangeReport:
    current_map = {(item.ecosystem, item.name.lower()): item for item in current.components}
    baseline_map = {(item.ecosystem, item.name.lower()): item for item in baseline.components}
    added = [current_map[key] for key in sorted(current_map.keys() - baseline_map.keys())]
    removed = [baseline_map[key] for key in sorted(baseline_map.keys() - current_map.keys())]
    updated = []
    for key in sorted(current_map.keys() & baseline_map.keys()):
        before = baseline_map[key]
        after = current_map[key]
        if before.version != after.version:
            updated.append(
                DependencyVersionChange(
                    ecosystem=after.ecosystem,
                    name=after.name,
                    from_version=before.version,
                    to_version=after.version,
                )
            )
    return DependencyChangeReport(added=added, removed=removed, updated=updated)


def _files(repository: Path, name: str) -> list[Path]:
    return [
        file
        for file in repository.rglob(name)
        if file.is_file() and not _ignored(file, repository)
    ]


def _ignored(candidate: Path, repository: Path) -> bool:
    return bool(_IGNORED_PARTS.intersection(candidate.relative_to(repository).parts))


def _relative(candidate: Path, repository: Path) -> str:
    return candidate.relative_to(repository).as_posix()


def _merge(
    target: dict[tuple[str, str], DependencyComponent],
    incoming: list[DependencyComponent],
) -> None:
    for component in incoming:
        key = (component.ecosystem, component.name.lower())
        existing = target.get(key)
        if existing is None or existing.version == "unknown":
            target[key] = component


def _component(
    name: str,
    version: str,
    ecosystem: str,
    source_file: str,
    *,
    scope: str = "unknown",
    direct: bool | None = None,
) -> DependencyComponent:
    privacy_category = _privacy_category(name)
    purl_type = {"cocoapods": "cocoapods", "gradle": "maven", "swift": "swift", "pub": "pub"}.get(
        ecosystem
    )
    purl = None
    if purl_type and version != "unknown":
        purl = f"pkg:{purl_type}/{quote(name, safe='/')}@{quote(version, safe='')}"
    identity = f"{ecosystem}\0{name.lower()}\0{version}"
    return DependencyComponent(
        bom_ref=f"urn:perfora:{hashlib.sha256(identity.encode()).hexdigest()}",
        name=name,
        version=version or "unknown",
        ecosystem=ecosystem,
        source_file=source_file,
        scope=scope,
        direct=direct,
        purl=purl,
        privacy_category=privacy_category,
        privacy_sensitive=privacy_category is not None,
    )


def _privacy_category(name: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    for category, markers in _PRIVACY_SDKS.items():
        if any(re.sub(r"[^a-z0-9]", "", marker.lower()) in normalized for marker in markers):
            return category
    return None


def _pub_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        return []
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(packages, dict):
        return []
    result = []
    for name, details in packages.items():
        if not isinstance(details, dict):
            continue
        dependency = details.get("dependency")
        result.append(
            _component(
                str(name),
                str(details.get("version") or "unknown"),
                "pub",
                _relative(file, repository),
                scope="excluded" if dependency == "direct dev" else "required",
                direct=dependency in {"direct main", "direct dev"},
            )
        )
    return result


def _pod_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        content = file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    result = []
    in_pods = False
    for line in content.splitlines():
        if line == "PODS:":
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        match = re.match(r"^  - ([A-Za-z0-9_.+/-]+) \(([^ :()]+)", line)
        if match:
            result.append(
                _component(
                    match.group(1),
                    match.group(2),
                    "cocoapods",
                    _relative(file, repository),
                    scope="required",
                )
            )
    return result


def _gradle_lock_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        content = file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    result = []
    for match in re.finditer(r"(?m)^([\w.-]+):([\w.-]+):([^=\s]+)=", content):
        result.append(
            _component(
                f"{match.group(1)}:{match.group(2)}",
                match.group(3),
                "gradle",
                _relative(file, repository),
                scope="required",
            )
        )
    return result


def _gradle_build_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        content = file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    pattern = re.compile(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['\"]"
        r"([\w.-]+):([\w.-]+):([^'\"\s)]+)"
    )
    result = []
    for match in pattern.finditer(content):
        configuration = content[match.start() : match.start(0) + 24]
        result.append(
            _component(
                f"{match.group(1)}:{match.group(2)}",
                match.group(3),
                "gradle",
                _relative(file, repository),
                scope="excluded" if "testImplementation" in configuration else "required",
            )
        )
    return result


def _swift_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    pins = payload.get("pins", payload.get("object", {}).get("pins", []))
    result = []
    for pin in pins if isinstance(pins, list) else []:
        if not isinstance(pin, dict):
            continue
        state = pin.get("state") or {}
        name = pin.get("identity") or pin.get("package")
        version = state.get("version") or state.get("revision") or "unknown"
        if name:
            result.append(
                _component(
                    str(name),
                    str(version),
                    "swift",
                    _relative(file, repository),
                    scope="required",
                )
            )
    return result


def _flutter_plugin_components(file: Path, repository: Path) -> list[DependencyComponent]:
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    plugins = payload.get("plugins") if isinstance(payload, dict) else None
    if not isinstance(plugins, dict):
        return []
    names: set[str] = set()
    for entries in plugins.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                names.add(str(entry["name"]))
    return [
        _component(
            name,
            "unknown",
            "flutter-plugin",
            _relative(file, repository),
            scope="required",
            direct=None,
        )
        for name in sorted(names)
    ]


def _pub_licenses(repository: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for config in repository.rglob("package_config.json"):
        if ".dart_tool" not in config.relative_to(repository).parts:
            continue
        try:
            payload = json.loads(config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        for package in payload.get("packages", []):
            if not isinstance(package, dict) or not package.get("name") or not package.get("rootUri"):
                continue
            root = _uri_path(str(package["rootUri"]), config.parent)
            if root is None:
                continue
            license_id = _license_from_directory(root)
            if license_id:
                result[str(package["name"])] = license_id
    return result


def _pod_licenses(repository: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for podspec in repository.rglob("*.podspec.json"):
        if "Pods" not in podspec.relative_to(repository).parts:
            continue
        try:
            payload = json.loads(podspec.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or not payload.get("name"):
            continue
        license_value = payload.get("license")
        if isinstance(license_value, dict):
            license_value = license_value.get("type")
        if isinstance(license_value, str) and license_value.strip():
            result[str(payload["name"])] = license_value.strip()
    return result


def _uri_path(value: str, base: Path) -> Path | None:
    parsed = urlparse(value)
    try:
        if parsed.scheme == "file":
            return Path(unquote(parsed.path)).resolve()
        if parsed.scheme:
            return None
        return (base / unquote(value)).resolve()
    except OSError:
        return None


def _license_from_directory(directory: Path) -> str | None:
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"):
        file = directory / name
        if not file.is_file():
            continue
        try:
            content = file.read_text(encoding="utf-8", errors="ignore")[:16000].lower()
        except OSError:
            continue
        signatures = (
            ("apache license", "Apache-2.0"),
            ("mit license", "MIT"),
            ("permission is hereby granted, free of charge", "MIT"),
            ("redistribution and use in source and binary forms", "BSD-3-Clause"),
            ("mozilla public license version 2.0", "MPL-2.0"),
            ("gnu general public license", "GPL"),
        )
        for marker, license_id in signatures:
            if marker in content:
                return license_id
        return "detected-unclassified"
    return None
