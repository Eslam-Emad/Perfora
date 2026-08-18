# Perfora support and scan-coverage matrix

This document defines what Perfora `0.4` inspects through static audits and
imported runtime artifacts. The recorded `scan_coverage` object remains the
authoritative static per-run result.

## Product environment

| Area | Supported | Current boundary |
| --- | --- | --- |
| Host application | macOS | Manual absolute paths can work elsewhere but are not certified |
| Repository | Local Flutter repository or monorepo | At least one Flutter `pubspec.yaml` is required |
| Git | Branch, commit, and worktree metadata | Non-Git Flutter directories can be inspected with reduced provenance |
| Dart SDK | Dart 3.5 or newer | Analyzer dependencies must be installed locally |
| Symlinks | Not followed | Symlink targets are outside the declared scan coverage |

## Static rule packs

| Rule pack | Inspected inputs | Deterministic coverage |
| --- | --- | --- |
| `performance@1.0.0` | Supported Dart source | Owned lifecycle resources without matching cleanup |
| `security@2.0.0` | Supported Dart source | Credentials, cleartext URLs, certificate acceptance, sensitive logging/storage/clipboard use, WebView options, weak crypto, randomness, and screenshot heuristics |
| `security@2.0.0` | `android/app/src/*/AndroidManifest.xml` | Cleartext, backup/debug flags, exported components, selected high-impact permissions, and HTTP deep links |
| `security@2.0.0` | `ios/Runner/Info.plist`, `ios/**/*.entitlements` | Global ATS exception, selected privacy capabilities, custom URL schemes, and debugger entitlement |

Every security rule carries its OWASP control group, platform applicability,
references, limitations, manual verification, and false-positive guidance. See
[mobile security rules](./security-rules.md). Coverage is shown by control group
and platform; Perfora deliberately provides no aggregate security score.

## Dependency and privacy inventory

| Ecosystem | Inputs | Recorded evidence |
| --- | --- | --- |
| Dart/Flutter | `pubspec.lock`, `.flutter-plugins-dependencies` | Name, version where available, direct/dev scope, purl, plugin presence |
| Android | `gradle.lockfile`, `build.gradle`, `build.gradle.kts` | Maven coordinate, version, source manifest |
| CocoaPods | `Podfile.lock`, local podspec JSON | Pod/subspec, version, locally declared license where available |
| Swift Package Manager | `Package.resolved` | Identity and pinned version/revision |
| Bundled Apple frameworks | `.framework`, `.xcframework` directories | Bundle name and repository-relative location |

License values are reported only when local package metadata provides evidence;
otherwise they remain `unknown`. Privacy categories are transparent name-based
inventory hints, not claims about runtime collection. CycloneDX uses schema 1.7
and marks composition completeness `unknown`. Online vulnerability matching is
not performed.

The analyzer version is stored separately from the rule-pack version. Updating
the implementation does not silently change the version attached to old audits.

## Runtime artifact imports

| Artifact family | Accepted evidence | Current analysis |
| --- | --- | --- |
| DevTools/Chrome timeline JSON | Complete trace events with names, timestamps, durations, threads, and optional source fields | Janky frames, UI/raster duration summaries, expensive build/layout/paint events |
| CPU profile JSON | Nodes, samples/hit counts, timestamps, call-frame source fields | Sample concentration and hot-path breakdown |
| Memory summary JSON | Timestamped heap-usage samples | Initial/final/peak heap and material observed growth |
| Heap comparison JSON | Explicit baseline/current heap byte values | Heap delta and material regression |
| Flutter `TimelineSummary` JSON | Frame build/raster arrays and summary fields | Budget misses and linked UI/raster frame evidence |
| Flutter analyze-size JSON | Hierarchical name/size tree | Total bytes, largest items, and before/after size delta |
| HAR 1.x | Request method/URL, response status/size, total duration | Slow/failed request observations and aggregate timing/bytes |

Raw artifacts are not persisted. Perfora stores the SHA-256 hash, filename,
format, declared or embedded build mode, available Flutter/Dart/DevTools
versions, sanitized metrics, bounded evidence, and JSON trace references.
Network query strings, headers, request/response bodies, and cookies are not
retained. Artifact JSON is limited to 25 MB.

Profile mode is required for trusted timing, CPU, memory, and network findings.
Release mode is trusted only for app-size analysis. Debug artifacts are labeled
`unreliable`; unknown-mode artifacts are `unverified`. Both may retain metrics
for inspection but their threshold findings are withheld. Comparisons require
the same repository path and artifact family and warn on tool-version drift.

## Exclusions and skip reasons

| Input | Coverage result | Reason key |
| --- | --- | --- |
| `.git`, `.dart_tool`, `.pub-cache`, `.symlinks`, `DerivedData`, `Pods`, `build`, `node_modules` | Skipped | `ignored_directory` |
| `.g.dart`, `.freezed.dart`, `.gr.dart`, `.config.dart` | Skipped | `generated_source` |
| Invalid UTF-8, binary, or unreadable supported file | Skipped | `unreadable_or_binary` |
| File type not used by the selected rule pack | Skipped | `unsupported_file` |
| Parseable Dart with syntax or semantic diagnostics | Best-effort scan | Counted under `dart`; findings may be incomplete |

Every skipped file contributes to `files_skipped` and exactly one
`skipped_by_reason` counter. Scanned files are grouped in `scanned_by_type`.
Analyzer `0.5` also records every repository-relative scanned path and skipped
path grouped by reason. These per-file manifests are required before Perfora can
certify a resolved finding.

## Deterministic verification boundary

Verification is available only for findings created with a stable fingerprint
and deliberately marked `resolved`. Perfora re-runs the current analyzer using
the original audit type. It reports:

- `verified_resolved` when the original rule executed, the source was scanned
  or removed, and the semantic finding is absent;
- `still_present` when the stable fingerprint or same rule/file/symbol identity
  is observed, reopening the finding;
- `inconclusive` when rule or per-file coverage cannot prove absence; or
- `error` when repository inspection or deterministic analysis fails.

Verification does not invoke a model, modify source, apply a patch, or claim
that unrelated findings were resolved.

## Finding identity and provenance

New findings contain:

- a run-specific finding ID;
- a stable SHA-256 fingerprint derived from rule ID, repository-relative file,
  semantic symbol, framework, and duplicate occurrence order;
- rule ID and rule version;
- analyzer and rule-pack versions on the parent audit;
- deterministic evidence, explanation, and recommendation;
- optional, separately labeled provider/model enrichment.

The fingerprint intentionally excludes the line number so ordinary code movement
does not create a new logical finding. Duplicate findings with the same semantic
identity receive a deterministic occurrence suffix before hashing.

Legacy records remain readable. Missing provenance is shown as `legacy` or
`unknown`; it is not reconstructed.

## Agent handoff boundary

Copy Prompt reads only the selected finding source inside the repository. The
source must exist, be readable, and contain at most 1,000,000 characters. Likely
secrets are redacted before the prompt reaches the browser. Prompt generation:

- does not invoke a model;
- does not modify the repository;
- does not create or switch Git branches;
- does not apply or roll back patches;
- includes deterministic and model-authored content under separate headings.

## Not currently covered

- Guided device capture, startup-specific traces, and automated retaining paths
- Semantic type resolution across the complete Dart program
- Native Kotlin, Java, Swift, or Objective-C source analysis
- Android network-security-config interpretation
- Domain-specific iOS transport-exception validation
- Online dependency vulnerability matching
- Complete license identification when local metadata is unavailable
- Built application artifact analysis
- Automatic remediation or patch application

These omissions must remain visible in product messaging and audit coverage.

## Foundation fixtures

The analyzer test suite includes fixtures for:

- lifecycle findings across Riverpod, Provider, Bloc/Cubit, and GetX;
- clean lifecycle ownership;
- insecure and secure Dart/Android/iOS configurations;
- generated Dart source;
- ignored build and CocoaPods vendor paths;
- unsupported text files;
- parseable but semantically invalid Dart;
- invalid UTF-8/binary source.
