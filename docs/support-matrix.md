# Perfora support and scan-coverage matrix

This document defines what a Perfora `0.3` static audit does and does not inspect.
The recorded `scan_coverage` object is the authoritative per-run result.

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
| `security@1.0.0` | Supported Dart source | Hardcoded credential literals, non-loopback HTTP URLs, unconditional certificate acceptance |
| `security@1.0.0` | `android/app/src/*/AndroidManifest.xml` | Explicit `usesCleartextTraffic=true` |
| `security@1.0.0` | `ios/Runner/Info.plist` | Explicit global `NSAllowsArbitraryLoads=true` |

The analyzer version is stored separately from the rule-pack version. Updating
the implementation does not silently change the version attached to old audits.

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
Analyzer `0.3` also records every repository-relative scanned path and skipped
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

- Runtime frame, startup, CPU, memory, network, or bundle measurements
- Semantic type resolution across the complete Dart program
- Native Kotlin, Java, Swift, or Objective-C source analysis
- Android network-security-config interpretation
- Domain-specific iOS transport-exception validation
- Dependency vulnerability or license analysis
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
