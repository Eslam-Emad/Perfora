# CLI and CI adoption

Perfora 0.2 runs security and lifecycle-performance rule packs without starting
the API, browser, or any model provider. The CLI sends no source or finding data
to OpenCode, Ollama, OpenAI, or another network service.

## Install in a Perfora checkout

```bash
python3 -m venv .venv
.venv/bin/pip install -e apps/api
(cd tools/analyzer && dart pub get)
```

The Python package installs the `perfora` executable. The Dart dependencies are
resolved once in the same Perfora checkout. A consuming CI repository can either
vendor this checkout under `.perfora-tool/` or fetch a pinned Perfora tag/commit
before running the same two install commands.

## Command

```bash
perfora audit \
  --repository . \
  --type security \
  --baseline origin/main \
  --format sarif \
  --output artifacts/perfora.sarif \
  --summary artifacts/perfora-summary.md \
  --fail-on new-high \
  --timeout 120 \
  --deterministic-only
```

`--type` may be repeated. When it is omitted, the CLI runs the audit types in
`.perfora.yaml`. `--include` replaces configured include patterns; repeated
`--exclude` values extend configured exclusions. Files outside the effective
filters appear in scan coverage as `path_excluded`.

The baseline is read with `git archive` into a temporary directory. Perfora
does not check out, reset, clean, or otherwise mutate the working tree. Current
findings are classified by stable semantic fingerprint as `new` or `unchanged`;
baseline findings that disappear are reported as `absent`/resolved. With no
baseline, current findings are treated as new so a new-only policy remains safe.

## Repository policy

Start with `.perfora.example.yaml`:

```yaml
version: 1
audit:
  types: [security, performance]
policy:
  fail_on:
    severity: high
    only_new: true
include: []
exclude:
  - "**/*.g.dart"
  - "**/*.freezed.dart"
  - build/**
suppressions:
  require_reason: true
  require_expiry: true
suppress: []
```

Configuration is strict: misspelled or undocumented fields fail with exit code
`2`. Suppressions use the emitted `sha256:` fingerprint. By default each entry
must have a reason and expiry date. An expired suppression remains visible in
the report and no longer bypasses the gate.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Audit completed and the configured gate passed |
| `1` | Audit completed, artifacts were written, and findings violated policy |
| `2` | Invalid arguments, repository, policy, or output path |
| `3` | Dart SDK, analyzer dependencies, or analyzer execution failed |
| `4` | The requested Git baseline could not be resolved or archived |
| `5` | An analyzer run exceeded `--timeout` |

CI should preserve artifacts for both `0` and `1`. Codes `2` through `5` are
operational failures and should not be interpreted as a clean audit.

## Output formats

- JSON is the complete machine-readable report, including provenance, policy,
  coverage, findings, suppressions, baseline state, and resolved findings.
- SARIF 2.1.0 uses repository-relative artifact URIs, stable partial
  fingerprints, baseline states, external suppressions, and rule metadata.
- HTML is a portable human-readable evidence report.
- `--summary` independently writes a compact Markdown job/merge-request summary.

## Monorepos

Point `--repository` at the smallest Flutter package or app that should own the
gate. To reuse a policy stored at the monorepo root, pass it explicitly:

```bash
perfora audit \
  --repository apps/member_app \
  --config "$PWD/.perfora.yaml" \
  --baseline origin/main \
  --format sarif \
  --output artifacts/member-app.sarif
```

Run a CI matrix for independently owned packages. This keeps relative paths,
baselines, artifacts, and policy decisions attributable to one component.

## CI templates

- `docs/ci/github-actions.yml` retains the SARIF and Markdown summary, uploads
  SARIF to GitHub code scanning, then restores the Perfora policy exit status.
- `docs/ci/gitlab-ci.yml` retains artifacts with `when: always` and publishes
  the SARIF report to GitLab.

Both examples fetch Perfora from `main` only as a readable starting template.
Production consumers should pin `PERFORA_REF` to a reviewed release tag or full
commit SHA and use their normal dependency-cache and artifact-retention policy.
