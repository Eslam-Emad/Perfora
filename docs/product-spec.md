# Perfora v0 product specification

## Promise

Given a local Flutter repository and one explicitly selected model, Perfora
produces an evidence-backed static performance or security audit and can copy
one complete, secret-redacted finding brief for another AI agent.

For CI, the same deterministic rule packs run non-interactively without a model
provider and enforce repository-owned policy against a Git baseline.

## Fixed decisions

- Full local-first web application, officially supporting macOS first.
- React/Vite frontend, FastAPI backend, Dart analyzer worker, SQLite storage.
- Single local user; no accounts, organizations, or roles.
- Organization governance is local and file-backed: policies may inherit reviewed
  local packs, route ownership, require due dates, and require suppression approval.
- Providers are OpenCode (CLI-backed), Ollama, and OpenAI.
- The local user can add, replace, or remove their own OpenAI API key and edit
  the Ollama base URL from Settings. Secret values are write-only in the browser
  and never returned by settings APIs; provider discovery refreshes immediately.
- Ollama is local only when its configured endpoint is loopback. A non-loopback
  endpoint and Ollama cloud models are remote source-transmission boundaries.
- Models are discovered dynamically. Every audit stores the exact provider,
  model identifier, and model metadata used. There is no silent fallback.
- Deterministic analysis establishes evidence. Models explain, prioritize, and
  propose changes in a separately labeled enrichment record. Model output never
  overwrites deterministic explanations or recommendations. Model-only claims
  are hypotheses.
- Remote source transmission requires explicit provider consent, secret
  redaction, and a visible context manifest.
- Local repositories only in v0. Audits capture Git branch, commit, SDK
  versions, source fingerprint, analyzer version, rule-pack version, and scan
  coverage.
- Riverpod, Provider, Bloc/Cubit, and GetX must satisfy a shared lifecycle-rule
  contract before being advertised as supported.
- Security audits use versioned deterministic rules mapped to OWASP MASVS and
  relevant MASWE/MASTG references. Every rule records platform scope, detection
  limitations, manual verification, and false-positive guidance. Secret values
  never enter finding evidence.
- Security coverage is reported by control group and independently for Dart,
  Android, iOS, and dependency manifests. Perfora does not calculate an overall
  security score.
- Dependency inventory is local by default and covers pub, CocoaPods, Gradle,
  Swift packages, Flutter plugins, and bundled Apple frameworks. CycloneDX,
  dependency changes, available license evidence, and privacy-SDK categories
  are exportable. No online vulnerability lookup occurs without a future,
  explicit consent boundary.
- No unsupported overall performance score. The UI reports evidence, severity,
  confidence, coverage, and verification state.
- Copy Prompt is per-finding and includes audit provenance, repository state,
  all evidence and recommendations, the context manifest, and current redacted
  source. It does not contact a model or modify the repository.
- Finding fingerprints use rule, repository-relative file, semantic symbol, and
  framework rather than mutable line numbers.
- Findings persist owner, due date, resolution reference, external ticket,
  append-only notes, disposition reason, suppression expiration, and status
  history. False-positive and risk-accepted states require a reason.
- The previous compatible audit is the automatic baseline. Users can select a
  different older audit with the same repository path and audit type.
- Baseline comparison reports new, unchanged, resolved, regressed, and
  severity-changed findings. Active triage metadata follows a fingerprint into
  the next audit; resolved or expired suppressed findings reopen if observed.
- `verified_resolved` cannot be selected manually and remains reserved for a
  deterministic verification re-scan.
- Verification requires the original rule to execute and the source to appear
  in the per-file scan manifest (or be removed). Reproduced findings reopen;
  missing coverage produces an inconclusive result without changing triage.
- Every verification attempt persists the current repository snapshot,
  analyzer/rule-pack versions, coverage, observed evidence, and outcome.
- No public API generates patches, applies changes, creates branches, or rolls
  back repository content.
- Persisted audit records are versioned and database changes use ordered schema
  migrations with legacy-record defaults.
- One active local audit job at a time.
- Exports: HTML, JSON, SARIF, CycloneDX 1.7, and a redacted evidence ZIP with
  checksums plus optional local HMAC signing.
- Optional shared repository policy lives in `.perfora.yaml`.
- The `perfora audit` CLI is analyzer-only. It supports repeated rule-pack
  selection, include/exclude globs, bounded timeouts, JSON/HTML/SARIF artifacts,
  a Markdown summary, Git-ref baselines, new-only severity gates, governed
  fingerprint suppressions, and stable exit codes.
- Baseline inspection uses a temporary `git archive`; it never changes the
  current worktree. SARIF paths stay repository-relative and results use stable
  partial fingerprints.
- No automatic telemetry.
- Runtime performance evidence is imported locally as versioned captures.
  Supported families are DevTools/Chrome timeline and CPU data, memory summaries
  and heap comparisons, Flutter frame timing and analyze-size JSON, and HAR.
- Runtime findings require trusted profile-mode provenance, except that release
  app-size artifacts are valid. Debug artifacts remain visible but explicitly
  unreliable and cannot produce trusted threshold findings.
- Every runtime finding references one or more persisted observed events. Runtime
  comparisons require the same repository and artifact family and never produce
  an overall performance score.

## Tracer-bullet acceptance path

```text
Setup health
→ Add repository
→ Select performance or security audit flow
→ Select provider/model
→ Start audit
→ Stream deterministic analysis
→ Inspect the selected flow's findings, evidence, and recommendations
→ Compare against an automatic or selected baseline
→ Filter and triage findings with ownership, notes, and disposition
→ Copy complete finding prompt
→ Hand off to the user's chosen AI agent
→ Mark the implemented finding resolved
→ Re-run deterministic verification and inspect the persisted result
→ Import profile-mode runtime artifacts and compare equivalent captures
→ Review local portfolio governance and recurrence trends
→ Copy a redacted issue handoff or export a compliance evidence package
→ Export
```

The CI acceptance path is `install → deterministic audit → compare Git baseline
→ retain artifacts → publish SARIF → enforce policy`. No provider discovery,
source transmission consent, model generation, API server, or browser is part
of that path.

## Non-goals for the first tracer bullet

- Guided or automatic runtime capture from a connected device.
- Team hosting, authentication, RBAC, or remote Git integrations.
- Batch or autonomous patch application.
- Concurrent audit execution.
- Linux or Windows certification.

## Foundation invariants

- A clean audit means no issue was found by the rules that actually executed;
  it is not a claim that every repository file was supported.
- Every audit records discovered, scanned, and skipped file counts plus skip
  reasons and executed rules.
- Deterministic evidence remains available when model enrichment fails.
- Legacy audit records remain readable with explicit `legacy` or `unknown`
  provenance where the old record did not store a value.
- Generated, vendor, binary, unreadable, and unsupported files are never
  silently treated as successfully scanned.
