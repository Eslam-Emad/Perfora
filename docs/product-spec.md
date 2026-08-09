# Perfora v0 product specification

## Promise

Given a local Flutter repository and one explicitly selected model, Perfora
produces an evidence-backed static performance or security audit and can apply
one reviewed, recoverable fix.

## Fixed decisions

- Full local-first web application, officially supporting macOS first.
- React/Vite frontend, FastAPI backend, Dart analyzer worker, SQLite storage.
- Single local user; no accounts, organizations, or roles.
- Providers are OpenCode (CLI-backed), Ollama, and OpenAI.
- Models are discovered dynamically. Every audit stores the exact provider,
  model identifier, and model metadata used. There is no silent fallback.
- Deterministic analysis establishes evidence. Models explain, prioritize, and
  propose changes. Model-only claims are hypotheses.
- Remote source transmission requires explicit provider consent, secret
  redaction, and a visible context manifest.
- Local repositories only in v0. Audits capture Git branch, commit, SDK
  versions, and a source fingerprint.
- Riverpod, Provider, Bloc/Cubit, and GetX must satisfy a shared lifecycle-rule
  contract before being advertised as supported.
- Security audits deterministically cover hardcoded credentials, cleartext URLs,
  unconditional certificate acceptance, Android cleartext policy, and iOS App
  Transport Security exceptions. Secret values never enter finding evidence.
- No unsupported overall performance score. The UI reports evidence, severity,
  confidence, coverage, and verification state.
- Apply Fix is per-finding: generate, preview, approve, checkpoint, apply,
  verify, rerun, compare, and rollback. It requires a clean Git worktree and
  creates a `perfora/fix-<finding-id>` branch.
- Verification is limited to `dart analyze`, `flutter analyze`, `flutter test`,
  existing Melos scripts, and explicitly approved project commands.
- One active local job at a time; repository fixes obtain an exclusive lock.
- Exports: HTML, JSON, SARIF, and patch.
- Optional shared repository policy lives in `.perfora.yaml`.
- No automatic telemetry.

## Tracer-bullet acceptance path

```text
Setup health
→ Add repository
→ Select performance or security audit flow
→ Select provider/model
→ Start audit
→ Stream deterministic analysis
→ Inspect the selected flow's findings, evidence, and recommendations
→ Generate fix
→ Review exact patch
→ Approve on clean worktree
→ Verify
→ Export
```

## Non-goals for the first tracer bullet

- Runtime frame, memory, startup, network, or bundle profiling.
- Team hosting, authentication, RBAC, or remote Git integrations.
- Batch or autonomous patch application.
- Concurrent audit execution.
- Linux or Windows certification.
