# Runtime performance artifacts

Perfora `0.4` imports performance evidence captured by Flutter, DevTools, Chrome
tracing, or another tool that emits the documented JSON/HAR structures. It does
not run or attach to the application and does not infer runtime measurements
from static source.

## Supported inputs

| UI selection | Minimum recognized structure | Typical producer |
| --- | --- | --- |
| Detect automatically | One of the structures below | Any supported producer |
| DevTools timeline | `traceEvents[]` containing complete events with `dur` | DevTools Performance export or Chrome trace JSON |
| CPU profile | `nodes[]` plus `samples[]` or profile timestamps | DevTools/Chrome CPU profiler |
| Memory snapshot | `samples[]` with `heapUsage`, `usedBytes`, or equivalent fields | Exported/normalized DevTools memory data |
| Heap comparison | `baseline` and `current` objects containing heap byte values | A locally prepared comparison summary |
| App-size analysis | A recursive `children` tree with `size`, `value`, `bytes`, or compact equivalents | `flutter build ... --analyze-size` |
| Frame timings | Flutter `TimelineSummary` fields such as `frame_build_times` and `frame_rasterizer_times` | Flutter integration profiling |
| Network HAR | HAR `log.entries[]` | DevTools Network export |

Flutter documents that [Performance snapshots](https://docs.flutter.dev/tools/devtools/performance)
can be exported and imported by DevTools,
[`TimelineSummary`](https://docs.flutter.dev/cookbook/testing/integration/profiling)
can write the complete timeline and summary JSON, and
[`flutter build --analyze-size`](https://docs.flutter.dev/perf/app-size)
produces JSON for the App Size tool.

## Trust and provenance

Each imported capture persists:

- repository snapshot;
- artifact filename, format, and SHA-256 digest;
- build mode and whether it came from artifact metadata or user declaration;
- available Flutter, Dart, and DevTools versions;
- capture/import timestamps when available;
- sanitized metrics, bounded breakdowns, observed evidence, and warnings.

Profile mode is required before timelines, frame timings, CPU, memory, or
network artifacts can produce trusted findings. Release mode is accepted for
app-size artifacts. Debug evidence is retained as `unreliable`; unknown mode is
`unverified`. Perfora withholds threshold findings for both states.

If artifact metadata conflicts with a declared build mode, embedded metadata
wins and the conflict is recorded. A declaration is never presented as an
artifact-verified fact.

## Evidence and findings

Every runtime finding has `observed=true` and at least one `evidence_id`. Each
evidence record includes a JSON trace reference such as
`$.traceEvents[42]` or `$.log.entries[3]`. Duration, timestamp, thread, value,
unit, and source location are stored only when the artifact provides them.

Threshold rules currently cover:

- UI/raster frames and build/layout/paint events above a 16.67 ms reference
  budget;
- a CPU hot path representing at least 20% of at least ten imported samples;
- heap growth above both 10 MiB and 20% between equivalent checkpoints;
- network requests lasting at least one second or returning failure status.

App size produces inventory and comparison evidence, not a standalone "large
app" finding. Size only becomes actionable relative to a compatible baseline.
Perfora never combines metrics into an overall score.

## Before/after comparison

Two captures are comparable only when they use the same repository path and
artifact family. Perfora calculates deltas for metrics shared by both captures,
labels known higher-is-worse measurements as improved or regressed, and reports
new or resolved runtime rule IDs. Flutter or DevTools version differences remain
comparable but produce a caution because schemas or measurement behavior may
differ.

Equivalent user flow, device, build mode, warm-up, and capture duration are the
user's responsibility and should be recorded in the capture label.

## Privacy and limits

- Import content is limited to 25 MB of JSON text.
- Raw artifact content is parsed in the local API process and is not persisted.
- HAR query strings, fragments, headers, cookies, and bodies are discarded.
- Persisted names and string metadata pass through Perfora secret redaction.
- Evidence is capped at 500 records per capture and breakdowns retain only the
  most relevant entries.
- Automatic device capture, retaining-path extraction, and full DevTools heap
  graph ingestion are not yet supported.
