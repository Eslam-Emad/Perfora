# Local-first team governance

Perfora 0.5 adds organizational workflow without turning the desktop app into a
hosted service. Policies, audit history, portfolio aggregation, handoffs, and
evidence packages remain on the machine running Perfora.

## Shared policy packs

Repository `.perfora.yaml` files may extend reviewed local YAML packs:

```yaml
version: 2
extends:
  - ../security-policy/mobile.yaml
organization: Mobile engineering
```

Relative paths resolve from the policy that declares them. Absolute local paths
are accepted for centrally managed files. HTTP(S) and other URL-like sources are
rejected, inheritance cycles fail closed, and all loaded source paths are included
in CI JSON and persisted desktop audit metadata.

Layers are applied from parent to child. `exclude`, `suppress`, ownership routes,
required ownership severities, required due-date severities, and audit types are
additive. Suppression requirements are sticky: a child cannot turn off a parent
requirement. Severity gates can only become stricter and an all-findings parent
gate cannot become new-only. Other scalar values use the closest layer. `include`
is intentionally replaced by the closest layer because it defines the repository's
scan boundary.

## Ownership and suppression approval

Ownership routes may select by rule ID, control group, severity, or a combination.
The first route whose configured selectors all match assigns the owner and an
optional due date. Policies can require an owner for selected severities and a
due date for another set. CI reports distinguish severity and governance counts,
while the exit status remains the documented policy result.

When `suppressions.require_approval` is true, a suppression needs a reason,
expiry, `approved_by`, and `approved_at`. A ticket URL is optional. The desktop
audit applies active approved suppressions as `risk accepted` and preserves the
approval metadata. Manual risk acceptance is blocked under this policy; the
exception must be reviewed in the versioned policy pack.

## Portfolio semantics

The Portfolio view is derived from SQLite and performs no network request. The
current repository posture uses the newest completed or partial audit for each exact
repository path and audit type. History and recurrence trends use all retained
audits. Governance issues are explicit counts, not an artificial risk score:

- unassigned open high or critical findings;
- open critical findings without a due date;
- overdue open findings;
- expired suppressions; and
- findings marked resolved but not yet verified resolved.

## Issue handoffs

Copy ticket returns a secret-redacted title, Markdown body, and labels suitable
for GitHub, Jira, Linear, or another tracker. It includes deterministic evidence,
location, rule version, fingerprint, owner, due date, standards, verification
state, recommendation, and acceptance criteria. Perfora does not authenticate to
or create content in an external tracker.

## Compliance evidence package

Evidence ZIP contains redacted `audit.json`, `report.html`, `results.sarif.json`,
`dependencies.cdx.json`, and `manifest.json`. The manifest records the SHA-256
digest and byte count of every artifact. This makes accidental or malicious
changes detectable when the recipient verifies the contents.

Set `PERFORA_REPORT_SIGNING_KEY` in `.env.local` to add an HMAC-SHA256 signature
over the canonical unsigned manifest. HMAC proves that the package came from a
party sharing that key; it is not a public-key signature and should not be used
as a substitute for independent code-signing identity. The key never appears in
the ZIP.

## Deliberately deferred

Hosted audit history, accounts, RBAC, billing, automatic external issue creation,
and remote organization policy distribution remain out of scope. Those features
require validated multi-user demand, an authentication model, tenant isolation,
credential management, and a separate threat assessment.
