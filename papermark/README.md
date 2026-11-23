# Papermark security review

A source-and-lab security review of [Papermark](https://github.com/papermark/papermark),
the open-source DocSend alternative, by Blaze Information Security.

- **Vendor notification:** initial contact on 2026-10-15; complete private report
  delivered on 2026-11-09. No response was received before publication.
- **Publication:** 2026-11-24 under Blaze Information Security's coordinated
  disclosure policy.

- **Target:** Papermark `main` @ `ed19717e`, re-validated live on `72888eec` — 939
  commits past the latest release tag `v0.22.0` (2025-12-03), so the audited code is
  untagged `main`, newer than any tagged release. Per-finding version detail is in
  each advisory's "Affected versions and configuration" section.
- **Method:** local source review plus a live proof of concept for every Critical
  and High finding, run against a containerized lab. Every database effect is read
  back through Postgres, and every proof restores the state it touched.
- **Scope note:** the checkout is partial — several `ee/features` subsystems and
  route families do not resolve — so some routes are recorded as untested rather
  than cleared. Both deployment profiles (hosted and self-hosted) are in scope and
  kept distinct, because several findings depend on environment variables.

## How this folder is organized

Each Critical and High finding has its own folder named for the finding, holding:

- `advisory.md` — the advisory and a vulnerability-development student guide:
  summary, affected versions and configuration, where it lives, prerequisites, the
  boundary crossed, impact (what was demonstrated and what is explicitly not
  claimed), reproduction, root cause, interim mitigation, remediation, and a
  coordinated-disclosure contact.
- `poc.py` — a self-contained Python proof that runs live against the lab and
  scores itself (`VULN` = the finding, `CONTROL` = baseline; a failed control
  invalidates the run).
- `patch.diff` — a proposed fix as a git format-patch: apply with `git am` to keep
  the commit message, or with `git apply` from the repo root. Each is verified to
  apply against a clean tree.
- `evidence/` — the Python run output (`run.txt`) and the original Node transcript.

The two attack chains have the same layout; their remediation points at the
component findings' patches. Mediums and the one Low are collected in
`medium-and-low-findings.md`. The internal working corpus is excluded from this
publication; only the final fix-verification transcript and the storage reseed helper
needed by the published proofs are retained under `_working-notes/`.

## Findings

The review identified 2 Critical, 7 High, 10 Medium, and 1 Low finding across
20 reportable ids, plus two attack chains.

### Critical and High (own folder, live Python proof)

| ID | Finding | Severity | Folder |
|---|---|---|---|
| PM-01 | Preview token bypasses every link access control | Critical | [`pm-01-preview-token-access-control-bypass/`](pm-01-preview-token-access-control-bypass/) |
| PM-15 | Viewer conversations API has no authentication | Critical | [`pm-15-unauthenticated-conversations-api/`](pm-15-unauthenticated-conversations-api/) |
| PM-02 | A `viewId` is a 23-hour bearer token that survives revocation | High | [`pm-02-viewid-bearer-token-survives-revocation/`](pm-02-viewid-bearer-token-survives-revocation/) |
| PM-04 | Cross-tenant file read: storage key not bound to the team | High | [`pm-04-cross-tenant-storage-key-read/`](pm-04-cross-tenant-storage-key-read/) |
| PM-08 | API tokens ignore scope and expiry | High | [`pm-08-api-token-scope-and-expiry-bypass/`](pm-08-api-token-scope-and-expiry-bypass/) |
| PM-13 | Scheduled jobs and the webhook callback are unauthenticated off Vercel | High | [`pm-13-unauthenticated-scheduled-jobs/`](pm-13-unauthenticated-scheduled-jobs/) |
| PM-19 | Link discloses the room's inventory before the password | High | [`pm-19-room-inventory-disclosed-before-password/`](pm-19-room-inventory-disclosed-before-password/) |
| PM-20 | `change-role` lets the lowest role take over the tenant | High | [`pm-20-change-role-privilege-escalation/`](pm-20-change-role-privilege-escalation/) |
| PM-21 | Visitor upload accepts an arbitrary storage key | High | [`pm-21-visitor-upload-arbitrary-storage-key/`](pm-21-visitor-upload-arbitrary-storage-key/) |

### Attack chains (live Python proof)

| Chain | Path | Reaches | Folder |
|---|---|---|---|
| A | PM-17 → PM-15 | One bidder's private negotiation: read, forge, mute | [`chain-a-bidder-identity-impersonation/`](chain-a-bidder-identity-impersonation/) |
| B | PM-19 → PM-01 | The room's original files, no password, no record | [`chain-b-inventory-then-preview-bypass/`](chain-b-inventory-then-preview-bypass/) |

The two chains share only "hold a link URL for the room". Chain A reaches no
documents; Chain B reaches no negotiation. Composed severity is `max(A, B)`.

### Medium and Low

See [`medium-and-low-findings.md`](medium-and-low-findings.md): PM-03, PM-05, PM-06,
PM-07, PM-09, PM-12, PM-14, PM-16, PM-17, PM-18 (Medium) and PM-11 (Low). PM-10 was
merged into PM-09.

## Cross-cutting themes

- **Viewer identity is asserted, not authenticated.** PM-15 and PM-17 accept a
  `viewerId` or email from the request as proof of identity. This is the engine of
  Chain A.
- **Storage keys are trusted to name their own tenant.** PM-04 and PM-21 persist a
  client-supplied key and later derive the owning team from it. One central fix in
  `process-document.ts` closes both.
- **Inline authorization checks drift from the RBAC layer.** PM-07, PM-14, PM-18,
  and PM-20 each test bare team membership instead of the `withTeamApi`
  entitlement the repository already ships. One wrapper migration closes the class.
- **Security controls keyed on hosting flags fail off Vercel.** PM-13 and PM-09
  disable themselves when `process.env.VERCEL` is not `"1"` — which is every
  self-hosted deployment.

## Running the proofs

See [`_poc/README.md`](_poc/README.md) for the one-time lab setup (bucket reseed and
the two Python dependencies) and the exact command. In short, from a restored lab:

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/<finding-folder>/poc.py
```

Each proof discovers its fixtures from the database, so it survives a reseed, and
proofs that change state restore it and print the row-count delta.
