# PM-04 — A document's storage key is never bound to the owning team, allowing cross-tenant file read

| | |
|---|---|
| **Severity** | High |
| **Actor** | Any registered user, acting inside their own team |
| **Prerequisites** | An account, and knowledge of a victim storage key |
| **Boundary crossed** | Tenant storage isolation (shared bucket, key-prefix partitioning) |
| **Affected component** | `lib/zod/url-validation.ts:112-114`; `lib/api/documents/process-document.ts:106,125`; `pages/api/file/s3/get-presigned-get-url.ts:55-56` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted; independent of every optional env var |
| **CWE** | CWE-639 Authorization Bypass Through User-Controlled Key; CWE-863 Incorrect Authorization |
| **Proof** | `poc.py` — 2 vulnerability assertions, 1 control, crafted rows removed |
| **Related** | Same root cause as PM-21. One central fix closes both. |

## Summary

A document's storage key is supplied by the client and never checked against the
team that owns the document. An attacker creates a document in their own team
whose `file` key points into another team's storage prefix, then downloads it
through the ordinary owner-side download endpoint. The signer derives the team
from the key itself, so it signs with the victim team's storage configuration and
returns the bytes.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

The sink that decides the outcome, `lib/api/documents/process-document.ts`, was added
in `ef1b8f49` (2025-04-13) and is byte-present in `v0.21.0` and `v0.22.0`: it has
written the client-supplied key without a tenant check across the current release
line. We exploited `main` at `ed19717e` and did not separately run the exploit
against a tagged build. We did not git-trace the two companion files
(`lib/zod/url-validation.ts`, `pages/api/file/s3/get-presigned-get-url.ts`) back
through the tags; their current state is what the exploit uses.

No optional configuration is required. The vulnerable path is the default S3
storage mode (`storageType === "S3_PATH"`). The shared-bucket, key-prefix tenancy
model this crosses is the default deployment: one bucket under one global
credential, partitioned only by the `<teamId>/…` key prefix.

## Where it lives

Three decisions compose into a tenant-isolation failure.

1. **The validator accepts any tenant id.** `lib/zod/url-validation.ts:112-114`
   tests the key against `^[a-zA-Z0-9_-]+\/doc_[a-zA-Z0-9_-]+\/…`. The first
   segment — the team id — need only be alphanumeric. It is never compared to the
   request's `teamId`.
2. **The key is persisted verbatim.** `process-document.ts:106` writes `file:
   key` and `:125` writes the same value onto the `DocumentVersion`. The team
   check at the creation endpoint confirms the caller belongs to the team in the
   URL, which the attacker owns. Nothing ties the two together.
3. **The signer trusts the key to name its own tenant.**
   `pages/api/file/s3/get-presigned-get-url.ts:55-56` is literally `const teamId =
   key.split("/")[0];`, and `getTeamS3ClientAndConfig(teamId)` then loads the
   victim team's storage configuration. The owner-side download endpoint calls
   this internally, so the membership check on the proxy path is bypassed.

## Attack prerequisites

- Any account. Registration is open — no invite, waitlist, or allowlist exists.
- Knowledge of a victim storage key. Keys are `<teamId>/doc_<id>/<name>`, and
  `teamId` leaks anonymously through the view routes while full keys leak through
  the signed URLs PM-01 returns. A key seen once is enough.

Two HTTP requests, no user interaction.

## Affected boundary

Tenant storage isolation. Papermark's default deployment stores every tenant in
one bucket under one global credential, partitioned only by the `<teamId>/…` key
prefix. The prefix is the entire tenant boundary for stored objects, and this
finding crosses it. The result is a cross-tenant read: the attacker obtains
another customer's original uploaded file.

## Impact

Arbitrary cross-tenant read of any object whose key the attacker can name, using
the victim's own storage access. Unlike PM-01, which yields rendered page images,
this returns the original uploaded file. It is also persistent: the crafted
document stays in the attacker's workspace and can be re-downloaded indefinitely,
long after the victim deletes the link or rotates its password.

It chains with PM-01: PM-01 discloses `teamId` anonymously and its signed URLs
disclose the full object key, so an attacker starting with nothing but a shared
link URL ends with permanent, direct access to that team's stored files.

### Demonstrated

As `mallory@attacker.test`, in an unrelated tenant, the proof created a document in
the attacker's own team whose `file` key named Victim Corp's board-deck object,
downloaded it through the ordinary owner-side endpoint, and read the victim's
original file bytes (the `MARKER` in the fetched object confirms the victim team and
key). The crafted document persists in the attacker's workspace, so the read is
repeatable.

### Not demonstrated / not claimed

- **Write or overwrite of another tenant's object.** The proof reads; it stores a key
  that points at the victim object but does not modify that object. We did not
  demonstrate a cross-tenant write.
- **Blind discovery of arbitrary keys.** The exploit needs the victim key
  (`<victimTeamId>/doc_.../name`). The `teamId` segment leaks (PM-01), and PM-01's
  signed URLs disclose full keys; the proof used a key it already held. We did not
  demonstrate enumeration of keys the attacker has never seen.
- **Reach outside the `S3_PATH` storage mode.** Only keys handled as `S3_PATH` are
  affected; we did not test other storage types.
- **Theft of the storage credential or code execution.** The endpoint signs with the
  victim team's storage configuration; it does not hand the attacker the global
  credential, and the result is a scoped, time-limited read.

## Reproduction

The proof runs as `mallory@attacker.test`, who creates a document in her own team
over Victim Corp's board-deck key, downloads it through the owner endpoint, and
reads the bytes. The crafted rows are removed in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-04-cross-tenant-storage-key-read/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] document row is owned by the attacker team but keyed to the victim prefix
            {teamId: cmuiv8b4d...(Attacker), file: cmuiv8b3q...(Victim)/doc_seed/board-deck.pdf}
[VULN PASS] download signs and returns a URL for the victim object  status=200
[VULN PASS] attacker reads another tenant's original file bytes
            MARKER team=cmuiv8b3q0001mqejmb79rz8g doc="Victim Q4 Board Deck" key=cmuiv8b3q.../board-deck.pdf
```

The create call returns HTTP 500 — the Trigger.dev stub raised after the write —
so the control reads the row back from the database rather than trusting the
status code.

The three requests, carrying `mallory`'s session cookie:

```
POST /api/teams/<attackerTeamId>/documents
  {"name":"pm04.pdf","url":"<victimTeamId>/doc_.../board-deck.pdf",
   "storageType":"S3_PATH","type":"pdf","contentType":"application/pdf"}
                               -> 500 (Trigger.dev stub; the Document row lands first)

POST /api/teams/<attackerTeamId>/documents/<docId>/download
  {}                           -> 200 {"downloadUrl":"<signed URL for the victim object>"}

GET  <signed URL>              -> 200  the victim team's original file bytes
```

With `patch.diff` applied and the dev server restarted, the create is refused at the
central guard, so the fixture that plants the foreign key can no longer be
established. The run goes invalid before any `VULN` step (fix-verification,
`_working-notes/fix-verification-2026-11-08.txt`):

```
[CTRL FAIL] document row is owned by the attacker team but keyed to the victim prefix
  vulnerability assertions : 0 proven, 0 not proven
  controls                 : 0 held, 1 failed   -> RUN INVALID
```

An invalid run here is the fix working, not a weak proof: the write that plants the
cross-tenant key is itself rejected, so the read bypass can never be staged.

## Root cause

The storage key is both the resource identifier and, at download time, the source
of the tenant decision. A value the client controls is used to select which
tenant's credentials sign the request. Any identifier that selects a resource
must be validated against the caller's authorization; it must never *be* the
authorization.

## Interim mitigation

Before the patch is deployed:

- No configuration isolates tenants here. The single shared bucket and single
  credential are the default, and there is no toggle that re-binds the key to the
  team.
- Until patched, treat any storage key that a client can influence as untrusted. If
  the deployment can move to per-team credentials or a per-prefix storage policy
  (an IAM policy that confines a team's signer to its own `<teamId>/` prefix), that
  enforces the boundary at the storage layer regardless of the application check —
  but the default single-credential model has no such boundary, so the application
  guard in the patch is the reliable fix.

## Remediation

Apply `patch.diff`. It adds one central guard in `processDocument`, where every
upload path converges, rejecting any `S3_PATH` key whose first segment is not the
request's `teamId`:

```ts
if (storageType === "S3_PATH" && key.split("/")[0] !== teamId) {
  throw new Error("Storage key does not belong to this team.");
}
```

This is the same change as PM-21 — apply it once. Defense in depth, each
independently worth doing:

- Enforce the prefix in `documentUploadSchema` as well, passing the team id into
  the schema context, so a bad key is rejected at the edge.
- Treat the key as server-generated: have the upload endpoint return the key it
  allocated rather than accepting one from the client. This removes the class
  entirely.
- Stop deriving the team from the key in `get-presigned-get-url.ts`; resolve it
  from the `Document`/`DocumentVersion` row instead.

Verify by re-running `poc.py`: the create must be rejected, so the control row
never appears and the two `VULN` assertions are not reached.

## For the vulndev student

1. **A key is an identifier, and identifiers from the client are attacker input.**
   The whole bug is that `<teamId>/doc_.../file` looks like an opaque path but its
   first segment is a security decision. Whenever a format embeds an authorization
   field, check that the server re-derives or validates that field rather than
   reading it back out of the attacker's string.

2. **Two endpoints disagreed, and the weaker one won.** The presigned-URL *proxy*
   checks team membership before signing — that path is safe. The owner-side
   *download* endpoint calls the internal signer, which derives the team from the
   key and skips the membership check. When two code paths reach the same sink
   with different guards, the attacker picks the weak one. Enumerate every caller
   of a sensitive helper, not just the obvious one.

3. **Read the row back; don't trust the status.** The create returns 500 here
   because an unrelated downstream task (Trigger.dev) throws *after* the database
   write. A PoC that asserted on the HTTP status would have called this "failed".
   The write landed. Confirm effects at the datastore, especially when a handler
   does work after the security-relevant step.

4. **Fix at the convergence point.** Validator, create endpoint, and signer each
   touch the key. Patching all three is tempting and fragile. `processDocument` is
   where every write flows through, so one guard there covers this finding, PM-21,
   and callers not yet written. Find where the data paths meet and put the
   invariant there.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-639: Authorization Bypass Through User-Controlled Key — <https://cwe.mitre.org/data/definitions/639.html>
- CWE-863: Incorrect Authorization — <https://cwe.mitre.org/data/definitions/863.html>
- OWASP API Security Top 10: API1:2023 Broken Object Level Authorization
- Sibling finding with the shared fix: PM-21. Chains with: PM-01.
