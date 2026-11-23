# PM-21 — Visitor upload accepts an arbitrary storage key, giving an unauthenticated cross-tenant file read

| | |
|---|---|
| **Severity** | High |
| **Actor** | Unauthenticated data room visitor (no account) |
| **Prerequisites** | A data room link with visitor upload enabled (`enableUpload: true`) |
| **Boundary crossed** | Tenant storage isolation (shared bucket, key-prefix partitioning) |
| **Affected component** | `app/(ee)/api/links/[id]/upload/route.ts:120-235`; `lib/api/documents/process-document.ts:64,106,125` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted |
| **CWE** | CWE-639 Authorization Bypass Through User-Controlled Key; CWE-862 Missing Authorization |
| **Proof** | `poc.py` — 4 vulnerability assertions, 5 controls, clean row-count restore |
| **Related** | Same root cause as PM-04. One central fix closes both. |

## Summary

The visitor-upload endpoint records a document from a storage `key` supplied in
the request body. It never checks that the key belongs to the room's team. A
visitor can register an upload whose key points at another tenant's object; the
row is created in the room's team with that foreign key, and opening the document
then signs a URL for that key and returns the bytes. This is the PM-04
key-confusion defect reached from an unauthenticated visitor rather than a
registered user.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

The sink that decides the outcome, `lib/api/documents/process-document.ts`, was added
in `ef1b8f49` (2025-04-13) and is byte-present in `v0.21.0` and `v0.22.0`: it writes
the client-supplied key without a tenant check across the current release line. The
visitor-upload entry point, `app/(ee)/api/links/[id]/upload/route.ts`, is part of the
enterprise (`ee`) feature set. We exploited `main` at `ed19717e` and did not
separately run the exploit against a tagged build.

Required configuration: a data room link with visitor upload enabled
(`enableUpload: true`) — a feature a seller turns on to collect documents from
bidders. The shared-bucket, key-prefix tenancy model this crosses is the default
deployment (one bucket, one global credential, partitioned only by the `<teamId>/…`
prefix). No account is required of the attacker; a GENERAL link admits any email the
visitor types.

## Where it lives

`app/(ee)/api/links/[id]/upload/route.ts` resolves the dataroom session, confirms
`link.enableUpload`, and checks the viewer — then passes the client's
`documentData` straight into `processDocument`:

```ts
const document = await processDocument({
  documentData: updatedDocumentData,   // includes the caller's `key`
  teamId: link.teamId,
  teamPlan: link.team?.plan ?? "free",
  isExternalUpload: true,
});
```

`updatedDocumentData` is the request body with only `name` sanitised.
`processDocument` (`:64,106,125`) calls `validateExternalDocumentUrl({ type, key,
teamId })` — which inspects only `notion` and `link` types and is a no-op for an
`S3_PATH` key — and then writes `file: key` and `originalFile: key` verbatim onto
the `Document` and its `DocumentVersion`. Nothing compares the key's first path
segment to `link.teamId`.

The correct pattern exists two directories over:
`file/s3/get-presigned-post-url.ts:58` and `multipart.ts:170` build their keys
from the verified `team.id`, never from client input.

## Attack prerequisites

- A data room link with `enableUpload: true` — a feature a seller turns on to
  collect documents from bidders.
- A dataroom session cookie, which the room's own access form hands to anyone the
  link admits. On a GENERAL link that is any email the visitor types. No account
  is required.
- Knowledge of a target storage key. Keys are `<teamId>/<docId-ish>/<name>`, and
  `teamId` leaks anonymously through the view routes (see PM-19, PM-04), so a key
  seen once — for example from a link the attacker was legitimately given to a
  different room — is enough.

## Affected boundary

Tenant storage isolation. Papermark's default deployment — and this lab — puts
every tenant in one bucket under one global credential, partitioned only by the
`<teamId>/…` key prefix. There are no per-team buckets or credentials to cross:
`getTeamStorageConfigById` resolves storage by the `usStorage` region flag alone,
and the `Team` table has no storage columns. The mechanism is therefore an
arbitrary-key read within the shared bucket, where tenancy is enforced only by
the key-prefix convention. The impact is still cross-tenant in the sense that
matters to a customer: naming another team's prefix returns that other customer's
confidential original file to an unauthenticated visitor.

## Impact

An unauthenticated visitor reads any stored object in the shared bucket whose key
they can name. Unlike PM-01's rendered page images, this returns the original
uploaded file. The crafted document persists in the room, so the read is
repeatable. In an M&A deal this turns an invitation to one room into a read
primitive against the seller's other deals.

An earlier pass recorded this route as "Defended" on the strength of its session,
folder, and `dataroomId` checks. Those checks are real, but they guard the wrong
thing: the route validates *who* is uploading and *where* the document attaches,
never *what* object the key names.

### Demonstrated

An unauthenticated visitor entered an upload-enabled room in Victim Corp with a
self-asserted email, registered an upload whose key named Attacker LLC's object,
and read that object's original bytes back through the ordinary viewer path (the
`MARKER` in the fetched object confirms the other tenant and key). A `Document` and a
`DataroomDocument` row were created in the victim room's team with the foreign key.
The crafted document persists in the room, so the read is repeatable.

### Not demonstrated / not claimed

- **Write or overwrite of the other tenant's object.** The proof reads; it registers
  a key that points at the other tenant's object but does not modify that object.
- **Blind discovery of arbitrary keys.** The exploit needs a target key
  (`<otherTeamId>/…`). The `teamId` segment leaks (PM-19, PM-04); the proof used a key
  it already held. We did not demonstrate discovery of keys the attacker has never
  seen.
- **Reach without `enableUpload`.** The vector requires visitor upload to be enabled
  on the link. We did not demonstrate any upload path on a link without it.
- **Account takeover or code execution.** The result is a scoped, time-limited read
  of the named object through a signed URL; we did not obtain the storage credential
  or any write beyond creating the attacker's own room rows.

## Reproduction

The proof runs as an unauthenticated visitor (`visitor-<ts>@outsider.test`) who
enters an upload-enabled room in Victim Corp and registers a key owned by Attacker
LLC, an unrelated tenant. It clears its rows before and after and prints the
whole-schema row-count delta.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-21-visitor-upload-arbitrary-storage-key/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] visitor enters the room and receives a dataroom session cookie  status=200
[CTRL PASS] room listing does not reference the unrelated tenant's key before the attack
[VULN PASS] Document row created in the room's team with file = the unrelated tenant's key
            {teamId: cmuiv8b3q...(Victim), file: cmuiv8b4d...(Attacker)/doc_h13/x.pdf}
[VULN PASS] viewer path signs a URL for the unrelated tenant's object
[VULN PASS] fetched bytes are the unrelated tenant's object
            MARKER team=cmuiv8b4d0003mqejm7mle4sl ... key=cmuiv8b4d.../doc_h13/x.pdf
[CTRL PASS] upload route refuses a caller with no dataroom session  status=401

row-count delta vs baseline after cleanup: {}  (restored)
```

The final control is the baseline: the route does authenticate the visitor's
session. What it does not do is bind the key.

> Note: the lab's first request to `/api/views-dataroom` can take tens of seconds
> while the Next.js dev server compiles the route. The harness allows a 180-second
> HTTP timeout, or you can warm the route once before running the proof.

The requests, carrying the dataroom session cookie the room itself issued to the
visitor:

```
POST /api/views-dataroom
  {"linkId":"<linkId>","dataroomId":"<roomId>","email":"<visitor>",
   "viewType":"DATAROOM_VIEW"}            -> 200  Set-Cookie: pm_drs_...=<session>

POST /api/links/<linkId>/upload
  {"dataroomId":"<roomId>","documentData":{
     "name":"innocent-looking.pdf","key":"<otherTeamId>/doc_.../x.pdf",
     "storageType":"S3_PATH","contentType":"image/png",
     "supportedFileType":"image","fileSize":128}}
                                          -> Document row created in the victim team

POST /api/views-dataroom
  {"linkId":"<linkId>","dataroomId":"<roomId>","email":"<visitor>",
   "viewType":"DOCUMENT_VIEW","documentId":"<id>","documentVersionId":"<vid>",
   "hasPages":false}                      -> 200 {"file":"<signed URL for the foreign object>"}

GET  <signed URL>                         -> 200  the other tenant's original file bytes
```

With `patch.diff` applied and the dev server restarted, the central guard rejects the
upload, so no `Document` row is created and every downstream step fails (all five
controls still hold; fix-verification,
`_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] Document row created in the room's team with file = the unrelated tenant's key  None
  (the DataroomDocument, signed-URL, and byte-read assertions then also fail)
  controls : 5 held, 0 failed
```

## Root cause

A client supplies both the data and the name of the resource it is writing to. The
storage key is the resource identifier, and the server trusts it as self-naming:
it later derives the owning team *from the key* when signing a download, so a key
that lies about its team is believed twice — once when stored, once when read.
Identifiers that select a resource must be validated against the caller's
authorization, never accepted as the authorization.

## Interim mitigation

Before the patch is deployed:

- Disabling visitor upload (`enableUpload: false`) on data room links closes this
  unauthenticated vector outright. The registered-user vector through the same sink
  (PM-04) stays open, so this is a containment step for PM-21, not a fix for the
  class.
- No configuration isolates tenants inside the shared bucket. A per-prefix storage
  policy that confines each team's signer to its own `<teamId>/` prefix would enforce
  the boundary at the storage layer, but the default single-credential model has no
  such boundary, so the application guard in the patch is the reliable fix.

## Remediation

Apply `patch.diff`. It adds one central guard in `processDocument`, where every
upload path converges (dashboard, public API, and visitor upload), rejecting any
`S3_PATH` key whose first segment is not the request's `teamId`:

```ts
if (storageType === "S3_PATH" && key.split("/")[0] !== teamId) {
  throw new Error("Storage key does not belong to this team.");
}
```

This is the same change as PM-04 — apply it once. Better still, treat the key as
server-allocated: have the visitor-upload flow return the key it minted for this
viewer rather than accepting one, so the client never names a storage location.

Verify by re-running `poc.py`: the "Document row created … with the unrelated
tenant's key" assertion must fail (the upload is rejected), and the byte-read
assertion must not be reached.

## For the vulndev student

This finding is the same bug as PM-04 wearing a different hat, and comparing the
two is the lesson.

1. **Follow the data to the sink, not the entrance.** The upload route has real,
   careful checks: it verifies the dataroom session, that uploads are enabled, the
   viewer, and the target folder. An auditor who stops at "is this request
   authorized?" marks it defended — the earlier pass did exactly that. The bug is
   one layer deeper, at what the authorized request is *allowed to say*. Trace
   every attacker-controlled field to where it is used, not just whether the
   caller got in.

2. **Shared-bucket multitenancy makes the key the security boundary.** When every
   tenant lives in one bucket split by key prefix, the prefix *is* the tenant
   check. Any code that accepts a key from the client and does not re-derive or
   re-validate the prefix has handed the client the tenant boundary. Look for the
   place keys are minted (`get-presigned-post-url.ts` builds them from the
   verified team) and compare it to the place keys are accepted — the asymmetry is
   the bug.

3. **One root cause, many front doors.** PM-04 reaches this through the registered
   `documents` API; PM-21 reaches it through the unauthenticated visitor upload.
   Both call `processDocument`. Fixing the symptom at each route would be two
   patches and an eventual third when a new caller is added. Fixing it at the
   convergence point is one patch that covers callers that do not exist yet. When
   you find a defect behind two entry points, look for where they meet.

4. **Impact depends on the storage model, so state it.** The honest claim here is
   "arbitrary-key read within one shared bucket", which happens to be cross-tenant
   because tenants share the bucket. An earlier phrasing — "the victim team's own
   storage credentials" — implied per-team credentials that do not exist. Describe
   the mechanism you proved, then map it to customer impact; do not borrow
   isolation the architecture never had.

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
- OWASP API Security Top 10: API1:2023 Broken Object Level Authorization
- Sibling finding with the shared fix: PM-04.
