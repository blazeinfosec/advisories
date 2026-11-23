# PM-01 — A preview token minted for any link bypasses every link access control

| | |
|---|---|
| **Severity** | Critical |
| **Actor** | Any registered user (registration is open) |
| **Prerequisites** | A shared link URL, and any account |
| **Boundary crossed** | Link access controls (password, email allowlist, expiry, group) |
| **Affected component** | `pages/api/links/[id]/preview.ts:16-27`; `app/api/views/pages/route.ts:56-143`; `lib/auth/preview-auth.ts` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted; independent of every optional env var |
| **CWE** | CWE-862 Missing Authorization; CWE-639 Authorization Bypass Through User-Controlled Key |
| **Proof** | `poc.py` — 4 vulnerability assertions, 3 controls, link state restored |
| **Chain** | Endpoint of **Chain B** (`../chain-b-inventory-then-preview-bypass/`), reached from PM-19 |

## Summary

Papermark's value proposition is that a shared link is gated: password, email
allowlist, one-time code, expiry. Those gates are enforced on `POST /api/views`.
They are not enforced on `POST /api/views/pages`, the endpoint that mints signed
URLs for a document's page images. That endpoint has a second authorization path
for "preview", intended for a document's owner, which requires only a logged-in
session plus a preview token that matches the caller and the link. Neither the mint
nor the verify step checks that the caller belongs to the team that owns the link.
Any account can mint a preview token for any link id and read that link's document
pages, whatever gates the owner configured.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

The two defects that compose here are both present in the current release line:

- The mint, `pages/api/links/[id]/preview.ts`, has carried the authenticate-but-not-
  authorize pattern since it was added in `e289af44` (2024-07-07). It is byte-present
  in `v0.21.0` and `v0.22.0`.
- The consumer currently lives in `app/api/views/pages/route.ts` (added `611ecac2`,
  2026-03-18, after `v0.22.0`). The preview-session consumption it performs is also
  present at `v0.21.0` and `v0.22.0`, in `app/api/views-dataroom/route.ts`, from which
  the page-image path was later split out. We confirmed `verifyPreviewSession`
  handling is present in that file at both tags; we exploited only `main` at
  `ed19717e` and did not separately run the exploit against a tagged build.

No optional configuration is required. The behaviour is on by default for any link
whose owner set a password, email allowlist, expiry, or group gate. Registration is
open, so the "any account" prerequisite also needs no special configuration.

## Where it lives

Two independent omissions that compose.

**1. The mint has no ownership check.** `pages/api/links/[id]/preview.ts:16-27`
authenticates the session, then hands the link id straight to
`createPreviewSession`:

```ts
const session = await getServerSession(req, res, authOptions);
if (!session) return res.status(401).end("Unauthorized");
const { id } = req.query as { id: string };
const previewSession = await createPreviewSession(id, (session.user as CustomUser).id);
```

There is no query against `UserTeam` or `Link.teamId`. `createPreviewSession`
stores `{linkId, userId, expiresAt}` in Redis; `verifyPreviewSession` checks user,
expiry, and link — never team membership.

**2. The consumer trusts the token in place of every gate.** In
`app/api/views/pages/route.ts:56-143`, when the body parses as a preview request,
the route checks a session, a rate limit, `verifyPreviewSession`, and that the
requested `documentVersionId` belongs to the link — then serves the pages. No
password, no email or one-time-code check, no `expiresAt`, `isArchived`, or team
check. The contrast with `app/api/views/route.ts:245-267`, which sets `isPreview`
only after confirming `prisma.userTeam.findUnique`, shows this is an oversight.

**3. The version id needed to exploit it is public.** The link's `_next/data`
payload is served to anonymous callers and includes `document.versions[0].id`. The
`password` field is correctly redacted; the version id is not.

## Attack prerequisites

- Any account. Registration is open — no invite, waitlist, or allowlist.
- A shared link URL. The `documentVersionId` then leaks anonymously from the link's
  data payload.

## Affected boundary

Every access control Papermark sells on a link: password, email allowlist, verified
email, expiry, and — on data room links and the page-image route — bidder group
segregation. See Chain B and the data-room escalation below for the group and
revocation dimensions.

## Impact

Every gate is bypassed for a caller who knows a link URL and holds a free account.
Sharing a link with one recipient effectively publishes the document to anyone who
obtains the URL. The page URLs are signed from the victim team's own storage
credentials, and no `View` record is created on this path, so the owner's analytics
show no trace.

### Demonstrated

A free account in an unrelated tenant read a password-protected document's rendered
page images without the password (`pages=1`, victim bytes retrieved). The page URLs
are signed from the victim team's own storage credentials, and no `View` record is
written on this path, so the owner's analytics show no trace.

Further escalations established during the review:

- **Expiry: revocation does not work.** On the page-image route the preview branch
  reads none of `isArchived`, `deletedAt`, or `expiresAt`, so page images stay
  retrievable after the link is archived, expired, and deleted (see Chain B, and
  PM-02 for the `viewId` variant).
- **Data room group segregation fails.** `app/api/views/pages/route.ts:122-133`
  binds the document to the link only by "is it in this data room"; `link.groupId`
  and `viewerGroupAccessControls` are never read. A free account minted a preview
  token for one bidder's group link and pulled another bidder's restricted
  document's pages. Bidder segregation is the control an M&A data room exists to
  provide.
- **On a GENERAL data room link it reaches the original files**, because the
  per-document ACL at `views-dataroom:1120` is guarded by `if (effectiveGroupId)`
  and a GENERAL link has a null `groupId`.

### Not demonstrated / not claimed

- **Write or modification.** This path is read-only. We did not demonstrate that a
  preview session grants any write to the victim's documents or link settings.
- **Reach without a link id.** The exploit needs the target link's id (or URL). Link
  ids are cuid2, not sequential; we did not demonstrate enumeration of link ids.
- **Cross-room reach on the non-GENERAL path.** The consumer binds the requested
  `documentVersionId` to the link's own data room. We pulled another *group's*
  document inside the same room; we did not retrieve a document outside that room.
- **Code execution or credential theft.** The signed URLs are scoped, time-limited
  reads of the victim's objects. We did not obtain the storage credentials
  themselves.

## Reproduction

The proof leaks the version id anonymously, then — as `mallory@attacker.test`, an
account in an unrelated tenant — mints a preview token for the victim's
password-protected link and pulls the page image without the password. It forces
the link active for the baseline and restores its revocation state in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-01-preview-token-access-control-bypass/poc.py
```

Observed result (`evidence/run.txt`):

```
[VULN PASS] the documentVersionId leaks anonymously from the link payload
[CTRL PASS] POST /api/views without the password is refused by the gate  HTTP 400 'Password is required.'
[CTRL PASS] POST /api/views/pages with no valid view or token is refused  HTTP 400
[VULN PASS] an unrelated account mints a preview token for the victim's link  HTTP 200
[CTRL PASS] minting a preview token with no session is refused  HTTP 401
[VULN PASS] the token serves signed page images without the password  HTTP 200 pages=1
[VULN PASS] the victim document's rendered bytes are retrieved
            MARKER team=cmuiv8b3q... doc="Victim Q4 Board Deck"
```

The three controls prove the baseline: the password gate works on the front door,
the page route refuses a request with no token, and minting requires a session.
Only the team check on the mint is missing.

The two requests at the center of the bypass, carrying `mallory`'s session cookie
and no link password, invited email, or one-time code:

```
POST /api/links/<linkId>/preview          -> 200 {"previewToken":"<token>"}

POST /api/views/pages
  {"previewToken":"<token>","linkId":"<linkId>",
   "documentVersionId":"<versionId>","pageNumbers":[1]}
                                           -> 200 {"pages":[{"file":"<signed URL>"}]}
```

With `patch.diff` applied and the dev server restarted, the same run reports the
bypass closed (fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] an unrelated account mints a preview token for the victim's link  HTTP 403
[VULN FAIL] the token serves signed page images without the password  HTTP 400 pages=0
```

The `documentVersionId` still leaks anonymously after this patch; that is the
disclosure primitive, closed separately by PM-19's filter and the version-id step in
Remediation below, not by the mint's team check.

## Root cause

A capability (the preview token) is issued to any authenticated principal for any
resource, and the consumer accepts that capability in place of the resource's
access controls. The mint never asks "does this user own this link?", and the
consumer never re-applies the link's gates. Either check alone would close it.

## Interim mitigation

Before the patch is deployed:

- There is no configuration that keeps the preview feature and closes the bypass. The
  mint has no team check to toggle on.
- Invite-only registration raises the bar from "any account" to "any invited account",
  but any logged-in user — including a legitimate tenant with no access to the target
  link — can still mint. That is a reduction, not a fix.
- Not serving `document.versions[].id` to callers who have not passed the link's gates
  (PM-19) removes the anonymous half: the attacker must then obtain the version id by
  other means.

A deployment that can neither patch nor accept the exposure should treat every shared
link as public for the interim.

## Remediation

Apply `patch.diff`. It requires the session user to belong to the link's team
before a preview token is minted:

```ts
const link = await prisma.link.findUnique({ where: { id }, select: { teamId: true } });
if (!link?.teamId) return res.status(404).end("Not found");
const membership = await prisma.userTeam.findUnique({
  where: { userId_teamId: { userId, teamId: link.teamId } },
});
if (!membership) return res.status(403).end("Forbidden");
```

This single change closes the finding, because the bypass depends on minting a
token for a link the caller does not own. Defense in depth, each worth doing:

- Carry `teamId` in the preview session record and re-verify it in
  `verifyPreviewSession`, so a stale token cannot outlive the membership.
- On the `/api/views/pages` preview branch, in the `link.dataroomId` case, require
  a `viewerGroupAccessControls` row with `canView` and check `isArchived`,
  `deletedAt`, and `expiresAt` — matching what `views-dataroom:1120-1195` already
  does. This closes the group-segregation and revocation dimensions directly.
- Stop serving `document.versions[].id` in the link payload to callers who have not
  passed the link's gates (see PM-19).

Verify by applying the patch, **restarting the dev server**, and re-running
`poc.py`: the mint must return 403 for `mallory`, so the token, page-serving, and
byte-read `VULN` assertions all fail.

## For the vulndev student

1. **Two "almost right" checks can sum to zero.** The mint checks authentication
   ("are you logged in?") but not authorization ("is this yours?"). The consumer
   checks the token's integrity but not the resource's gates. Each side assumes the
   other handles ownership, and neither does. When a capability is minted in one
   place and spent in another, verify that *one* of them binds the capability to
   the caller's authorization — do not assume the other end does.

2. **A parallel route that gets it right is the proof it is a bug.** `/api/views`
   confirms `userTeam.findUnique` before honouring a preview; `/api/views/pages`
   does not. When two routes implement the same concept and only one has the check,
   you are looking at drift, and the stricter one tells you the intended invariant.

3. **Redacting one field exposes the asymmetry.** The link payload carefully
   redacts `password` to `"protected"` but ships `document.versions[].id` in clear.
   Someone thought about what is sensitive in that payload and missed an item. When
   a response has obvious redaction, inventory the *other* fields — the redaction
   proves the channel reaches untrusted callers.

4. **Prove the baseline before claiming the bypass.** The PoC shows the password
   gate returning 400 and the page route rejecting a tokenless request *first*. A
   bypass claim is only as strong as the proof that the thing being bypassed was
   actually on. State the controls, then break them.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-862: Missing Authorization — <https://cwe.mitre.org/data/definitions/862.html>
- CWE-639: Authorization Bypass Through User-Controlled Key — <https://cwe.mitre.org/data/definitions/639.html>
- OWASP API Security Top 10: API1:2023 Broken Object Level Authorization. Chain: PM-19 → PM-01. Related: PM-02, PM-04.
