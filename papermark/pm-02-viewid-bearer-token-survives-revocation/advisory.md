# PM-02 — A viewId is a 23-hour bearer token that survives revocation

| | |
|---|---|
| **Severity** | High |
| **Actor** | Unauthenticated — anyone holding a `viewId` |
| **Prerequisites** | Possession of a `viewId` (returned to every legitimate viewer) |
| **Boundary crossed** | Link lifecycle / revocation |
| **Affected component** | `app/api/views/pages/route.ts:146-195` (`VIEW_MAX_AGE_MS` at `:17`) |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted |
| **CWE** | CWE-613 Insufficient Session Expiration; CWE-863 Incorrect Authorization |
| **Proof** | `poc.py` — 2 vulnerability assertions, 2 controls, state restored |

## Summary

After a viewer passes a link's gates once, the resulting `viewId` alone unlocks
that document's page images for 23 hours, with no cookie, no session, and no
re-check of the link. Revoking the link does not revoke the access. An owner who
discovers a leak and archives the link, expires it, and rotates the password is
told the link is dead while the document keeps serving to anyone holding the old
`viewId`.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

The page-image route in its current form, `app/api/views/pages/route.ts`, was added in
`611ecac2` (2026-03-18), after `v0.22.0`. The same `viewId`-only page-serving path is
present at `v0.21.0` and `v0.22.0` in `app/api/views-dataroom/route.ts`, from which the
page-image handling was later split out. We exploited only `main` at `ed19717e` and did
not separately run the exploit against a tagged build.

No optional configuration is required. The `viewId` path is on by default, and
`VIEW_MAX_AGE_MS` (23 hours) is a compile-time constant, not a setting. The gap applies
to document-link views, where `view.dataroomId` is null and the session recheck at
`:197` is therefore skipped; a legitimate viewer obtains the `viewId` through the
normal front door.

## Where it lives

On the `viewId` path, `app/api/views/pages/route.ts:146-195` checks only three
things: that the `View` row exists, that `Date.now() - view.viewedAt.getTime()` is
within `VIEW_MAX_AGE_MS` (23 hours, `:17`), and that the requested
`documentVersionId` belongs to `view.documentId`.

The session check is at `:197`, guarded by `if (view.dataroomId && view.linkId)`.
For a document link `view.dataroomId` is null, so `verifyDataroomSession` never
runs. The link's current `password`, `expiresAt`, `isArchived`, and `deletedAt`
are never re-read.

## Attack prerequisites

- Possession of a `viewId`. Every legitimate viewer receives it in the `POST
  /api/views` response body, so it sits in the browser history, logs, and memory
  of anyone who has ever opened the link, and is available to browser extensions
  and shared devices. No cookie, no session, no account. One HTTP request.

## Affected boundary

The link's revocation lifecycle. Expiry, archival, and soft-deletion are the
controls an owner uses to end access. None of them reaches this route, so the
boundary they are supposed to enforce does not exist here for 23 hours.

## Impact

Revocation is ineffective for 23 hours. The expiry result is the worst of the
three: an expired link still yields document pages, so anyone who ever held a link
keeps access after the owner believes they have cut it off. The page URLs are
signed from the victim team's own storage credentials, and no `View` record is
created on this path, so the owner's analytics show no trace of the access.

Two related routes share the root cause:

- `pages/api/links/generate-index.ts:90-96` discloses the full data room index
  with the only gate being `view.dataroomId === dataroomId && view.viewerId ===
  viewerId` — no session, password, one-time code, expiry, or archived check.
- `pages/api/links/[id]/annotations.ts:22-55` gates on `view.id` plus
  `view.linkId` and checks `deletedAt` and the 23-hour window, but never
  `isArchived`, `expiresAt`, the password, or any cookie. It returns only
  sanitised annotation fields, so no link secrets leak through it.

### Demonstrated

A `viewId` minted through the legitimate front door kept serving signed page images
after the owner expired and archived the link — with no cookie, no session, and no
password. In the same revoked state, `POST /api/views` returned 404 "Link is no longer
available" while `POST /api/views/pages` returned 200 with signed URLs (`pages=1`). The
URLs are signed from the victim team's own storage credentials, and the path writes no
`View` row, so the access leaves no analytics trace.

### Not demonstrated / not claimed

- **Serving images for a still-active link is not the bug.** A `viewId` that serves
  page images while the link is open is intended behaviour. The finding is only that
  the same `viewId` kept working *after* revocation.
- **Possession of a valid `viewId` is required.** The attacker must hold a `viewId`
  from a legitimate prior view. We did not demonstrate minting or guessing a `viewId`
  without first passing the link's gates; `viewId`s are cuid, not sequential.
- **Read-only.** We retrieved page images. We did not demonstrate any write through
  the `viewId` path.
- **The window is bounded.** Access ends once the view ages past `VIEW_MAX_AGE_MS`
  (23 hours from `viewedAt`); we did not demonstrate access beyond that window.

## Reproduction

The proof temporarily un-revokes a document link to mint a fresh view through the
legitimate front door, re-revokes it (expire + archive), and shows the back door
still open. It deletes the probe view and restores the link's state in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-02-viewid-bearer-token-survives-revocation/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] a legitimate open mints a viewId  HTTP 200
[VULN PASS] the viewId alone serves signed page images  HTTP 200 pages=1
[CTRL PASS] the front door refuses after revocation  HTTP 404
[VULN PASS] the viewId survives revocation: the back door still serves page images  HTTP 200 pages=1
```

The contradiction is the finding: the front door (`POST /api/views`) returns 404
"Link is no longer available" while the back door (`POST /api/views/pages`)
returns 200 with signed URLs, for the same link in the same revoked state.

The two requests, neither carrying a cookie, session, or password:

```
POST /api/views
  {"linkId":"<linkId>","documentVersionId":"<versionId>", ...}  -> 200 {"viewId":"<viewId>"}

POST /api/views/pages
  {"viewId":"<viewId>","documentVersionId":"<versionId>","pageNumbers":[1]}
                                                               -> 200 {"pages":[{"file":"<signed URL>"}]}
```

The first request runs once, through the front door, while the link is open. The
second replays after the owner has expired and archived the link.

With `patch.diff` applied and the dev server restarted, an active view still serves its
pages (intended), but the revoked view is refused (fix-verification,
`_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN PASS] the viewId alone serves signed page images  HTTP 200 pages=1
[VULN FAIL] the viewId survives revocation: the back door still serves page images  HTTP 404 pages=0
```

The first line still passing is correct: an active view should serve its own pages. The
patch closes only the revocation-survival, so the revoked request now matches the front
door's 404.

## Root cause

The route treats the `viewId` as proof of a past authorization and never
re-checks the present. A capability minted when the link was open stays valid
because the only freshness check is the view's own age, not the link's current
state. Access tokens must be validated against the live state of the resource they
grant, on every use.

## Interim mitigation

Before the patch is deployed:

- There is no setting that re-checks link state on the `viewId` path or shortens the
  23-hour window; both are in code.
- Revocation cannot be made effective within the window. An owner who must cut off a
  leaked link at once has to make the underlying document unreadable — for example by
  replacing or removing the document version the link points to — rather than relying
  on expire, archive, or delete, none of which this path honours for up to 23 hours.
- Rotating the link password does not help: the `viewId` path reads no password.

## Remediation

Apply `patch.diff`. It re-reads the link on the `viewId` path and refuses the
request when the link is archived, expired, or soft-deleted:

```ts
if (view.linkId) {
  const currentLink = await prisma.link.findUnique({
    where: { id: view.linkId },
    select: { isArchived: true, expiresAt: true, deletedAt: true },
  });
  if (!currentLink || currentLink.isArchived || currentLink.deletedAt ||
      (currentLink.expiresAt && currentLink.expiresAt < new Date())) {
    return NextResponse.json({ message: "Link is no longer available." }, { status: 404 });
  }
}
```

Defense in depth: apply the document equivalent of `verifyDataroomSession` to
document views as well as data room views — the cookie already exists
(`lib/auth/link-session.ts`) and is simply not consulted here. Shorten
`VIEW_MAX_AGE_MS`, invalidate outstanding views when a link is archived or its
password changes, and apply the same link recheck to `generate-index.ts` and
`annotations.ts`.

Verify by re-running `poc.py`: the second `VULN` line must become a controlled
404, matching the front door.

## For the vulndev student

1. **A bearer token is only as safe as its revocation path.** A `viewId` handed
   back in a JSON body, usable with no cookie, is a bearer token whether the
   designers called it one or not. The question for any bearer credential is: what
   invalidates it, and is that checked on *every* use? Here the answer was "a
   23-hour timer, and nothing else", which means revocation is a lie for 23 hours.

2. **Guard clauses that are conditional hide gaps.** The session recheck exists —
   but behind `if (view.dataroomId && view.linkId)`. A document link has a null
   `dataroomId`, so the whole recheck is skipped for exactly the case the finding
   exploits. When a security check sits inside a conditional, enumerate the inputs
   that make the condition false and confirm each is still safe.

3. **"Front door vs back door" is a reusable test.** The cleanest way to prove a
   stale-authorization bug is to revoke through the supported path and then hit the
   alternate path with the old credential. If the supported path says "gone" and
   the alternate says "here you go", you have a revocation bypass, and the
   contradiction is self-evidently a bug to any reviewer.

4. **Silence compounds it.** This path writes no `View` row, so the access leaves
   no analytics trace. When you assess an authorization bug, check whether the
   unauthorized action is also invisible to the victim — undetectable access is
   materially worse than noisy access, and it belongs in the impact.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-613: Insufficient Session Expiration — <https://cwe.mitre.org/data/definitions/613.html>
- CWE-863: Incorrect Authorization — <https://cwe.mitre.org/data/definitions/863.html>
- OWASP API Security Top 10: API2:2023 Broken Authentication. Chains with PM-04.
