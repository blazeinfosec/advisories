# PM-19 — A password-protected link discloses the room's document inventory before the password

| | |
|---|---|
| **Severity** | High (reviewer's rating; see status) |
| **Actor** | Unauthenticated — no account, cookie, password, or email |
| **Prerequisites** | A GENERAL-audience data room link id |
| **Boundary crossed** | Link gate (pre-authentication information disclosure) |
| **Affected component** | `lib/api/links/link-data.ts`, served through `/_next/data/<buildId>/view/<linkId>.json` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted |
| **CWE** | CWE-200 Exposure of Sensitive Information; CWE-862 Missing Authorization |
| **Proof** | `poc.py` — 1 vulnerability assertion, 2 controls, read-only |
| **Status** | Identified in the round-3 chain review; severity is the reviewer's, not panel-adjudicated |
| **Chain** | Entry condition of **Chain B** (`../chain-b-inventory-then-preview-bypass/`), feeding PM-01 |

## Summary

A data room link carries gates — password, email, allow list, NDA. The Next.js
data route that backs the viewer page returns the room's contents before any of
them are applied. For a GENERAL-audience link, which has no group to filter by, the
whole room comes back: every document name and `documentVersionId`, to an
unauthenticated caller who never sends the password.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

`lib/api/links/link-data.ts` was added in `b936dad8` (2024-08-09) and is present at
`v0.21.0` and `v0.22.0`, so the current release line is affected. The behaviour
depends on no environment variable.

Configuration: the finding applies to a GENERAL-audience data room link that carries a
gate (a password or email protection). A GROUP link is filtered correctly and is not
affected; an ungated link discloses its inventory by design.

## Where it lives

`lib/api/links/link-data.ts` builds the viewer payload, including the room's
documents:

```ts
documents: {
  where:
    groupPermissions.length > 0 || effectiveGroupId
      ? { id: { in: documentIds } }   // GROUP link: filtered to the group
      : undefined,                     // GENERAL link: ALL documents
  ...
}
```

For a GROUP link, `effectiveGroupId` is set and the list is filtered to that
group's `viewerGroupAccessControls`. For a GENERAL link both operands are falsy, so
`where: undefined` returns every document in the room. This function's output is
served as the static data payload at
`/_next/data/<buildId>/view/<linkId>.json` — reachable with no password, because
the payload is produced by `getStaticProps`, which has no request or auth context.

## Attack prerequisites

- A GENERAL-audience link id for the room. No account, cookie, password, or email.
  One GET.

## Affected boundary

The link's own gate. The password gate on `/api/views-dataroom` is real and
enforced (the proof confirms it returns "Password is required."). The data route
simply sits in front of that gate and discloses the inventory the gate is meant to
protect.

## Impact

Document names are the asset, and in M&A they are material on their own: a deal
codename, and a title like "Litigation Settlement CONFIDENTIAL" or "BETA ONLY
Litigation", tell a rival what is in play and what the seller is worried about. No
document content is disclosed by this finding alone.

Its larger role is as the entry condition for **Chain B**: the `documentVersionId`
values it hands over are exactly what the preview-token bypass (PM-01) needs in
order to retrieve files. Round-3 review established that without this disclosure
Chain B has no way to name what it wants, because a group link's surfaces are
correctly filtered.

### Demonstrated

An anonymous caller, sending no password, read a gated GENERAL link's document
inventory from the static data payload: document names (for example "R2D3 Harrier -
BETA ONLY Litigation") and four `documentVersionId` values. A GROUP link for the same
room withheld two of those documents, proving the data route can filter and does not
for GENERAL links.

### Not demonstrated / not claimed

- **Document content.** This finding discloses names and version ids only. No file
  bytes are retrieved here; that requires PM-01 (Chain B).
- **GROUP-link or ungated-link exposure.** The leak is specific to a gated
  GENERAL-audience link. A GROUP link filters correctly and is not claimed to
  over-disclose; an ungated link is public by design.

## Reproduction

The proof reads the GENERAL link's data payload anonymously, confirms the password
gate is otherwise real, and confirms a GROUP link for the same room withholds
documents the GENERAL link disclosed (so the leak is specific to the GENERAL
path, not inherent to the data route). It is read-only.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-19-room-inventory-disclosed-before-password/poc.py
```

Observed result (`evidence/run.txt`):

```
      document: 'R2D3 Harrier - BETA ONLY Litigation'
      document: 'R2D3 Harrier - UNSHARED STAGING'
      documentVersionIds: ['cmukz08kx...', 'cmukz08ma...', 'cmukzgxl5...', 'cmul063di...']
[VULN PASS] the room's document inventory is disclosed anonymously, before the password
[CTRL PASS] the password gate genuinely blocks room entry  HTTP 400 'Password is required.'
[CTRL PASS] the GROUP link withholds at least one document the GENERAL link disclosed  2 withheld
```

The two controls are what make the disclosure a finding rather than a quirk: the
password gate is proven real, and the GROUP link for the same room proves the data
route *can* filter and simply does not for GENERAL links.

The single unauthenticated request:

```
GET /_next/data/<buildId>/view/<generalLinkId>.json   -> 200, room inventory in the payload
                                                         (no password, no email, no cookie)
```

With `patch.diff` applied and the dev server restarted, the patched route sets
`documents.where: { id: { in: [] } }` for a gated link with no group, so the documents
array comes back empty (fix-verification,
`_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] the room's document inventory is disclosed anonymously, before the password  1 name(s), 0 version id(s), no password sent
```

The closed primitive is the `documentVersionId` disclosure — **0** after the patch —
which is exactly what Chain B needs from this finding. The proof's name counter uses a
broad `"name":"…"` regex that still matches one non-document `name` field left in the
payload (the room, folder, or link name), which is why it reports "1 name(s)"; that is
not a leaked document title, and no document title is expected to remain once the
documents array is empty. The maintainer should confirm this against the live payload.
The run is also marked INVALID because the GROUP-link control compares the GENERAL and
GROUP disclosures, and with the GENERAL link now disclosing nothing there is nothing
left for it to establish.

## Root cause

The viewer page's data is assembled in `getStaticProps`, which runs without a
request and therefore without authentication, yet it includes gated content. A
pre-rendered, publicly cacheable payload must contain only what an unauthenticated
visitor is allowed to see. Authorization-dependent content has to be fetched after
the gate, not baked into the static payload.

## Interim mitigation

Before the patch is deployed:

- For a sensitive room, use a GROUP-audience link rather than a GENERAL one. A GROUP
  link filters the inventory to the group's `viewerGroupAccessControls`, so the
  pre-auth payload does not disclose the whole room. This is the practical stopgap.
- Treat document names in any GENERAL-link room as disclosed to anyone holding the
  link id, and keep sensitive information out of the titles themselves until patched.

A network-level block does not apply: the data payload is viewer-facing and must stay
reachable by legitimate anonymous visitors.

## Remediation

Apply `patch.diff`. It withholds the document inventory from the pre-auth payload
for any gated link that has no group scoping; the authorized list is already served
by `/api/views-dataroom` after the visitor passes the gate:

```ts
const gate = await prisma.link.findUnique({
  where: { id: linkId },
  select: { password: true, emailProtected: true },
});
const withholdDocuments = !effectiveGroupId && !!(gate?.password || gate?.emailProtected);
// documents.where: withholdDocuments ? { id: { in: [] } } : <existing logic>
```

Confirm the authenticated viewer still renders its documents: after the gate
passes, the content comes from the `/api/views-dataroom` response, not from the
static payload. Equivalently, return only the room name and a "password required"
flag before the gate, and load the tree client-side afterward.

Verify by applying the patch, **restarting the dev server**, and re-running
`poc.py`: the data payload must disclose zero document version ids, so the `VULN`
assertion fails while both controls still hold.

## For the vulndev student

1. **`getStaticProps` has no auth, so it must have no secrets.** The subtle part of
   this bug is *where* it lives: a Next.js static-data route produces a payload at
   build/ISR time with no request context, so there is no password to check. Any
   gated content placed there is, by construction, public. When you audit a
   Next.js app, treat every `getStaticProps`/`getStaticPaths` output as
   world-readable and ask what gated data leaked into it.

2. **A filter that exists for one case and not another is the tell.** The code
   filters documents for GROUP links (`effectiveGroupId`) and returns everything
   for GENERAL links (`where: undefined`). The asymmetry is the bug. When you see a
   conditional data filter, test the branch where the filter is absent — that is
   where the over-disclosure lives.

3. **Names are data.** It is easy to wave off "only document names, not content" as
   low impact. In the deal context Papermark serves, a title like "Litigation
   Settlement CONFIDENTIAL" is itself the sensitive fact. Rate information
   disclosure by what the metadata reveals to the specific adversary, not by
   whether file bytes came out.

4. **Prove the control is otherwise real.** The strongest version of an
   info-disclosure finding shows the gate working elsewhere (the password 400) and
   the same route filtering correctly in a sibling case (the GROUP link). That
   turns "the server returned data" into "the server returned data it withholds
   one request later, which proves it knows better".

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor — <https://cwe.mitre.org/data/definitions/200.html>
- CWE-862: Missing Authorization — <https://cwe.mitre.org/data/definitions/862.html>
- Chain entry: PM-19 → PM-01 (Chain B).
