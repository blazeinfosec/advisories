# Chain B — Inventory a room before its password, then pull every document

| | |
|---|---|
| **Composed severity** | Critical |
| **Actor** | One free account (registration is open) |
| **Components** | PM-19 (inventory disclosed before password) → PM-01 (preview token bypasses gates) |
| **Boundary crossed** | Every link gate on a data room, and the revocation lifecycle |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted |
| **Proof** | `poc.py` — 9 vulnerability assertions, 7 controls, link state restored |

## The one-sentence statement

Any unauthenticated party holding a GENERAL-audience data room link id can
enumerate the room's full inventory — including documents shared with no group —
before the password, and with one free signup can then retrieve the original
uploaded file for every one of those documents, leaving no record anywhere; page
images remain retrievable even after the link is archived, expired, and deleted.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`.

Chain B's exposure is the composition of its two component findings, which carry the
per-file version detail. PM-19's pre-auth link payload (`lib/api/links/link-data.ts`,
added 2024-08-09) and PM-01's preview mint (`pages/api/links/[id]/preview.ts`, added
2024-07-07) are both present in the current release line.

No optional feature is required. The only precondition beyond a free account is
possession of a GENERAL-audience link id for the room (see Preconditions); a GROUP link
is correctly filtered and does not work.

## How it composes

```
Start: the attacker holds a GENERAL-audience data room link id and one free account.
  │
  ├─ PM-19 ─ GET /_next/data/.../view/<linkId>.json returns the room's document
  │          names and documentVersionIds, anonymously, before the password.
  │          (A GROUP link is correctly filtered — which is why the GENERAL link
  │          matters: it is the only way to learn the version ids.)
  │
  └─ PM-01 ─ POST /api/links/<linkId>/preview mints a preview token for a link the
             attacker does not own. POST /api/views/pages then serves page images
             for every version id from PM-19, with no password and no group check.
             On a GENERAL link, views-dataroom DOCUMENT_VIEW yields the ORIGINAL
             uploaded file. No View row is written. Archival/expiry/deletion close
             the front door but not the page-image route.
Outcome: every document in the room, original files included, with no record.
```

PM-19 supplies the `documentVersionId` values PM-01 needs to name what it wants.
Round-3 review established that without PM-19, Chain B has nothing to request,
because a group link's surfaces are correctly filtered.

## Preconditions

1. A GENERAL-audience link id for the room. Not a bidder's group link — that
   distinction does real work: group links are filtered.
2. One registered account. Registration is open.

## Which gates fall

Measured in the proof:

| Gate | no token | preview @ `views-dataroom` | preview @ `views/pages` |
|---|---|---|---|
| Link password | 400 | **200** | **200** |
| Email allowlist | 403 | **200** | **200** |
| Verified email | OTP demanded | **200, no OTP** | **200** |
| NDA / agreement | 400 | **200** | **200** |
| Expiry | 404 | 404 — holds | **200** |
| Archival | 404 | 404 — holds | **200** |

The two findings are not Chain A. Chain B needs no bidder address, no `viewerId`, no
Q&A, and no group. They share only "hold a link URL for the room".

### Demonstrated

The full path ran end to end against the live lab: one free account, holding a
GENERAL-audience link id, read the room's inventory before the password (PM-19), minted
a preview token for a link it does not own (PM-01), and pulled page images — and, on
the GENERAL link, the ORIGINAL uploaded file — for a document the group link withholds,
with no row written anywhere. Archival did not close the page-image route.

### Not demonstrated / not claimed

- **No negotiation reach.** Chain B reaches documents, not the Q&A. Reading a bidder's
  private threads is Chain A, an independent path. Composed severity is `max(A, B)`.
- **GENERAL link required.** The chain needs a GENERAL-audience link id; a GROUP link
  is filtered and withholds the version ids (proven as a control). We do not claim the
  chain from a group link.
- **Read, not write.** We retrieved documents and original files; we did not
  demonstrate modifying or deleting the room's contents through this path.
- **A link id is required.** The attacker must hold a GENERAL link id or URL; we did
  not demonstrate enumerating link ids (cuid2, not sequential).

## Reproduction

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/chain-b-inventory-then-preview-bypass/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] the gate rejects entry (password required)  HTTP 400 'Password is required.'
[VULN PASS] the room's inventory is disclosed anonymously, before the password    (PM-19)
[CTRL PASS] the GROUP link withholds at least one document the GENERAL link discloses
[VULN PASS] a preview token is issued for another tenant's link                   (PM-01)
[VULN PASS] page images are served for a document the group link withholds
[VULN PASS] the entire sequence is recorded nowhere  0 row changes, no isPreview column
[VULN PASS] on a GENERAL link the ORIGINAL uploaded file is served, not just a page image
[CTRL PASS] bulk document download refuses a preview token  HTTP 401
[CTRL PASS] archival does close room entry (front door)  HTTP 404
[VULN PASS] archival does NOT close the page-image route  views/pages still HTTP 200
```

The controls are what make the chain honest: the password gate is proven real, the
GROUP link is proven filtered (so the GENERAL disclosure is specific, not inherent),
bulk download correctly refuses the token, and archival correctly closes the front
door — while the page-image route stays open.

With the component patches applied — PM-19's and PM-01's `patch.diff` — the chain is
broken at both ends (fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] the room's inventory is disclosed anonymously, before the password  0 version id(s)
[VULN FAIL] a preview token is issued for another tenant's link  HTTP 403
[VULN FAIL] the token opens the room without the password or an invited email  HTTP 400
[VULN FAIL] page images are served for a document the group link withholds  0/0 cross-group document(s)
```

PM-19 withholds the version ids, so the attacker cannot name what to request, and
PM-01's mint returns 403, so no token is issued — the chain is closed at both PM-19 and
PM-01.

## Interim mitigation

Before the component patches are deployed:

- There is no configuration that keeps the preview feature and closes PM-01 (the mint
  has no team check to toggle), so the root of the chain cannot be mitigated by config.
- Not serving the document inventory in the pre-auth payload (PM-19) removes the
  version ids the chain needs to name documents; until that ships, treat a GENERAL
  link's inventory as public.
- A deployment that can neither patch nor accept the exposure should treat every
  GENERAL-audience data room link as fully public — original files included — for the
  interim.

The PM-01 and PM-19 advisories carry the per-component detail.

## Remediation

Chain B is closed at its root by the PM-01 fix; apply all three for defense in
depth:

- **`../pm-01-preview-token-access-control-bypass/patch.diff`** — require the
  session user to own the link before minting a preview token. Closes the chain at
  its root (no token, no page pull).
- **`../pm-19-room-inventory-disclosed-before-password/patch.diff`** — withhold the
  document inventory from the pre-auth payload for gated links, so the attacker
  cannot name what to request.
- On `/api/views/pages`, apply the link's gates and group ACL on the preview branch
  and check `isArchived` / `deletedAt` / `expiresAt` — this closes the revocation
  and group dimensions directly (detailed in the PM-01 advisory).

## For the vulndev student

1. **Enumeration plus a bypass is a full read.** PM-19 is "only names and ids" and
   PM-01 is "page images for ids you can name". Each sounds bounded; together they
   are "every document in the room". The lesson: an information-disclosure finding's
   real severity depends on what else in the system consumes the information it
   leaks. Trace the leaked identifiers to every endpoint that accepts them.

2. **GENERAL vs GROUP is the crux, and revision 1 got it wrong.** The first write-up
   claimed a bidder's group link reached the whole room; it does not — group links
   are filtered. The chain needs a GENERAL link. When a system filters one audience
   type and not another, build your fixture to test *both*, or you will over- or
   under-claim. The PoC proves the GROUP link withholds documents as a control.

3. **Revocation is a security property — test it after the fact.** The chain shows
   archival closing the front door (`views-dataroom` 404) while the back door
   (`views/pages`) keeps serving. Always test the revoked state through *every*
   path that serves the resource, not just the one the UI uses.

4. **"No record" is part of the impact.** The proof compares all tables and finds
   zero row deltas, and confirms there is no `isPreview` column — the response says
   "Dataroom View recorded" while nothing is written. Silent exfiltration is
   materially worse than logged access; measure it and say so.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- Component advisories: `../pm-19-room-inventory-disclosed-before-password/`, `../pm-01-preview-token-access-control-bypass/`.
- OWASP API Security Top 10: API1:2023 Broken Object Level Authorization.
