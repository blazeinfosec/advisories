# Chain A — Assume an invited bidder's identity and read their private negotiation

| | |
|---|---|
| **Composed severity** | Critical |
| **Actor** | Unauthenticated — no account, no cookie, no session |
| **Components** | PM-17 (group-link identity is self-asserted) → PM-15 (unauthenticated conversations API) |
| **Boundary crossed** | Bidder identity and the confidentiality of a private Q&A thread |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted; no environment variable involved |
| **Proof** | `poc.py` — 7 vulnerability assertions, 3 controls, forged message and setting restored |

## The one-sentence statement

Any holder of a group data room link can assume an invited bidder's identity in one
unauthenticated request, then read, post to, and mute that bidder's private
negotiation with the seller, leaving no record of the reads — where the seller's
plan includes the Q&A channel and it was enabled on that link at some point.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`.

Chain A's exposure is the composition of its two component findings, which carry the
per-file version detail. PM-15's conversations route
(`ee/features/conversations/api/conversations-route.ts`, added 2025-04-04) and PM-17's
group-link entry path are both present in the current release line; the chain is
unauthenticated only while both hold.

The seller-side configuration the chain needs is listed under Preconditions: a GROUP
link with `emailAuthenticated: false` (the shipped default), a plan that includes the
Q&A channel, and `enableConversation` having been switched on for the link at some
point.

## How it composes

```
Start: the attacker holds a GROUP data room link URL (dataroomId, groupId, teamId
       come free from the link's _next/data payload — unauthenticated).
  │
  ├─ PM-17 ─ Assert an invited bidder's email on the GROUP link
  │          (emailAuthenticated defaults to false). One POST /api/views-dataroom
  │          returns HTTP 200 and the bidder's GENUINE, canonical viewerId —
  │          byte-identical to the one the real bidder holds.
  │
  └─ PM-15 ─ That viewerId is the credential the conversations API accepts.
             GET /api/conversations?dataroomId=&viewerId= returns the bidder's
             PRIVATE threads with message bodies, no cookie. POST /messages forges
             a message attributed to the bidder; POST /notifications mutes them.
Outcome: read + forge + mute a bidder's private negotiation, unauthenticated,
         with no trace on the reads.
```

The two findings are genuinely dependent: PM-15's read is gated by knowing a
participant's `viewerId`, an unguessable cuid, and PM-17 is what hands that id to
an anonymous caller. Neither alone reaches the negotiation.

## Preconditions (seven, not one)

The round-3 review established these, and the proof checks the ones it can:

1. The attacker holds the group link URL.
2. The link is `DATAROOM_LINK`, `audienceType: GROUP`, on a non-`allowAll` group.
3. `emailAuthenticated: false` — the shipped default, a seller choice the UI does
   offer on the Group tab.
4. The seller's plan includes the Q&A channel (`conversationsInDataroom`, on
   `DATAROOMS_PLUS` and above).
5. `enableConversation` was switched on for the link at some point — switching it
   back off does not close the hole (PM-15's `GET /` checks only participation).
6. The target bidder has used the Q&A and participates in at least one thread.
7. The attacker knows an invited address, or enumerates for one (loud — PM-16).

## What it reaches, and what it does not

Chain A reaches one bidder's private negotiation: the questions and answers they
exchanged with the seller, the ability to post as them, and the ability to mute
their notifications. It does **not** reach documents — that is Chain B, an
independent path. The composed severity is `max(A, B)`, not `A + B`.

The read is silent (comparing all tables across an anonymous read showed zero row
deltas). Entry (precondition step via PM-17) is **not** silent: it records a `View`
and sends the seller an immediate notification, attributed to the bidder.

### Demonstrated

The full path ran end to end against the live lab, unauthenticated — no account, no
cookie:

- PM-17: one `POST /api/views-dataroom` asserting an invited bidder's email returned
  HTTP 200 and the bidder's genuine, canonical `viewerId`, byte-identical to the id the
  real bidder holds (compared against ground truth read from the database).
- PM-15: with that `viewerId`, an anonymous `GET /api/conversations` returned the
  bidder's PRIVATE thread with message bodies; `POST .../messages` stored a message
  attributed to the bidder; `POST .../notifications` flipped the bidder's notification
  setting. The reads changed no rows.

### Not demonstrated / not claimed

- **No document reach.** Chain A reaches the negotiation, not the files. Retrieving the
  room's documents is Chain B, an independent path; we did not reach a document through
  Chain A. Composed severity is `max(A, B)`, not `A + B`.
- **Entry is not silent.** The PM-17 step records a `View` and notifies the seller,
  attributed to the bidder. Only the conversation reads are traceless.
- **One bidder per asserted identity.** We demonstrated reading one invited bidder's
  thread per entry; we did not demonstrate enumerating all bidders, which needs an
  invited address per target (PM-16, which is loud).
- **An invited address is required.** The chain assumes the attacker knows or
  enumerates a valid invited email; we did not demonstrate blind discovery of one.

## Reproduction

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/chain-a-bidder-identity-impersonation/poc.py
```

Observed result (`evidence/run.txt`):

```
[VULN PASS] the response returns the GENUINE bidder's canonical viewerId   (PM-17)
      "Bidder A - price discussion" [PRIVATE]
        > VICTIM-ASSET: our board will not approve above 71M. Can you move on the earn-out?
[VULN PASS] an unauthenticated caller reads the bidder's PRIVATE thread        (PM-15)
[VULN PASS] the read leaves no trace anywhere in the schema
[VULN PASS] an anonymous message is stored in the victim's private thread, attributed to the bidder
[VULN PASS] an anonymous caller writes the bidder's notification setting
```

With the component patches applied — PM-15's `patch.diff`, with PM-17 intentionally
left unpatched to show where the chain breaks — the private-thread read fails
(fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN PASS] the response returns the GENUINE bidder's canonical viewerId   (PM-17, open by design)
[VULN FAIL] an unauthenticated caller reads the bidder's PRIVATE thread  0 PRIVATE thread(s)
[VULN FAIL] an anonymous message is stored in the victim's private thread  no row
[VULN FAIL] an anonymous caller writes the bidder's notification setting  flipped and restored
```

The PM-17 entry steps still succeed because PM-17 is not patched in this run; the
read, forge, and mute all fail, so patching PM-15 alone neutralizes the chain's
impact.

## Interim mitigation

Before either component is patched:

- Turning `enableConversation` off for GROUP links does not retroactively close
  PM-15's read for a `viewerId` already known, so treat already-exposed threads as
  compromised.
- Where the plan allows, require email verification on GROUP links (the seller choice
  behind PM-17) so entry needs a verified address and no free `viewerId` is handed out.
- Restrict who holds the group link URL; the chain starts from possession of it.

The component advisories carry the detail behind each step.

## Remediation

Chain A is closed by fixing either component; fix both. Apply:

- **`../pm-15-unauthenticated-conversations-api/patch.diff`** — resolve the viewer
  from the dataroom session instead of the query string, across all four
  conversation handlers, and require participation on writes. This closes the read,
  forge, and mute directly.
- **PM-17 (the identity layer)** — render and default the email-verification
  control on for GROUP-audience links, as the allow-list path already does, so
  entry requires a verified address rather than an asserted one. (PM-17 is tracked
  as a Medium in `../medium-and-low-findings.md`; its fix removes the free
  precondition that makes this chain unauthenticated.)

Fixing PM-15 alone neutralizes the impact (the negotiation becomes unreadable
without a real session). Fixing PM-17 alone removes the free identity but leaves
the conversations API open to anyone who obtains a `viewerId` another way.

## For the vulndev student

1. **Chains are where "medium" inputs become critical outputs.** PM-17 alone is "a
   group link trusts an asserted email" — a Medium. PM-15 alone needs "a
   participant's viewerId" — which sounds like a secret. Composed, PM-17 *produces*
   exactly the secret PM-15 needs, and the result is unauthenticated access to
   private deal negotiations. Always ask what each finding *hands to* another.

2. **Establish ground truth independently of the attack.** The PoC reads the
   genuine bidder's `viewerId` from the database first, then shows the attack
   returns the same id. Without that, "the response returned a viewerId" proves
   only that the endpoint returns *a* value; comparing it to ground truth proves it
   returns the *real bidder's* identity.

3. **Severity of a chain is `max`, not `sum`, unless you ran it end to end.** This
   chain was executed end to end, so it is claimed as demonstrated. Chain B reaches
   documents but not the negotiation; they share only "hold a link URL". Do not
   merge independent paths into one inflated finding, and do not claim a chain you
   did not actually run.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- Component advisories: `../pm-15-unauthenticated-conversations-api/`, and PM-17 in `../medium-and-low-findings.md`.
- OWASP API Security Top 10: API2:2023 Broken Authentication.
