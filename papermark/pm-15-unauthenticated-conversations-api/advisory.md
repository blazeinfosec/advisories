# PM-15 — The viewer-facing conversations API has no authentication

| | |
|---|---|
| **Severity** | Critical |
| **Actor** | Unauthenticated — no account, no cookie, no token |
| **Prerequisites** | A `dataroomId` and a participant's `viewerId` (both free — see below) |
| **Boundary crossed** | Viewer identity and tenant isolation |
| **Affected component** | `ee/features/conversations/api/conversations-route.ts` (all four handlers); `ee/features/conversations/lib/api/messages/index.ts:81-88` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted; no environment variable involved |
| **CWE** | CWE-306 Missing Authentication for Critical Function; CWE-639 Authorization Bypass Through User-Controlled Key |
| **Proof** | `poc.py` — 5 vulnerability assertions, 3 controls, forged message and setting restored |
| **Chain** | Entry point of **Chain A** (`../chain-a-bidder-identity-impersonation/`), reached from PM-17 |

## Summary

Papermark data rooms carry a private Q&A channel between a visitor and the room
owner. In an M&A or fundraising context that channel is where a bidder asks the
questions they do not want other bidders to see. The viewer-facing conversations
API identifies the caller by a `viewerId` taken straight from the request and
never compared to a session, cookie, or team. Any unauthenticated caller who holds
a `dataroomId` and a participant's `viewerId` can read those private threads, post
messages attributed to that participant, and toggle another viewer's notification
setting.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

`ee/features/conversations/api/conversations-route.ts` was added in `ac04841b`
(2025-04-04) and is present at `v0.21.0` and `v0.22.0`, so the current release line is
affected. The behaviour depends on no environment variable.

Configuration: the finding requires the enterprise conversations feature — the data
room Q&A channel — to be enabled on a room. Where that feature is unused there are no
threads to read, but the endpoints themselves are unauthenticated regardless.

## Where it lives

`ee/features/conversations/api/conversations-route.ts:19-28`:

```ts
const { dataroomId, viewerId } = req.query as { dataroomId?: string; viewerId?: string };
if (!dataroomId || !viewerId) return res.status(400).json({ error: "Missing dataroomId or viewerId" });
const conversations = await prisma.conversation.findMany({
  where: { dataroomId, participants: { some: { viewerId } } },
  include: { messages: {...}, dataroom: true, ... },
});
```

`viewerId` is read from the URL and used as the identity. It is never compared to a
session, a dataroom session, or a team. All four handlers — `GET /`, `POST /`,
`POST /messages`, `POST /notifications` — follow the same pattern. A second missing
check compounds it: `messages/index.ts:81-88` enrols whoever posted as a
participant, with no authorization, so posting both forges a message and makes the
poster a participant.

## Attack prerequisites

- A `dataroomId` and a participant's `viewerId`. `GET /` filters on
  `participants: { some: { viewerId } }`, so reading another party's threads needs
  that party's `viewerId`, an unguessable cuid.
- **Both are free.** PM-17 hands them over: asserting an invited bidder's email on
  a GROUP link returns that bidder's canonical `viewerId`, byte-identical to the
  one they hold, and the `dataroomId` leaks anonymously from the link's
  `_next/data` payload. No account, cookie, or `conversationId` is ever needed.

## Affected boundary

Two at once: viewer identity (the route accepts an asserted identity as proof of
that identity) and tenant isolation (the query is never scoped to the caller's
team, so a `viewerId` from one tenant reads a conversation owned by another). The
route is the one place in the audited surface where the cross-tenant boundary —
which held across a 574-request mutation sweep elsewhere — is simply absent.

## Impact

### Demonstrated

Each of the following was executed live:

- Anonymous read of a PRIVATE thread, with message bodies, no cookie.
- Cross-tenant read: a `viewerId` from one tenant reads a conversation owned by
  another, because the query is never scoped by team.
- Anonymous message forgery, attributed to the genuine participant's email address
  and indistinguishable from a real message in the owner's dashboard.
- Participant self-enrolment and toggling another viewer's notification setting.

The read is silent — comparing every table across an anonymous read showed zero
row changes. A source-confirmed second route family (the AI chat endpoint,
`app/(ee)/api/ai/chat/[chatId]/route.ts`) has the identical missing check but is
behind a feature flag off in this lab, so it is reported source-only.

### Not demonstrated / not claimed

- **Reach without a participant's `viewerId`.** `GET /` filters on
  `participants: { some: { viewerId } }`, so reading a thread needs that party's
  `viewerId`, an unguessable cuid. PM-17 supplies it for an invited bidder; absent
  that, we did not demonstrate enumeration of viewer ids.
- **The AI chat route end to end.** `app/(ee)/api/ai/chat/[chatId]/route.ts` carries
  the identical missing check but sits behind a feature flag off in this lab, so it is
  reported source-only, not executed.
- **Production write status codes.** The write handlers returned HTTP 500 in the lab
  because `TRIGGER_SECRET_KEY` is thrown *after* the database write, so the proof
  reads the row back to confirm the write landed. We did not observe the production
  201 or the notification task firing; both are inferred from the code path.

## Reproduction

The proof reads a PRIVATE thread anonymously, confirms the read writes nothing,
forges a message attributed to a genuine participant, and toggles that
participant's notification setting. It deletes the forged message and restores the
setting in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-15-unauthenticated-conversations-api/poc.py
```

Observed result (`evidence/run.txt`):

```
[VULN PASS] an unauthenticated caller reads PRIVATE threads with message bodies  9 message bodies, no cookie
      > CONFIDENTIAL: what is the real EBITDA?
[VULN PASS] the read leaves no trace anywhere in the schema  0 row changes
[VULN PASS] an anonymous message is stored in the victim's private thread
[VULN PASS] it is attributed to the genuine participant, not an anonymous author  attributed to confidential-bidder@acme.test
[VULN PASS] an anonymous caller writes another viewer's notification setting  flipped and restored
```

The write handlers return HTTP 500 in the lab because `TRIGGER_SECRET_KEY` is
thrown after the database write, so the proof reads the row back. In production the
same request returns 201 and fires the notification task.

The three unauthenticated requests, with no cookie or session:

```
GET  /api/conversations?dataroomId=<room>&viewerId=<participant viewerId>
                                      -> 200 [ PRIVATE threads with message bodies ]

POST /api/conversations/messages
  {"conversationId":"<conv>","viewerId":"<participant viewerId>","content":"..."}
                                      -> message stored, attributed to the genuine participant

POST /api/conversations/notifications
  {"conversationId":"<conv>","viewerId":"<participant viewerId>","enabled":false}
                                      -> that participant's notification setting flipped
```

With `patch.diff` applied and the dev server restarted, the route authenticates the
caller from the dataroom session cookie and the sequence collapses (fix-verification,
`_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] an unauthenticated caller reads PRIVATE threads with message bodies  0 message bodies, no cookie
[VULN PASS] the read leaves no trace anywhere in the schema  0 row changes
[VULN FAIL] an anonymous message is stored in the victim's private thread  no row
[VULN FAIL] it is attributed to the genuine participant, not an anonymous author  attributed to ?
[VULN FAIL] an anonymous caller writes another viewer's notification setting  flipped and restored (original=True)
```

The one remaining `VULN PASS` — "the read leaves no trace" — passes trivially because
the anonymous read is now denied, so nothing is written; it measures the absence of a
write, not a residual bypass.

## Root cause

The route authenticates nothing. It treats a `viewerId` from the request as proof
that the caller is that viewer, when a `viewerId` is just an identifier the
attacker can obtain. Identity must be established from a server-held credential
(the dataroom session cookie, resolved in Redis), never asserted in a query
parameter.

## Interim mitigation

Before the patch is deployed:

- Disable the data room conversations feature on sensitive rooms. With the feature off
  there are no threads to read or forge, which removes the exposure for those rooms.
  The endpoints stay unauthenticated, so this is containment, not a fix.
- A network-level block does not help here: the routes are viewer-facing and must stay
  reachable by legitimate anonymous visitors, unlike the scheduler routes in PM-13.

No configuration keeps the conversations feature usable and authenticates the caller
without the patch.

## Remediation

Apply `patch.diff`. It resolves the caller's viewer from the dataroom session
cookie in every handler and ignores any `viewerId` in the request:

```ts
async function resolveSessionViewer(req, dataroomId) {
  // scan pm_drs_<linkId> cookies, verify each session, accept one bound to this dataroom
  // return session.viewerId or null
}
// GET /, POST /: viewerId = await resolveSessionViewer(req, dataroomId); 401 if null
// POST /messages, /notifications: resolve dataroomId from the conversation, then the same,
//   and require that the resolved viewer already participates.
```

The write handlers additionally require the resolved viewer to be an existing
participant, which closes the self-enrolment at the route. Remove, or gate on an
authenticated session, the unauthorized `ConversationParticipant.create` at
`messages/index.ts:81-88`. Separately, `conversations-route.ts:261-266` returns
`error.message` verbatim to anonymous callers, leaking Prisma payloads and schema
field names; return a generic error.

Verify by applying the patch, **restarting the dev server**, and re-running
`poc.py`: the anonymous read must return 401 and all five `VULN` assertions must
fail.

## For the vulndev student

1. **An identifier in a request is never an identity.** The entire bug is `where:
   { participants: { some: { viewerId } } }` with `viewerId` from the query. The
   route reasons "you gave me the participant's id, so you must be the
   participant". Identity has to come from something the server issued and the
   attacker cannot mint — here, the dataroom session stored in Redis. When you see
   a user/tenant/owner id read from query, body, or header and used as the subject
   of an authorization decision, that is the bug.

2. **An unguessable id is not an access control.** The one hurdle is knowing the
   victim's `viewerId`, a random cuid. That feels like a secret, but PM-17 hands it
   out, and in general "you need to know an id" is obscurity, not authorization.
   Rate the finding on the missing control, and separately assess how hard the
   precondition really is — here, free.

3. **Check every handler, not the one in the write-up.** It is tempting to report
   the GET and stop. The same missing check sits on `POST /`, `POST /messages`, and
   `POST /notifications`, turning a read bug into read + forge + tamper. Enumerate
   every method and path on a route that shares a helper or a pattern.

4. **One systemic defect, not six IDORs.** The honest framing is "viewer identity
   is accepted from the request and never authenticated", affecting two route
   families, rather than six separate findings. Inflating one root cause into many
   findings misleads prioritization; the fix is one change applied consistently.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-306: Missing Authentication for Critical Function — <https://cwe.mitre.org/data/definitions/306.html>
- CWE-639: Authorization Bypass Through User-Controlled Key — <https://cwe.mitre.org/data/definitions/639.html>
- OWASP API Security Top 10: API2:2023 Broken Authentication. Chain entry: PM-17 → PM-15.
