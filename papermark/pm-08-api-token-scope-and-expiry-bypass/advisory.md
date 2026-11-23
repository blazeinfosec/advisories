# PM-08 — API tokens ignore scope and expiry: a read-only, expired token can write

| | |
|---|---|
| **Severity** | High |
| **Actor** | Holder of any API token for the team, including read-only or expired |
| **Prerequisites** | Possession of any `RestrictedToken` string for the team |
| **Boundary crossed** | Token authorization (scope and lifetime) |
| **Affected component** | `pages/api/teams/[teamId]/documents/index.ts:375-395` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted |
| **CWE** | CWE-863 Incorrect Authorization; CWE-613 Insufficient Session Expiration |
| **Proof** | `poc.py` — 1 vulnerability assertion, 3 controls, token and row removed |

## Summary

Papermark issues scoped API tokens — `RestrictedToken.scopes` is a space-separated
preset (`apis.all`, `apis.read`) or granular list (for example `documents.write
links.write`) — and supports expiry through `RestrictedToken.expires`. The
document endpoint's bearer path enforces neither. A token issued read-only, and
expired a day ago, creates documents.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

The route, `pages/api/teams/[teamId]/documents/index.ts`, is long-standing: it was
added in `7ebb7466` (2023-10-15) and is present at `v0.21.0` and `v0.22.0`. The bearer
block that omits `scopes` and `expires` is the current `main` form; we exploited `main`
at `ed19717e` and did not separately run the exploit against a tagged build.

Configuration: the attacker must hold a `RestrictedToken` for the team — an API token
the team has issued. The route accepts bearer tokens wherever the API is used; the PoC
seeds its own token (hashed as `lib/api/auth/token.ts` does,
`sha256(token + NEXTAUTH_SECRET)`) rather than depending on a pre-existing one. No
optional env var gates the route.

## Where it lives

`pages/api/teams/[teamId]/documents/index.ts:379-395`:

```ts
const restrictedToken = await prisma.restrictedToken.findUnique({
  where: { hashedKey: hashedToken },
  select: { userId: true, teamId: true },
});
if (!restrictedToken) return res.status(401).json({ error: "Unauthorized" });
if (restrictedToken.teamId !== teamId) return res.status(401).json({ error: "Unauthorized" });
userId = restrictedToken.userId;
```

`scopes` and `expires` are not merely unchecked — they are not selected from the
database, so the handler could not evaluate them if it wanted to. The only tests
are that the token exists and belongs to the team in the URL. Execution then
continues into the same write path a full session user takes.

The finding was found in the Phase 5 sweep. Two further instances share the
omission and are untested here because each imports a module absent from this
partial checkout: `documents/[id]/versions/index.ts:34-60`, and
`webhooks/services/[...path]/index.ts:177-180`, which selects
`{ teamId: true, rateLimit: true }` — scopes and expiry unread there too.
`lib/oauth/scopes.ts` (`ALLOWED_SCOPES`) is also absent, so the scope model cannot
be assessed as a whole; what is shown is that this route consults no part of it.

## Attack prerequisites

- Possession of any `RestrictedToken` string for the team. The token can be one
  deliberately issued read-only, and one that has already expired. No session, no
  cookie, no user interaction.

## Affected boundary

Token authorization. Scope and expiry are the two controls that bound what a
token can do and for how long. Both are security promises Papermark makes to
anyone who issues a token to an integration, and neither is kept on this route.

## Impact

A token handed to a read-only integration, a reporting script, or a third-party
tool carries full write authority on this endpoint. Revocation by expiry does not
work either: an expired token keeps writing indefinitely, so rotating a leaked
token does not contain it. For an organization that issued a narrow token
precisely to limit blast radius, the limit is not enforced.

### Demonstrated

A `RestrictedToken` issued read-only (`scopes: "apis.read"`) and expired a day earlier
created a document through `POST /api/teams/{teamId}/documents`. The row persisted
(`row=cmw7wt1h0...`), confirming the write landed despite both the scope and the
expiry. Authentication still worked: a bogus bearer token and the valid token aimed at
another team were both refused 401.

### Not demonstrated / not claimed

- **Extent of the write surface.** We demonstrated document creation on this one route.
  We did not enumerate every write reachable with a read-only or expired token.
- **Two sibling routes carry the same omission but were not run here**, because each
  imports a module absent from this partial checkout:
  `documents/[id]/versions/index.ts:34-60` and
  `webhooks/services/[...path]/index.ts:177-180` (which selects
  `{ teamId: true, rateLimit: true }` — scopes and expiry unread there too). We assert
  the omission from source, not from a live run.
- **The scope model as a whole was not assessed**: `lib/oauth/scopes.ts`
  (`ALLOWED_SCOPES`) is absent from the checkout. We show only that this route consults
  no part of it.
- **Token acquisition was not demonstrated.** The attacker is assumed to already hold a
  token for the team; we did not demonstrate obtaining or stealing one.

## Reproduction

The proof seeds a token with `scopes: "apis.read"` and `expires` one day in the
past (hashed exactly as `lib/api/auth/token.ts`), then performs a write. It reads
the row back and removes the token and the document in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-08-api-token-scope-and-expiry-bypass/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] token is read-only and already expired  scopes=apis.read expires=2026-11-07 ...
[VULN PASS] an expired read-only token performs a write (document row persisted)  row=cmw7wt1h0...
[CTRL PASS] a bogus bearer token is refused 401
[CTRL PASS] the valid token aimed at another team is refused 401
```

The write returns HTTP 500 — the Trigger.dev stub raised after the write — so the
proof reads the document row back rather than trusting the status. The two
controls establish that authentication works: a bogus token and a cross-team
token are both correctly refused. Only authorization — scope and lifetime — is
missing.

The write request — a read-only, expired bearer token creating a document:

```
POST /api/teams/<teamId>/documents
Authorization: Bearer <read-only, expired token>
  {"name":"pm08.pdf","url":"<teamId>/doc/x.pdf","storageType":"S3_PATH",
   "type":"pdf","contentType":"application/pdf"}          -> Document row created
```

The response is HTTP 500 (a Trigger.dev stub raises after the write), so the proof
reads the `Document` row back rather than trusting the status code.

With `patch.diff` applied and the dev server restarted, the write is refused and no row
is created (fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] an expired read-only token performs a write (document row persisted)  row=none
```

The patch returns 401 for the expired token and 403 for a non-expired read-only token.

## Root cause

The handler authenticates the token but never authorizes it. Authentication asks
"is this a real token for this team?" and both of those are checked.
Authorization asks "is this token allowed to do *this*, *now*?" — the scope and
expiry questions — and neither is asked, because neither field is even loaded.

## Interim mitigation

Before the patch is deployed:

- There is no setting that enforces scope or expiry on this route; both fields are
  unread in code.
- Treat every issued API token as full-scope and non-expiring, regardless of how it was
  created. A token issued read-only is not read-only here, and an expired token is not
  revoked here.
- Revoke (delete) any token that should no longer hold write access rather than relying
  on its expiry or scope, and rotate tokens issued to third parties or read-only
  integrations.

## Remediation

Apply `patch.diff`. It selects `scopes` and `expires`, rejects an expired token,
and requires a write-permitting scope before the write proceeds:

```ts
select: { userId: true, teamId: true, scopes: true, expires: true },
// ...
if (restrictedToken.expires && restrictedToken.expires.getTime() < Date.now())
  return res.status(401).json({ error: "Token expired" });
const scopes = (restrictedToken.scopes ?? "apis.all").split(" ");
if (!(scopes.includes("apis.all") || scopes.includes("documents.write")))
  return res.status(403).json({ error: "Insufficient token scope for this operation" });
```

The deeper fix is to move bearer authentication and scope enforcement into one
shared middleware, since this block is copy-pasted across handlers — the two
untested instances above carry the identical omission. Audit every route that
accepts `Authorization: Bearer` for the same gap.

Verify by re-running `poc.py`: the write must now be refused (401 for the expired
token; 403 if a non-expired read-only token is substituted), so the single `VULN`
assertion fails.

## For the vulndev student

1. **Authentication is not authorization.** This route proves the token is real
   and team-matched, then stops. Those are identity checks. Scope ("what may this
   credential do") and expiry ("is it still valid") are authorization checks, and
   a credential system that skips them has an access-control bug even though
   "login" works. When you review token or API-key handling, list the credential's
   claimed limits — scope, expiry, audience, rate — and check each is enforced,
   not just that the key resolves.

2. **The tell is the `select`.** The strongest signal here is that `scopes` and
   `expires` are not even read from the database. A field the code never loads is
   a field the code cannot be enforcing. When auditing an ORM-backed handler, read
   the `select`/projection first: it bounds what the handler can possibly check.

3. **Copy-pasted auth drifts.** The same bearer block appears on at least three
   routes, and the fix is the same each time — which is the argument for one
   middleware instead of three call sites. Duplicated security code is where
   coverage gaps hide, because a reviewer fixes the instance they are looking at
   and the clones stay broken. Prefer a single choke point.

4. **Prove authn still works, to isolate the authz gap.** The controls (bogus
   token → 401, wrong team → 401) matter: they show the finding is specifically
   missing *authorization*, not a broken endpoint that accepts anything. A proof
   that shows both what still works and what does not is far harder to dismiss.

## Disclosure and contact

Reported by Blaze Information Security as part of a source-and-lab security review of
Papermark. We'd like to coordinate disclosure: please confirm receipt and your
preferred timeline. We can request a CVE once a fix is available, unless you'd rather
handle the assignment.

Contact: Blaze Information Security, julio.fort@blazeinfosec.com.

Part of the analysis was AI-assisted; every finding and the proof of concept were
manually validated against a live lab.

## References

- CWE-863: Incorrect Authorization — <https://cwe.mitre.org/data/definitions/863.html>
- CWE-613: Insufficient Session Expiration — <https://cwe.mitre.org/data/definitions/613.html>
- OWASP API Security Top 10: API5:2023 Broken Function Level Authorization
