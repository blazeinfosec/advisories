# PM-20 — Missing authorization in team role management lets the lowest role take over the tenant

| | |
|---|---|
| **Severity** | High |
| **Actor** | Authenticated `DATAROOM_MEMBER` — the lowest team role |
| **Prerequisites** | A session for a team the attacker already belongs to |
| **Boundary crossed** | Team role / privilege boundary (intra-tenant) |
| **Affected component** | `pages/api/teams/[teamId]/change-role.ts:49-68` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Hosted and self-hosted; no environment variable involved |
| **CWE** | CWE-862 Missing Authorization; CWE-269 Improper Privilege Management |
| **Proof** | `poc.py` — 5 vulnerability assertions, 8 controls, state restored |

## Summary

The role-management endpoint checks that the caller belongs to the team and that
the caller is not granting `ADMIN` or managing `DATAROOM_MEMBER` assignments. It
never checks that the caller is allowed to manage members at all. A
`DATAROOM_MEMBER` — scoped by Papermark's own schema to specific rooms and
"denied everywhere else" — can `PUT` its own row to `MANAGER`, then `PUT` the
team's only `ADMIN` down to `MEMBER`. The attacker gains the team-wide document
surface its role was built to deny, and the demotion leaves the team with no
admin and no in-product way to recover.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

`pages/api/teams/[teamId]/change-role.ts` was added in `788d73b4` (2024-05-21) and is
byte-present in `v0.21.0` and `v0.22.0`. The inline authorization it carries predates
the `withTeamApi` / `members.write` RBAC layer the rest of the codebase moved to, so
the gap is present across the current release line.

No optional configuration is required. The endpoint is reachable by any authenticated
member of a team, on hosted and self-hosted deployments alike; no environment variable
gates it.

## Where it lives

`pages/api/teams/[teamId]/change-role.ts:35-68` is the entire authorization. The
caller's own role is read, but it gates only two of the four possible target
roles:

```ts
const userTeam = await prisma.userTeam.findUnique({
  where: { userId_teamId: { userId, teamId } },
});
if (!userTeam) return res.status(401).json("Unauthorized");

// Only ADMINs can change roles
if (role === "ADMIN" && userTeam.role !== "ADMIN") {
  return res.status(403).json("Only admins can change user roles");
}
if (role === "DATAROOM_MEMBER" && userTeam.role !== "ADMIN" && userTeam.role !== "MANAGER") {
  return res.status(403).json("Only admins and managers can manage data room members");
}
if (userTeam?.role === "ADMIN" && userTeam.userId === userToBeChanged) {
  return res.status(401).json("You can't change the Admin");
}
```

A target role of `MANAGER` or `MEMBER` matches neither guard, so any member can
set it, on any other member. The self-protection at `:66` fires only when an
`ADMIN` changes its own row, so it does nothing against an attacker demoting
someone else.

## Attack prerequisites

- An authenticated session in the target team. A `DATAROOM_MEMBER` with zero
  room entitlements is enough — the lowest-privilege account the product issues.
- Nothing else. No environment variable, no knowledge of other identifiers (the
  admin's user id is returned by team-listing endpoints the member can reach),
  and no user interaction.

## Affected boundary

The team role boundary. `lib/api/rbac/permissions.ts` reserves the
`members.write` verb for `ADMIN` alone, and `withTeamApi` enforces it on the
routes that use the wrapper. This route predates that layer and carries an
inline `prisma.userTeam.findUnique` check that the wrapper was written to
replace, so the boundary the rest of the codebase enforces is absent here.

## Impact

Full privilege escalation inside the tenant from its lowest role, plus a denial
of control. Once the only admin is a `MEMBER`, no one can promote anyone —
`change-role` rejects every path to `ADMIN` because no `ADMIN` remains to
authorize it. Recovery needs direct database access.

In the M&A threat model Papermark is sold into, a bidder's teammate, or any
account that reached `DATAROOM_MEMBER` for a single room, takes over the seller's
whole workspace: every room, every document list, member management, and the
ability to lock the real owner out.

The self-promotion and the lockout are independent capabilities. A raw
`DATAROOM_MEMBER`, without first promoting itself, can `PUT {userToBeChanged:
<admin>, role: "MEMBER"}` and receive `204`, leaving the team with zero admins.
The escalation to `MANAGER` is a separate capability, not a prerequisite for the
lockout.

### Demonstrated

Running as `carol` (`DATAROOM_MEMBER`, zero room entitlements):

- Self-promotion `DATAROOM_MEMBER -> MANAGER` through `change-role` (HTTP 204,
  confirmed `MANAGER` in the database), after which the team document list her role
  had been refused (403) opened (200).
- Demotion of the team's only `ADMIN` to `MEMBER` (HTTP 204, confirmed), leaving the
  team with zero admins.
- The genuine admin could not restore herself through the product afterward (403) —
  the lockout is effective.

### Not demonstrated / not claimed

- **Cross-tenant reach.** This is a within-tenant escalation by an account that is
  already a member of the target team. A non-member and an unauthenticated caller are
  both refused (401), proven as controls; we claim no cross-tenant or unauthenticated
  role change.
- **Only the two ungated target roles.** We demonstrated the `MANAGER` and `MEMBER`
  targets, which the guards miss. The `ADMIN` and `DATAROOM_MEMBER` targets are
  correctly refused, and we claim no bypass of those.
- **Out-of-band recovery.** We showed the in-product recovery path is blocked after
  the lockout; we did not test operator recovery through direct database access, which
  remains available.

## Reproduction

The proof runs as `carol@victim.test` (`DATAROOM_MEMBER`, zero rooms) against
`alice@victim.test` (the team's only `ADMIN`). It reads every role back from the
database and restores the pre-run roles and room assignments in `finally`.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-20-change-role-privilege-escalation/poc.py
```

Observed result (`evidence/run.txt`):

```
[CTRL PASS] carol asking for ADMIN -> 403
[CTRL PASS] carol assigning DATAROOM_MEMBER -> 403
[VULN PASS] carol promotes herself DATAROOM_MEMBER -> MANAGER   db role=MANAGER
[VULN PASS] the promotion is effective: carol now reads the team document list  status=200
[VULN PASS] carol demotes the team's ADMIN to MEMBER           db role=MEMBER
[VULN PASS] the team is left with zero ADMINs                  admins=0
[VULN PASS] alice cannot restore herself to ADMIN through the product  status=403
```

The two `CTRL PASS` lines at the top are the point: the endpoint does reject the
caller when the target role is `ADMIN` or `DATAROOM_MEMBER`, so it is reachable
and its partial checks work. Only the `MANAGER` and `MEMBER` targets are ungated.

The two writes at the center of the escalation, carrying `carol`'s session cookie:

```
PUT /api/teams/<teamId>/change-role
  {"userToBeChanged":"<carolId>","role":"MANAGER"}   -> 204   (self-promotion)

PUT /api/teams/<teamId>/change-role
  {"userToBeChanged":"<aliceId>","role":"MEMBER"}    -> 204   (demote the only admin)
```

With `patch.diff` applied and the dev server restarted, every escalation is refused
and the roles are unchanged, while the legitimate admin path still works
(fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] carol promotes herself DATAROOM_MEMBER -> MANAGER  db role=DATAROOM_MEMBER
[VULN FAIL] the promotion is effective...  status=403
[VULN FAIL] carol demotes the team's ADMIN to MEMBER  db role=ADMIN
[VULN FAIL] the team is left with zero ADMINs  admins=1
[VULN FAIL] alice cannot restore herself to ADMIN through the product  status=204
```

The last line is a `VULN FAIL` because the assertion read "alice *cannot* restore
herself". Under the patch she can (HTTP 204), so the lockout no longer holds — the
legitimate admin path is intact. All eight controls still pass.

## Root cause

Authorization is decided per target role rather than per caller capability. The
handler asks "is this a role you are allowed to grant?" for two roles and forgets
the other two, when the question it should ask once is "are you allowed to manage
members at all?". That question has a single answer in this product — `ADMIN` —
and a single home — the `members.write` permission the RBAC layer already
defines.

## Interim mitigation

Before the patch is deployed:

- No configuration restricts who can call `change-role`; any team member reaches it,
  and there is no feature flag to disable.
- Restrict team membership to trusted users. Any member can currently self-promote to
  `MANAGER` and demote the admin, so one low-trust `DATAROOM_MEMBER` is enough to take
  the tenant over.
- Monitor `UserTeam` role changes — an unexpected `MANAGER` promotion, or the `ADMIN`
  count dropping to zero — as a detection signal until the check is in place.

Recovery from a completed attack needs direct database access to restore an `ADMIN`.

## Remediation

Apply `patch.diff`. It makes member management `ADMIN`-only for every target
role, and refuses any change that would leave the team with zero admins:

```ts
if (userTeam.role !== "ADMIN") {
  return res.status(403).json("Only admins can change user roles");
}
// ... and a last-admin guard before the write.
```

The deeper fix is to move this route onto `withTeamApi` with
`requiredPermissions: ["members.write"]`, so it inherits the same
default-deny-for-`DATAROOM_MEMBER` enforcement as the 11 routes that already use
the wrapper. The patch is the minimal in-place change; the wrapper migration
removes the whole class of inline-check drift that produced this finding (see
also PM-07, PM-14, PM-18).

Verify the fix by re-running `poc.py`: the two self-promotion `VULN` lines and
the admin-demotion lines must become controlled failures (HTTP 403), and the
summary must report zero vulnerability assertions proven.

## For the vulndev student

This is a textbook **missing-function-level-authorization** bug, and the
instructive part is *why* it slipped through when the author clearly thought
about authorization — there are three guard clauses, not zero.

1. **The guard enumerates values instead of capabilities.** The check is written
   as "if the *target role* is dangerous, require privilege". `ADMIN` and
   `DATAROOM_MEMBER` are treated as the dangerous ones. But `role` is an
   attacker-controlled enum with four values, and `MANAGER` and `MEMBER` are
   every bit as sensitive — `MANAGER` reads the whole team, and demoting an
   `ADMIN` to `MEMBER` destroys control. Whenever authorization branches on a
   value the attacker supplies, ask: what happens for the values you did *not*
   write a branch for? The safe default is deny, reached by checking the
   caller's capability once, before you ever look at the requested value.

2. **A partial guard reads as a complete one.** The `if (role === "ADMIN" ...)`
   line looks like "only admins change roles". It is not — it is "only admins
   grant the admin role". The gap is one missing clause, invisible unless you
   enumerate the enum yourself. When you audit authorization, list every value
   the input can take and tick each against the check.

3. **The PoC proves it is a real escalation, not a status-code quirk.** Notice
   the controls: the PoC first shows carol *is* refused `ADMIN` (403) and *is*
   refused the document list (403), establishing that the endpoint's partial
   checks work and that her role genuinely lacks access. Only then does it show
   the `MANAGER` write landing (204, confirmed in the database) and the document
   list opening (200). A finding is "the server returned 204"; a *proof* is "the
   privilege the server denied a moment ago is now held, confirmed in the
   database, and the baseline that denied it was real".

4. **Reversibility is part of impact.** The demotion leaves zero admins and the
   product offers no way back — `change-role` needs an existing admin to mint a
   new one. An authorization bug that also destroys the recovery path is worse
   than one that merely grants access. Always test what the victim can do *after*
   the attack, not only what the attacker gains.

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
- CWE-269: Improper Privilege Management — <https://cwe.mitre.org/data/definitions/269.html>
- OWASP API Security Top 10: API5:2023 Broken Function Level Authorization
- Related findings sharing the inline-check root cause: PM-07, PM-14, PM-18.
