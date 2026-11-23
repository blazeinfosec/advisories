# PM-13 — Scheduled jobs and the webhook callback are unauthenticated off Vercel

| | |
|---|---|
| **Severity** | High |
| **Actor** | Unauthenticated |
| **Prerequisites** | The deployment is not on Vercel (any self-hosted install) |
| **Boundary crossed** | Scheduled-job / internal callback authentication |
| **Affected component** | `lib/cron/verify-qstash.ts:11-14`; `lib/cron/index.ts:12-15`; inline checks in `app/api/cron/{domains,year-in-review,dataroom-digest/daily,dataroom-digest/weekly}/route.ts`; `app/api/webhooks/callback/route.ts` |
| **Affected version** | Papermark `main` @ `ed19717e`; re-validated on `72888eec` |
| **Deployment profile** | Self-hosted only. On Vercel the signature is verified and these return 401 |
| **CWE** | CWE-306 Missing Authentication for Critical Function; CWE-1188 Insecure Default |
| **Proof** | `poc.py` — 2 vulnerability assertions, 1 control, 3 side-effecting routes skipped |

## Summary

Every scheduled-job endpoint, and the webhook callback, verify their QStash
signature only when `process.env.VERCEL` is `"1"`. On any other deployment the
check is skipped entirely, so anyone on the internet can invoke the platform's
scheduled jobs and post forged webhook-delivery records on demand.

## Affected versions and configuration

Audited on `main` at `ed19717e`, re-validated at `72888eec` — 939 commits past the
latest release tag `v0.22.0` (2025-12-03). The audited code is untagged `main`, newer
than any tagged release.

`lib/cron/verify-qstash.ts` was added in `8f60a7da` (2025-03-26), and the
`process.env.VERCEL` gate is byte-present at `v0.21.0` and `v0.22.0`, so the current
release line is affected.

**This fails open only off Vercel.** The guard returns early when
`process.env.VERCEL !== "1"`. A Vercel-hosted deployment sets that variable, so the
signature is verified and these routes return 401 — a Vercel deployment is **not**
affected. Every self-hosted deployment (Docker, a VM, any non-Vercel host) leaves the
variable unset, so the check is skipped. No optional setting turns this on or off: the
exposure is the default for self-hosting, and nothing short of the patch keeps the
jobs reachable by the scheduler while restoring the signature check.

## Where it lives

`lib/cron/verify-qstash.ts:11-14` opens with:

```ts
// skip verification in local development
if (process.env.VERCEL !== "1") {
  return;
}
```

The comment says "local development", but the condition is true for every
non-Vercel deployment, including production self-hosting. The cron routes repeat
the same shape inline, wrapping the whole `receiver.verify` call in `if
(process.env.VERCEL === "1")`.

Compounding it, `lib/cron/index.ts:12-15` constructs the `Receiver` with
`process.env.QSTASH_CURRENT_SIGNING_KEY || ""` — an empty HMAC secret rather than
failing closed — so even on Vercel an unconfigured deployment would verify against
an empty key.

Two verification styles exist, and the finding proves both are bypassable:

- **Shared helper** `verifyQstashSignature`, used by `webhooks/callback` and
  `cron/welcome-user`.
- **Inline** `if (process.env.VERCEL === "1")`, in `cron/domains`,
  `cron/year-in-review`, and `cron/dataroom-digest/{daily,weekly}`.

## Attack prerequisites

- The deployment is not on Vercel. No account, cookie, token, or signature. One
  HTTP request per job.

## Affected boundary

The trust boundary between Papermark's scheduler (QStash) and its own job
endpoints. These routes are meant to be callable only by the signed scheduler;
the signature is their only authentication, and it is not checked off Vercel.

## Impact

An unauthenticated caller invokes the platform's maintenance jobs at will and
forges webhook-delivery records. The obvious amplifications were checked and found
bounded — digest email flooding is prevented by `popDigestQueue` draining the
queue, domain-warning emails are de-duplicated, and attacker-timed domain deletion
is gated on `invalidDays >= 30` and zero link clicks. What remains:

- Forced, unbounded execution of maintenance work (per-domain Vercel API calls,
  queue and database load) on every invocation.
- Forged webhook deliveries: `webhooks/callback` writes an attacker-supplied
  `url`, `status`, `request_body`, and `response_body` to a team's webhook event
  log for any `webhookId` that exists, so a team debugging a webhook sees
  fabricated deliveries. (A stored-XSS chain through those bodies was investigated
  and does not exist — the render path escapes through Shiki's `codeToHtml`.)
- A forward-looking risk: any scheduled job added later inherits this bypass, and
  the next one may not be idempotent.

### Demonstrated

Both verification styles were bypassed unauthenticated, with no side effects:

- The shared `verifyQstashSignature` helper was reached past its guard on
  `/api/webhooks/callback` with no `Upstash-Signature` header (HTTP 200 "Webhook not
  found", reaching the database lookup).
- The inline `if (VERCEL === "1")` guard was skipped on
  `/api/cron/dataroom-digest/daily` (HTTP 200, not 401).

### Not demonstrated / not claimed

- **The downstream side effects of the jobs.** The proof fired only safe probes. It
  did not send digest or welcome emails, make the per-domain Vercel API calls, delete
  a domain, or write a forged webhook-delivery record. It proves the authentication
  gate is bypassable, not the full downstream impact of each job; the amplifications
  in Impact above are source-confirmed and bounded, not executed end to end.
- **A stored-XSS chain through forged webhook bodies.** Investigated and found absent
  — the render path escapes through Shiki's `codeToHtml`.
- **Any effect on a Vercel-hosted deployment.** Not applicable: the guard passes there
  and the routes return 401.

## Reproduction

The proof demonstrates the bypass on both verification styles without side
effects. It does not fire the routes that make external calls, send email, or
mutate state — those are recorded as SKIP with reasons.

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-13-unauthenticated-scheduled-jobs/poc.py
```

Observed result (`evidence/run.txt`):

```
[VULN PASS] the shared verifyQstashSignature guard is skipped with no Upstash-Signature
            (webhooks/callback -> HTTP 200 "Webhook not found", reached the DB lookup)
[VULN PASS] the inline 'if (VERCEL === 1)' guard is skipped with no Upstash-Signature
            (cron/dataroom-digest/daily -> HTTP 200, not 401)
[CTRL PASS] the callback probe wrote nothing (Webhook-not-found path precedes the write)  0 row changes
```

The callback probe uses a nonexistent `webhookId`, so the handler returns "Webhook
not found" *before* `recordWebhookEvent` — reaching that response proves the
signature guard returned without checking, and the row-count control confirms no
write. The digest route is idempotent (the queue is empty, so `processed: 0`).

The two unauthenticated requests, with no `Upstash-Signature` header:

```
POST /api/webhooks/callback?webhookId=pm13-nonexistent&eventId=pm13&event=document.created
  {"status":200,"url":"http://example.invalid","createdAt":0,
   "sourceMessageId":"pm13","sourceBody":"","body":""}   -> 200 "Webhook not found"

POST /api/cron/dataroom-digest/daily
  {}                                                      -> 200 (not 401)
```

With `patch.diff` applied and the dev server restarted, both guards fail closed
(fix-verification, `_working-notes/fix-verification-2026-11-08.txt`):

```
[VULN FAIL] the shared verifyQstashSignature guard is skipped with no Upstash-Signature  reached the DB lookup unauthenticated
[VULN FAIL] the inline 'if (VERCEL === 1)' guard is skipped with no Upstash-Signature  HTTP 401 (401 would mean the signature was enforced)
```

In the lab no signing key is configured, so the patched helper fails closed (the
callback errors rather than serving) and the digest route returns 401; both `VULN`
assertions fail. In a real deployment the signing key is set, and legitimately signed
QStash calls continue to pass.

## Root cause

Authentication is gated on a hosting-provider flag, not on the environment or on
whether the credential is configured. `process.env.VERCEL` is a deployment-target
marker that is simply absent everywhere except Vercel, so "verify only on Vercel"
silently means "never verify when self-hosted". A security control must never
depend on an ambient variable whose absence disables it.

## Interim mitigation

Before the patch is deployed, on a self-hosted install:

- Block external access to `/api/cron/*` and `/api/webhooks/callback` at the reverse
  proxy or edge, allowing only the scheduler's own source. The signature is the only
  intended authentication, and off Vercel it is not checked, so a network-level
  restriction is the stopgap.
- Do **not** set `VERCEL=1` to force the check on. The flag also changes
  hosting-specific behaviour elsewhere, and pinning a security control to an unrelated
  deployment marker is not a safe mitigation.

No configuration keeps these jobs reachable by the scheduler and restores the
signature check without the patch.

## Remediation

Apply `patch.diff`. It verifies the signature on every deployment and fails closed
when no signing key is configured, in the shared helper and in all four inline
routes:

```ts
// verify-qstash.ts
if (!process.env.QSTASH_CURRENT_SIGNING_KEY) {
  throw new Error("QStash signing key is not configured.");
}
// then verify the Upstash-Signature unconditionally
```

```ts
// each inline cron route
if (!process.env.QSTASH_CURRENT_SIGNING_KEY) {
  return new Response("Unauthorized", { status: 401 });
}
const isValid = await receiver.verify({ ... });
if (!isValid) return new Response("Unauthorized", { status: 401 });
```

If a local-development escape hatch is wanted, gate it explicitly on `NODE_ENV ===
"development"`, never on a hosting-provider variable. Stop defaulting the signing
keys to `""` in `lib/cron/index.ts`.

Verify by applying the patch, **restarting the dev server** (so the routes
recompile), and re-running `poc.py`: with no signing key configured, the lab
leaves both routes fail-closed — the callback throws (HTTP 500) and the digest
route returns 401 — so both `VULN` assertions fail. In a real deployment, the
signing key is set and legitimate signed calls from QStash continue to pass.

## For the vulndev student

1. **Beware controls keyed on ambient deployment flags.** The whole bug is `if
   (process.env.VERCEL !== "1") return;`. On the platform the author tested
   (Vercel) it works; everywhere else the variable is simply undefined, so the
   guard disables itself. When a security check reads an environment variable, ask
   "what happens on a host where this is unset?" — if the answer is "the check is
   skipped", it is an insecure-default bug.

2. **The comment lies, and that is a signal.** The code says "skip verification in
   local development" but the condition covers all production self-hosting. When a
   comment describes a narrower intent than the condition actually implements,
   you have likely found a gap. Read the predicate, not the prose.

3. **Fail closed on missing secrets.** `new Receiver({ currentSigningKey:
   process.env.X || "" })` turns a missing secret into an empty one, so
   verification silently degrades instead of refusing. Credentials and keys should
   make the system refuse to operate when absent, not operate without them.

4. **Prove the bypass without becoming the attack.** The interesting discipline
   here is choosing probes with no side effects: a nonexistent `webhookId` reaches
   the auth-relevant code path and returns before any write, and an idempotent
   digest drains an empty queue. You can prove "the guard was skipped" without
   sending emails, deleting domains, or forging records. State the routes you did
   not fire and why — a reviewer trusts a proof more when it shows restraint.

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
- CWE-1188: Insecure Default Initialization of Resource — <https://cwe.mitre.org/data/definitions/1188.html>
- Upstash QStash request signature verification documentation.
