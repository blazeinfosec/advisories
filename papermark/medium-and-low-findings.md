# Medium and Low findings — Papermark security review

These findings are below the Critical/High bar that earns a dedicated folder, but
each was proven or source-confirmed during the review and each carries a concrete
fix. The internal working corpus and raw exploratory evidence are excluded from this
public release. This document preserves the final reportable claims and their
remediation guidance.

- **Target:** Papermark `main` @ `ed19717e`, re-validated on `72888eec`.
- **Lab:** the containerized stack described in `_poc/README.md`.

| ID | Title | Severity | Actor |
|---|---|---|---|
| PM-07 | Presigned-URL proxy checks membership, ignores role | Medium | `DATAROOM_MEMBER` |
| PM-14 | Plan and role entitlements enforced only in the browser | Medium | any member |
| PM-18 | Room-scoped member reads the tenant's whole deal inventory | Medium | `DATAROOM_MEMBER` |
| PM-05 | `WORKFLOW_LINK` downloads skip session and email checks | Medium | unauthenticated |
| PM-06 | Unauthenticated SSRF in the PDF routes (self-hosted default) | Medium | unauthenticated |
| PM-12 | Unauthenticated ZIP export of an arbitrary bucket and key list | Medium | unauthenticated |
| PM-13-adjacent PM-09 | Rate-limit keys collapse to one global bucket off Vercel | Medium | unauthenticated |
| PM-03 | Link passwords have no brute-force protection | Medium | unauthenticated |
| PM-16 | An email-gated link is an oracle for its invited audience | Medium | unauthenticated |
| PM-17 | Group-link identity is self-asserted | Medium | unauthenticated |
| PM-11 | Unauthenticated page injection into another tenant's documents | Low | unauthenticated |

PM-10 (download one-time-code rate limit keyed on a client header) was merged into
PM-09 after review showed it did not warrant a separate reportable id.

---

## PM-07 — Presigned-URL proxy checks team membership but ignores role

**Affected:** `pages/api/file/s3/get-presigned-get-url-proxy.ts:33-50`; same shape at
`lib/api/links/bulk-import.ts:91-93`. **Actor:** a `DATAROOM_MEMBER` with zero room
assignments.

`get-presigned-get-url-proxy.ts` authorizes with `users: { some: { userId } }`,
which matches any `UserTeam` row regardless of `role`, `status`, or `blockedAt`, and
consults neither `UserDataroom` nor the per-document permission groups. A room-scoped
member who is refused the team document list (403) can still mint a read URL for any
object in the team (200). Proven live: member signs an arbitrary same-team key (200),
non-member refused (403). The cross-team boundary holds; the intra-team role boundary
fails.

**Remediation:** authorize the object, not the prefix. Resolve the key to its
`Document` row and apply the same entitlement path the rest of the codebase uses —
role, `UserDataroom`, and permission groups — rather than bare team membership. Same
change at `bulk-import.ts:91-93`. This shares a root cause with PM-14 and PM-18: use
`withTeamApi` with a `requiredPermissions` set.

## PM-14 — Plan and role entitlements enforced only in the browser

**Affected:** `pages/api/teams/[teamId]/domains/index.ts:62-171`; the
`advancedLinkControlsOnPro` entitlement, read only by four React components.
**Actor:** any member on a free plan, including `DATAROOM_MEMBER`.

Custom domains are a Business-tier feature (`FREE`/`PRO` limits are both `0`), yet
the domain-creation route checks neither plan nor role — a free-plan team, and the
least-privileged role, both create a domain (201). Advanced link controls
(`advancedLinkControlsOnPro`) are gated only in React, so a free-plan team persists
screenshot protection, confidential view, email auth, and allow lists by calling the
API directly. Proven live for both.

**Remediation:** add a plan check and an `ADMIN`/`MANAGER` role check to the domain
route using the `ee/limits/` helpers. Move `advancedLinkControlsOnPro` enforcement
server-side into the link create/update handlers. Apply the link-count check in
`links/index.ts` that `bulk-import.ts:160` already performs.

## PM-18 — A room-scoped member reads the tenant's whole deal inventory

**Affected:** `pages/api/teams/[teamId]/workflow-links.ts:24,41-67`. **Actor:** a
`DATAROOM_MEMBER` with zero room entitlements.

`workflow-links.ts` checks team membership with a bare `prisma.userTeam.findUnique`
and never checks room entitlement. In one session, `carol` is refused the documents
list (403) and returned zero datarooms, yet `workflow-links` returns every data room
and document name in the tenant, including the deal codename. Names and identifiers,
not content; an authenticated insider. Proven live (200, inventory returned).

**Remediation:** move `workflow-links.ts` onto `withTeamApi` with a
`requiredPermissions` set and a resolved dataroom id, so the existing per-room
entitlement check applies. Same class and fix as PM-07 and PM-14.

## PM-05 — `WORKFLOW_LINK` downloads skip every session and email check

**Affected:** `pages/api/links/download/index.ts:83-120`. **Actor:** unauthenticated,
holding a `linkId`/`viewId` pair.

The download authorization branches on link type: `DATAROOM_LINK` verifies a dataroom
session, `DOCUMENT_LINK` verifies a link session, and `WORKFLOW_LINK` matches neither
branch — so no session is verified and the `emailAuthenticated` check never runs.
Execution falls through to the signed-URL mint. A `DOCUMENT_LINK` request is refused
(401 "Session required"); the identical `WORKFLOW_LINK` request returns 200 with a
download URL to the original file. Combined with PM-02, the `viewId` is not a
meaningful secret.

Demoted from High during the review because the live proof used a hand-built fixture;
the missing-branch logic is source-confirmed unchanged. **Remediation:** replace the
`if/else if` with an exhaustive switch over `LinkType` whose `default` denies, and
apply the document session check to `WORKFLOW_LINK`.

## PM-06 — Unauthenticated SSRF in the PDF routes (self-hosted default)

**Affected:** `pages/api/mupdf/get-pages.ts:13-24`; same guard at
`convert-page.ts:29` and `annotate-document.ts:71`. **Actor:** unauthenticated, where
`INTERNAL_API_KEY` is unset (the default — it is absent from `.env.example`).

The guard reads `token = authHeader?.split(" ")[1]` then rejects on `token !==
process.env.INTERNAL_API_KEY`. With no header and the variable unset, that is
`undefined !== undefined` → `false`, so the guard passes. The sink at `:24` is `await
fetch(url)` with `url` from the request body; `lib/utils/ssrf-protection.ts` exists
but is not called. Proven live: an internal listener logged the server-side fetch;
with the key set the same request returns 401. Response body is not returned, so
exfiltration is blind.

**Remediation:** fail closed when the variable is unset (as
`get-presigned-get-url.ts:31-33` already does) and compare with
`crypto.timingSafeEqual`; route the fetch through `ssrf-protection.ts`; better, call
PDF processing in-process rather than over HTTP.

## PM-12 — Unauthenticated ZIP export of an arbitrary bucket and key list

**Affected:** `pages/api/jobs/process-download-batch.ts:22-100`. **Actor:**
unauthenticated, where `INTERNAL_API_KEY` is unset and the bulk-download Lambda is
configured.

Behind the same fail-open guard as PM-06, the endpoint accepts `sourceBucket` and
`fileKeys` from the body, invokes the bulk-download Lambda with the deployment's AWS
credentials, and returns the presigned URL to the caller. Neither value is checked
against the team or the deployment's own bucket. Proven to reach the AWS SDK
`InvokeCommand` with attacker-controlled bucket and keys (the lab has no Lambda, so
the final ZIP step is not demonstrated — a configured deployment should be assumed
exploitable). **Remediation:** fail closed on the key; take `sourceBucket` from the
server's own config; validate every `fileKey` is prefixed with the resolved team id.

## PM-09 — Rate-limit keys collapse to one global bucket off Vercel

**Affected:** viewer-facing limiters in `app/api/views/route.ts`,
`app/api/views-dataroom/route.ts`, and `app/(ee)/api/workflow-entry/**`, all keyed on
`ipAddress()` from `@vercel/functions`. **Actor:** unauthenticated, self-hosted.

Off Vercel, `ipAddress()` returns `undefined`, so the key becomes the literal string
`verify-otp:undefined` and all users of the instance share one bucket. One attacker
exhausts the shared allowance and locks every viewer out of one-time-code
verification. Proven: 25 attempts with distinct `X-Forwarded-For` produced 11 × 429,
and Redis shows the literal `undefined` key. PM-10 (the download verify limiter keyed
on a client-controlled `x-forwarded-for`) merged into this. **Remediation:** derive
the client address from a trusted-proxy configuration, never interpolate a possibly
`undefined` value into a limiter key, and add a per-link/per-email key to
`verify-otp`.

## PM-03 — Link passwords have no brute-force protection

**Affected:** `app/api/views/route.ts:332-364`. **Actor:** unauthenticated.

The password branch has no `ratelimit()` call (the limiters guard only the
later email and one-time-code paths), the comparison at `:355` is a non-constant-time
`===`, and passwords are reversibly encrypted rather than hashed. Proven: 15–60 wrong
passwords from one IP, zero 429s. Rated Medium because the outcome depends on
owner-chosen password strength, and it is listed mainly because it chains with PM-01
as a second route to the same documents. **Remediation:** rate-limit on `linkId` and
client IP with escalating lockout, use a constant-time comparison, notify the owner
after repeated failures.

## PM-16 — An email-gated link is an oracle for its invited audience

**Affected:** `app/api/views-dataroom/route.ts:488-543`, and the same shape on
`/api/views`. **Actor:** unauthenticated.

An email-gated link distinguishes an address on its audience from one that is not,
before any verification step: an invited address falls through to the OTP block, a
stranger gets 403 — with no rate limit on the deny path. Proven: an invited bidder's
address returns a verification response while strangers return 403, and 60 deny-path
probes drew zero 429s. Held at Medium because every probe emails the owner
immediately (`BLOCKED_ACCESS` defaults to `{IMMEDIATE, ALL}`), so it is detectable
and doubles as an inbox-flood rather than a quiet sweep. Its real weight is as the
entry point of Chain A. **Remediation:** return one indistinguishable response for
every address on an email-gated link; apply the rate limit before the deny branch;
throttle `BLOCKED_ACCESS` notifications.

## PM-17 — Group-link identity is self-asserted

**Affected:** `app/api/views-dataroom/route.ts:466-495`;
`components/links/link-sheet/link-options.tsx:258`;
`email-access-section.tsx:60-68`. **Actor:** unauthenticated.

For a GROUP-audience link, access is decided by the caller's typed email against the
group's members, because `emailAuthenticated` defaults to `false`. The product
auto-hardens on the allow-list path (enabling an allow list flips verification on)
but those sections render only for GENERAL audience; on a GROUP link none render,
nothing sets the flag, and the default stands. Verified email is also plan-gated
behind Business. Asserting an invited bidder's address returns that bidder's genuine
`viewerId` — the credential PM-15 accepts — making PM-17 the identity half of Chain A.
**Remediation:** render and default the email-verification control on for
GROUP-audience links; until it is on, do not present group membership as an access
control; lift verified email out of the Business-plan gate for group links.

## PM-11 — Unauthenticated page injection into another tenant's documents (Low)

**Affected:** `pages/api/mupdf/convert-page.ts:25-355`;
`lib/files/put-file-server.ts:77-84`. **Actor:** unauthenticated, where
`INTERNAL_API_KEY` is unset.

Behind the same fail-open guard as PM-06, the page-conversion endpoint takes
`teamId`, `documentVersionId`, page number, and source URL from the body, renders a
page from an attacker-controlled PDF, writes it into another tenant's storage prefix,
and creates a `DocumentPage` row making the image part of the victim's document — a
cross-tenant write. Proven: a victim document grew from three pages to four, the
fourth attacker-supplied. Rated Low by the round-2 panel: no single configuration
makes it both exploitable and impactful without contradiction. **Remediation:** fail
closed on `INTERNAL_API_KEY`; derive `teamId` and `docId` server-side from the
`documentVersionId`, never from the body or the URL; route the fetch through
`ssrf-protection.ts`.

---

## Observations below the reporting bar

Recorded during the review so future reviewers do not need to re-derive them: link
passwords reversibly encrypted rather than hashed; `xlsx` pinned to a
vendor CDN tarball with no registry integrity; a couple of import/declaration
mismatches; and third-party clients constructed at module load that 500 unrelated
routes when their env vars are absent (an availability concern).
