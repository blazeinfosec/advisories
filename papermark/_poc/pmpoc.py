"""Shared harness for the Papermark Python proofs of concept.

This is the Python port of ``security-review/_working-notes/lab/poc-lib.mjs``. It
keeps the same scoring discipline so a run cannot flatter itself:

    VULN(name, cond)     a claim that IS the finding. Only these score.
    CONTROL(name, cond)  establishes the baseline. A failing control INVALIDATES
                         the run instead of adding to the score.
    OBSERVE(name)        a recorded fact that scores nothing, including facts
                         that work against the finding.
    SKIP(name, why)      a stage that did not run, stated plainly.

Anything that claims a database effect reads the row back through ``db()``.

Runtime: the PoCs run inside the ``pm-audit-app`` container, where
``http://localhost:3000`` and the S3 endpoint both resolve. Dependencies
(``cryptography`` for the session cookie, ``pg8000`` for Postgres) live in
``/opt/poc-deps`` — see ``_poc/README.md`` for the one-time bootstrap. Invoke a
PoC as::

    docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
        python3 /app/security-review/<finding>/poc.py

Environment overrides: ``PM_BASE`` (default ``http://localhost:3000``) and
``PM_ENV`` (default ``/app/.env``) for the database URL and NextAuth secret.
"""

import json as _json
import hashlib
import hmac
import os
import time
import urllib.parse
import urllib.request
import uuid

import pg8000.dbapi
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.environ.get("PM_BASE", "http://localhost:3000")
_ENV_PATH = os.environ.get("PM_ENV", "/app/.env")


# ---------------------------------------------------------------- environment
def _env():
    out = {}
    with open(_ENV_PATH, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


_ENV = _env()


# ---------------------------------------------------------------- database
_conn = None


def _connect():
    global _conn
    if _conn is not None:
        return _conn
    url = _ENV.get("POSTGRES_PRISMA_URL") or _ENV.get("DATABASE_URL")
    if not url:
        raise RuntimeError("no database URL in env")
    u = urllib.parse.urlparse(url)
    _conn = pg8000.dbapi.connect(
        user=urllib.parse.unquote(u.username or "postgres"),
        password=urllib.parse.unquote(u.password or ""),
        host=u.hostname or "localhost",
        port=u.port or 5432,
        database=(u.path or "/postgres").lstrip("/"),
    )
    _conn.autocommit = True
    return _conn


def db(sql, params=()):
    """Run a query, return a list of dict rows. ``$1``-style params are rewritten
    to pg8000's ``%s`` placeholders."""
    cur = _connect().cursor()
    # Translate $1, $2, ... into %s in order, leaving the values list aligned.
    rewritten, i = [], 0
    out_params = []
    tokens = sql.split("$")
    rewritten.append(tokens[0])
    for tok in tokens[1:]:
        j = 0
        while j < len(tok) and tok[j].isdigit():
            j += 1
        idx = int(tok[:j])
        out_params.append(params[idx - 1])
        rewritten.append("%s" + tok[j:])
    sql2 = "".join(rewritten) if len(tokens) > 1 else sql
    if out_params:
        cur.execute(sql2, tuple(out_params))
    else:
        cur.execute(sql2)
    if cur.description is None:
        cur.close()
        return []
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    cur.close()
    return rows


def db_close():
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def table_counts():
    """Row count of every base table, as a dict, in one round trip."""
    tables = db(
        "select table_name from information_schema.tables "
        "where table_schema='public' and table_type='BASE TABLE' order by table_name"
    )
    union = " union all ".join(
        f"select '{t['table_name']}' as t, count(*)::int as n from \"{t['table_name']}\""
        for t in tables
    )
    return {r["t"]: r["n"] for r in db(union)}


def count_delta(before, after):
    out = {}
    for k in set(before) | set(after):
        n = after.get(k, 0) - before.get(k, 0)
        if n != 0:
            out[k] = n
    return out


# ---------------------------------------------------------------- http
def _request(method, path, body=None, cookie=None, headers=None):
    url = BASE + path
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = _json.dumps(body).encode("utf-8")
        hdrs["content-type"] = "application/json"
    if cookie:
        hdrs["cookie"] = cookie
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        resp = urllib.request.urlopen(req, timeout=180)
        return resp.getcode(), resp.read().decode("utf-8", "replace"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers


def get(path, cookie=None, headers=None):
    return _request("GET", path, None, cookie, headers)


def post(path, body=None, cookie=None, headers=None):
    return _request("POST", path, body if body is not None else {}, cookie, headers)


def put(path, body=None, cookie=None, headers=None):
    return _request("PUT", path, body if body is not None else {}, cookie, headers)


def fetch_bytes(url):
    """Fetch a signed URL (or any URL) and return (status, bytes)."""
    try:
        resp = urllib.request.urlopen(url, timeout=180)
        return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def as_json(text):
    try:
        return _json.loads(text)
    except Exception:
        return {"_raw": text[:300]}


def build_id():
    import re
    _, html, _ = get("/")
    m = re.search(r"/_next/static/([^/\"]+)/_buildManifest\.js", html)
    return m.group(1) if m else "development"


def link_data(link_id, cookie=None):
    bid = build_id()
    status, text, _ = get(f"/_next/data/{bid}/view/{link_id}.json", cookie)
    return status, text, as_json(text)


# ---------------------------------------------------------------- session cookie
def _b64u(raw):
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _hkdf_sha256(ikm, salt, info, length):
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def mint_cookie(email, max_age=86400):
    """Mint a NextAuth v4 session cookie (encrypted JWE, dir/A256GCM) for a lab
    user, equivalent to that user having logged in. Uses the lab's own
    ``NEXTAUTH_SECRET``. This is a lab convenience; the attacker in these findings
    holds an ordinary account and would simply log in."""
    secret = _ENV["NEXTAUTH_SECRET"]
    rows = db(
        'select id, email, name, image, "createdAt" from "User" where email=$1', [email]
    )
    if not rows:
        raise RuntimeError(f"no such user: {email}")
    u = rows[0]
    created = u["createdAt"]
    created = created.isoformat() if hasattr(created, "isoformat") else created
    now = int(time.time())
    payload = {
        "sub": u["id"],
        "email": u["email"],
        "name": u["name"],
        "user": {
            "id": u["id"],
            "email": u["email"],
            "name": u["name"],
            "image": u["image"],
            "createdAt": created,
        },
        "iat": now,
        "exp": now + max_age,
        "jti": str(uuid.uuid4()),
    }
    key = _hkdf_sha256(
        secret.encode(), b"", b"NextAuth.js Generated Encryption Key", 32
    )
    header = _b64u(_json.dumps({"alg": "dir", "enc": "A256GCM"}).encode())
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, _json.dumps(payload).encode(), header)
    body, tag = ct[:-16], ct[-16:]
    token = b".".join([header, b"", _b64u(iv), _b64u(body), _b64u(tag)]).decode()
    return f"next-auth.session-token={token}"


# ---------------------------------------------------------------- scoring
_results = {"vuln": [], "control": [], "observe": [], "skip": []}


def _line(tag, name, ok, detail):
    state = "" if ok is None else (" PASS" if ok else " FAIL")
    print(f"  [{tag}{state}] {name}" + (f"  {detail}" if detail else ""))


def VULN(name, cond, detail=""):
    cond = bool(cond)
    _results["vuln"].append((name, cond, detail))
    _line("VULN", name, cond, detail)
    return cond


def CONTROL(name, cond, detail=""):
    cond = bool(cond)
    _results["control"].append((name, cond, detail))
    _line("CTRL", name, cond, detail)
    return cond


def OBSERVE(name, detail=""):
    _results["observe"].append((name, detail))
    _line("NOTE", name, None, detail)


def SKIP(name, why):
    _results["skip"].append((name, why))
    _line("SKIP", name, None, why)


def log(s=""):
    print(s)


def summary(title):
    vp = sum(1 for _, ok, _ in _results["vuln"] if ok)
    vf = len(_results["vuln"]) - vp
    cp = sum(1 for _, ok, _ in _results["control"] if ok)
    cf = len(_results["control"]) - cp
    log("")
    log("=" * 72)
    log(title)
    log("=" * 72)
    log(f"  vulnerability assertions : {vp} proven, {vf} not proven   <- the finding")
    log(f"  controls                 : {cp} held, {cf} failed          <- baseline only")
    log(f"  observations             : {len(_results['observe'])}")
    log(f"  skipped                  : {len(_results['skip'])}")
    if cf > 0:
        log("")
        log("  RUN INVALID. A control failed, so the fixture does not establish the")
        log("  baseline these assertions are measured against:")
        for name, ok, detail in _results["control"]:
            if not ok:
                log(f"    - {name}  {detail}")
    if _results["skip"]:
        log("")
        log("  Not demonstrated in this run:")
        for name, why in _results["skip"]:
            log(f"    - {name}: {why}")
    log("")
    return {"vp": vp, "vf": vf, "cp": cp, "cf": cf, "invalid": cf > 0}
