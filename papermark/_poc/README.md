# PoC harness and how to run the proofs

Every finding folder holds a `poc.py` that proves the finding live against the
lab. The proofs share one harness, `pmpoc.py`, the Python port of the original
original Node harness used during the audit. It keeps the same scoring rule: a
`VULN` line is the finding, a `CONTROL` line is the baseline, and a
failed control marks the whole run invalid instead of inflating the score.

## What the lab is

A containerized Papermark on the `pm-audit-net` Docker network: `pm-audit-app`
(Next.js dev server), `pm-audit-pg` (Postgres), `pm-audit-redis`, `pm-audit-srh`
(serverless-redis-http), and LocalStack S3. The proofs run inside `pm-audit-app`,
where `http://localhost:3000` and the S3 endpoint both resolve, and read the
database back through Postgres to confirm every claimed effect.

## One-time setup after a lab restart

LocalStack is ephemeral, so repopulate the bucket, and install the two Python
dependencies the harness needs. Neither step touches the host.

```sh
# 1. Repopulate the S3 bucket (marker object per stored key).
docker exec pm-audit-app node /app/security-review/_working-notes/lab/reseed-bucket.mjs

# 2. Install the harness dependencies into a container-local directory.
docker exec pm-audit-app sh -lc '
  curl -sS https://bootstrap.pypa.io/pip/get-pip.py -o /tmp/get-pip.py
  python3 /tmp/get-pip.py -q --break-system-packages --no-warn-script-location
  python3 -m pip install -q --break-system-packages --target=/opt/poc-deps cryptography pg8000
'
```

`cryptography` mints the NextAuth session cookie (an encrypted JWE, not a plain
JWT). `pg8000` is a pure-Python Postgres driver, so no build toolchain is needed.

If the dev server is not already running:

```sh
docker exec -d -w /app pm-audit-app sh -c 'npx next dev -H 0.0.0.0 -p 3000'
```

## Running a proof

```sh
docker exec -e PYTHONPATH=/opt/poc-deps pm-audit-app \
    python3 /app/security-review/pm-20-change-role-privilege-escalation/poc.py
```

Each proof discovers the fixtures it needs from the database, so it survives a
reseed. Proofs that mutate state restore it in a `finally` block and print the
row-count delta after cleanup.

## Reading the output

- `[VULN PASS]` — a proven element of the finding.
- `[CTRL PASS]` — a baseline that held, so the VULN lines mean what they say.
- `[CTRL FAIL]` — the run is invalid; the summary says why.
- `[NOTE]` — a recorded fact, including facts that cut against the finding.
- `[SKIP]` — a step not run in this pass, with the reason.

## Lab convenience: the session cookie

`mint_cookie(email)` forges a valid session for a lab user with the lab's own
`NEXTAUTH_SECRET`. This stands in for the attacker logging in. The attacker in
these findings holds an ordinary account — registration is open — or no account
at all; the cookie is never the vulnerability.
