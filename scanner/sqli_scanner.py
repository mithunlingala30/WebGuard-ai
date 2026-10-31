"""
Controlled, NON-destructive SQL injection check (error-based with differential confirmation).

For each parameter we send:
  1. baseline value
  2. value + a single quote        -> may provoke a database syntax error
  3. value + two quotes (escaped)  -> a valid string; used to CONFIRM the first result
No data is extracted and no SQL commands beyond a stray quote are ever sent.

  confirmed = error signature appears with ' but NOT with the baseline and NOT with ''
  suspected = error signature appears with ' and is not in the baseline, but '' also errors
"""
import re

from scanner.base import RawFinding, snippet

# (dbms, specific?, regex)
SIGNATURES = [
    ("MySQL/MariaDB", True, r"you have an error in your sql syntax"),
    ("MySQL/MariaDB", True, r"check the manual that corresponds to your (mysql|mariadb) server version"),
    ("MySQL/MariaDB", True, r"mysqli?_(fetch|query|num_rows)|com\.mysql\.jdbc|mysqlexception"),
    ("PostgreSQL", True, r"unterminated quoted string at or near|pg_query\(\)|psqlexception|postgresql.{0,40}error"),
    ("Microsoft SQL Server", True, r"unclosed quotation mark after the character string|\[sql server\]|system\.data\.sqlclient\.sqlexception|microsoft ole db provider for sql server"),
    ("Oracle", True, r"ora-\d{5}|quoted string not properly terminated"),
    ("SQLite", True, r"sqlite3?\.operationalerror|sqlite_error|sqliteexception|sqlite/jdbcdriver|unrecognized token: ?[\"']"),
    ("Generic SQL", False, r"sqlstate\[|syntax error at or near|odbc .{0,30}driver|sql syntax.{0,40}error"),
]
COMPILED = [(d, s, re.compile(p, re.I)) for d, s, p in SIGNATURES]


def match_db_error(text):
    for dbms, specific, rx in COMPILED:
        m = rx.search(text)
        if m:
            return dbms, specific, snippet(text, m.start(), 150)
    return None


def _send(ctx, pt, value):
    params = dict(pt.params)
    params[pt.param] = value
    ctx.tick()
    if pt.method == "GET":
        return ctx.http.request("GET", pt.url, params=params)
    return ctx.http.request("POST", pt.url, data=params)


def run(ctx, points, lo, hi, done_offset=0, total=None):
    """Returns number of points processed (for combined progress with the XSS module)."""
    ctx.set_range(lo, hi)
    total = total or max(1, len(points))
    for i, pt in enumerate(points):
        ctx.check_cancel()
        ctx.stage((done_offset + i) / total, f"SQL injection check: {pt.method} {pt.url} [{pt.param}]")
        original = str(pt.params.get(pt.param, "")) or "1"
        base = _send(ctx, pt, original)
        if base.error or match_db_error(base.text):
            continue
        r1 = _send(ctx, pt, original + "'")
        if r1.error:
            continue
        hit = match_db_error(r1.text)
        if not hit:
            continue
        dbms, specific, excerpt = hit
        r2 = _send(ctx, pt, original + "''")
        confirmed = (not r2.error) and not match_db_error(r2.text)
        verb = "did not" if confirmed else "also did"
        ev = (f"Parameter '{pt.param}' ({pt.method} {pt.url}). Appending a single quote produced a {dbms} "
              f"database error that was absent from the baseline response. Escaped quote pair {verb} reproduce "
              f"the error. Excerpt: \"{excerpt}\"")
        ctx.add(RawFinding(
            type="sqli_error", url=pt.url, param=pt.param, evidence=ev,
            status="confirmed" if confirmed else "suspected",
            detail={"dbms": dbms,
                    "confidence_hint": 0.92 if confirmed else (0.6 if specific else 0.4)},
        ))
        ctx.log(f"Possible SQL injection in parameter '{pt.param}' at {pt.url}", "warning")
    return len(points)
