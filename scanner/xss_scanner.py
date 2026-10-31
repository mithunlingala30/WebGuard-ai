"""
Safe reflected-XSS check. We submit a harmless unique marker that contains HTML-special
characters (< > " ') but NO script, and inspect HOW it is reflected. Nothing is executed.

  confirmed = marker reflected with raw '<' and '>' (HTML context not encoded)
  suspected = '<' encoded, but raw quote reflected (attribute breakout) or marker inside <script>
"""
import re
import secrets

from scanner.base import RawFinding, snippet


def _send(ctx, pt, value):
    params = dict(pt.params)
    params[pt.param] = value
    ctx.tick()
    if pt.method == "GET":
        return ctx.http.request("GET", pt.url, params=params)
    return ctx.http.request("POST", pt.url, data=params)


def run(ctx, points, lo, hi, done_offset=0, total=None):
    ctx.set_range(lo, hi)
    total = total or max(1, len(points))
    for i, pt in enumerate(points):
        ctx.check_cancel()
        ctx.stage((done_offset + i) / total, f"XSS reflection check: {pt.method} {pt.url} [{pt.param}]")
        marker = "wg" + secrets.token_hex(4)
        probe = f'{marker}<wgx>"\''
        res = _send(ctx, pt, probe)
        if res.error or not res.is_html or marker not in res.text:
            continue
        body = res.text
        idx = body.index(marker)
        if probe in body:
            status, hint = "confirmed", 0.9
            how = "reflected with raw < > \" ' characters (no output encoding)"
        elif re.search(re.escape(marker) + r"(&lt;|&#60;|&#x3c;)wgx(&gt;|&#62;|&#x3e;)\"", body, re.I):
            status, hint = "suspected", 0.55
            how = "angle brackets encoded but a raw double quote is reflected (possible attribute breakout)"
        elif re.search(r"<script[^>]*>[^<]{0,2000}" + re.escape(marker), body, re.I):
            status, hint = "suspected", 0.45
            how = "reflected inside a <script> block"
        else:
            continue
        ev = (f"Parameter '{pt.param}' ({pt.method} {pt.url}). Harmless marker '{marker}' was {how}. "
              f"Context: \"{snippet(body, idx, 160)}\"")
        ctx.add(RawFinding(type="xss_reflected", url=pt.url, param=pt.param, evidence=ev, status=status,
                           detail={"confidence_hint": hint}))
        ctx.log(f"Reflected input without proper encoding in '{pt.param}' at {pt.url}", "warning")
    return len(points)
