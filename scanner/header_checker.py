"""HTTP security header checks: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy."""
import re

from scanner.base import RawFinding


def run(ctx, home):
    if home is None or not home.ok:
        ctx.log("Security header check skipped: no response from the homepage.", "warning")
        return
    h, site, https = home.headers, ctx.site_url(), ctx.target.scheme == "https"
    where = f"Response from {home.final_url} (HTTP {home.status})"

    def add(t, ev, hint=0.9, status="observed"):
        ctx.add(RawFinding(type=t, url=site, evidence=ev, status=status, detail={"confidence_hint": hint}))

    # Content-Security-Policy
    csp = h.get("Content-Security-Policy")
    ctx.tick()
    if not csp:
        add("missing_csp", f"{where}: the Content-Security-Policy header is absent.")
    else:
        issues = []
        if re.search(r"script-src[^;]*'unsafe-inline'", csp) or (
                "script-src" not in csp and re.search(r"default-src[^;]*'unsafe-inline'", csp)):
            issues.append("allows 'unsafe-inline' scripts")
        if "'unsafe-eval'" in csp:
            issues.append("allows 'unsafe-eval'")
        if re.search(r"(script-src|default-src)[^;]*(\s|^)\*(\s|;|$)", csp):
            issues.append("uses a wildcard (*) source")
        if issues:
            add("weak_csp", f"{where}: CSP \"{csp[:200]}\" " + "; ".join(issues) + ".")

    # HSTS (only meaningful over HTTPS)
    ctx.tick()
    hsts = h.get("Strict-Transport-Security")
    if https:
        if not hsts:
            add("missing_hsts", f"{where}: the Strict-Transport-Security header is absent on an HTTPS site.")
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                add("weak_hsts", f"{where}: HSTS value \"{hsts}\" has a max-age below 180 days.", 0.85)

    # X-Content-Type-Options
    ctx.tick()
    xcto = h.get("X-Content-Type-Options", "")
    if "nosniff" not in xcto.lower():
        add("missing_xcto", f"{where}: X-Content-Type-Options is " + ("set to an unexpected value." if xcto else "absent."))

    # X-Frame-Options / frame-ancestors
    ctx.tick()
    if not h.get("X-Frame-Options") and not (csp and "frame-ancestors" in csp):
        add("missing_xfo", f"{where}: neither X-Frame-Options nor CSP frame-ancestors is set.")

    # Referrer-Policy
    ctx.tick()
    rp = h.get("Referrer-Policy")
    if not rp:
        add("missing_referrer_policy", f"{where}: the Referrer-Policy header is absent.")
    elif rp.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
        add("weak_referrer_policy", f"{where}: Referrer-Policy \"{rp}\" may leak full URLs to other sites.", 0.8)
