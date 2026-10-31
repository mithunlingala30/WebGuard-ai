"""Cookie attribute checks: Secure, HttpOnly, SameSite."""
import re

from scanner.base import RawFinding

SESSION_RX = re.compile(r"(sess|sid|token|auth|jwt|login|phpsessid|jsessionid|asp\.net|connect\.sid|csrf)", re.I)


def parse_set_cookie(header: str) -> dict:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", "").lower()}


def run(ctx, crawl):
    seen = {}
    pages = [(p.url, p.set_cookies) for p in crawl.pages]
    if crawl.home is not None and crawl.home.set_cookies:
        pages.insert(0, (crawl.home.final_url, crawl.home.set_cookies))
    for url, headers in pages:
        for raw in headers:
            c = parse_set_cookie(raw)
            if c["name"] and c["name"] not in seen:
                seen[c["name"]] = (url, c)
    https = ctx.target.scheme == "https"
    if not seen:
        ctx.log("No cookies were set by the pages that were crawled.")
    for name, (url, c) in seen.items():
        ctx.tick(3)
        is_session = bool(SESSION_RX.search(name))
        site = ctx.site_url()
        base = f"Cookie '{name}' set by {url}"
        detail = {"is_session": is_session, "confidence_hint": 0.95}
        if https and not c["secure"]:
            ctx.add(RawFinding("cookie_missing_secure", site, f"{base} has no Secure attribute.", "observed", name, dict(detail)))
        if not c["httponly"]:
            ctx.add(RawFinding("cookie_missing_httponly", site, f"{base} has no HttpOnly attribute.", "observed", name, dict(detail)))
        if not c["samesite"]:
            ctx.add(RawFinding("cookie_missing_samesite", site, f"{base} has no SameSite attribute.", "observed", name, dict(detail)))
        elif c["samesite"] == "none" and not c["secure"]:
            ctx.add(RawFinding("cookie_missing_samesite", site, f"{base} uses SameSite=None without Secure.", "observed", name, dict(detail)))
