"""
Information disclosure checks using a small, restricted, NON-destructive path list.

Each probe needs a content SIGNATURE (not just HTTP 200) so single-page-app catch-all routes
do not create false positives. Response bodies are inspected in memory and never stored.
"""
import re

from scanner.base import RawFinding

ENV_RX = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=", re.M)

FILE_CHECKS = [
    ("/.git/HEAD", "git_exposed", "contains a Git 'ref:' pointer", lambda b: b.lstrip().startswith("ref:")),
    ("/.git/config", "git_exposed", "contains a Git [core] section", lambda b: "[core]" in b),
    ("/.env", "env_file_exposed", "looks like KEY=VALUE environment configuration",
     lambda b: len(ENV_RX.findall(b)) >= 2 and "<html" not in b.lower()[:500]),
    ("/web.config", "config_file_exposed", "contains an ASP.NET <configuration> element", lambda b: "<configuration" in b.lower()),
    ("/WEB-INF/web.xml", "config_file_exposed", "contains a <web-app> descriptor", lambda b: "<web-app" in b.lower()),
    ("/.htaccess", "config_file_exposed", "contains Apache directives", lambda b: bool(re.search(r"RewriteEngine|AuthType|Require ", b))),
    ("/phpinfo.php", "phpinfo_exposed", "renders the PHP configuration page", lambda b: "phpinfo()" in b or "PHP Version" in b and "<table" in b),
    ("/server-status", "server_status_exposed", "shows the Apache status page", lambda b: "Apache Server Status" in b),
    ("/actuator/env", "actuator_exposed", "returns Spring Boot environment properties", lambda b: "propertySources" in b),
    ("/.DS_Store", "ds_store_exposed", "starts with the macOS .DS_Store signature", lambda b: "Bud1" in b[:16]),
]
DIR_PATHS = ["/ftp/", "/uploads/", "/backup/", "/backups/", "/logs/", "/files/", "/static/"]
DIR_RX = re.compile(r"<title>\s*index of /|<h1>\s*index of|parent directory|directory listing (for|of)|listing directory", re.I)


def run(ctx, crawl):
    base = ctx.target.origin
    home = crawl.home
    site = ctx.site_url()
    total = len(FILE_CHECKS) + len(DIR_PATHS)

    # --- Server banner disclosure (from homepage headers) ---
    if home is not None and home.ok:
        ctx.tick()
        server = home.headers.get("Server", "")
        if re.search(r"\d+\.\d+", server):
            ctx.add(RawFinding("server_version_disclosure", site, f"Server header discloses: \"{server}\".",
                               "observed", detail={"confidence_hint": 0.95}))
        for hdr in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            val = home.headers.get(hdr)
            if val:
                ctx.add(RawFinding("x_powered_by_disclosure", site, f"{hdr} header discloses: \"{val}\".",
                                   "observed", hdr, {"confidence_hint": 0.95}))

    # --- Directory listing on crawled pages ---
    for p in crawl.pages:
        if DIR_RX.search(p.snippet or ""):
            ctx.add(RawFinding("directory_listing", p.url, f"Crawled page {p.url} renders a directory index.",
                               "confirmed", detail={"confidence_hint": 0.9}))

    # --- Restricted sensitive path probes ---
    done = 0
    for path, key, sig, test in FILE_CHECKS:
        ctx.check_cancel()
        ctx.stage(done / total, f"Checking exposed path {path}")
        res = ctx.http.get(base + path)
        ctx.tick()
        done += 1
        if res.ok and res.status == 200 and test(res.text):
            ctx.add(RawFinding(key, base + path, f"GET {path} returned HTTP 200 and {sig}. Content was not stored.",
                               "confirmed", detail={"confidence_hint": 0.93}))
            ctx.log(f"Sensitive path publicly accessible: {path}", "warning")

    for path in DIR_PATHS:
        ctx.check_cancel()
        ctx.stage(done / total, f"Checking directory listing {path}")
        res = ctx.http.get(base + path)
        ctx.tick()
        done += 1
        if res.ok and res.status == 200 and DIR_RX.search(res.text[:20000]):
            if any(f.type == "directory_listing" and f.url == base + path for f in ctx.findings):
                continue
            ctx.add(RawFinding("directory_listing", base + path,
                               f"GET {path} returned HTTP 200 with a directory index page.",
                               "confirmed", detail={"confidence_hint": 0.9}))
            ctx.log(f"Directory listing exposed at {path}", "warning")
