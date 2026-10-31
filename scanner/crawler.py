"""Website crawler: pages, internal links, forms, input fields and injection points."""
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".map", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3", ".avi", ".exe", ".dmg", ".doc",
    ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}
TEXT_INPUT_TYPES = {"", "text", "search", "textarea", "tel", "url", "email"}
RISKY_FORM_WORDS = ("delete", "logout", "signout", "remove", "reset", "password", "register", "signup", "checkout", "pay")


@dataclass
class FormInfo:
    page_url: str
    action: str
    method: str
    inputs: list = field(default_factory=list)   # [{"name","type","value"}]


@dataclass
class PageInfo:
    url: str
    status: int
    headers: dict
    set_cookies: list
    content_type: str
    title: str = ""
    snippet: str = ""
    depth: int = 0


@dataclass
class InjectionPoint:
    url: str
    method: str
    params: dict
    param: str
    kind: str      # "url" | "form"


@dataclass
class CrawlResult:
    pages: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    param_urls: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    visited: set = field(default_factory=set)
    home: object = None          # HttpResult of the first page


def _port(p):
    return p.port or (443 if p.scheme == "https" else 80)


def _same_origin(a, b) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return pa.hostname == pb.hostname and _port(pa) == _port(pb)


def _key(url):
    p = urlparse(url)
    names = tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))
    return (p.scheme, p.netloc.lower(), p.path or "/", names)


def _clean(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))


def _extract_forms(soup, page_url):
    forms = []
    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").upper()
        method = "POST" if method == "POST" else "GET"
        action = urljoin(page_url, f.get("action") or page_url)
        inputs = []
        for el in f.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            etype = (el.get("type") or ("textarea" if el.name == "textarea" else "text")).lower()
            if el.name == "select":
                opt = el.find("option")
                value, etype = (opt.get("value", "") if opt else ""), "select"
            elif el.name == "textarea":
                value = el.text or ""
            else:
                value = el.get("value", "")
            if etype in ("checkbox", "radio", "file", "image", "reset"):
                continue
            inputs.append({"name": name, "type": etype, "value": value})
        forms.append(FormInfo(page_url=page_url, action=_clean(action), method=method, inputs=inputs))
    return forms


def crawl(ctx, start_url, max_depth, max_pages, extra_paths=()):
    result = CrawlResult()
    queue = deque([(start_url, 0)])
    for path in extra_paths:
        u = urljoin(start_url, path)
        if _same_origin(u, start_url):
            queue.append((_clean(u), 1))
    seen_param_keys = set()

    while queue and len(result.pages) < max_pages:
        ctx.check_cancel()
        url, depth = queue.popleft()
        k = _key(url)
        if k in result.visited:
            continue
        result.visited.add(k)

        res = ctx.http.get(url)
        ctx.tick()
        if result.home is None:
            result.home = res
        if res.error:
            result.errors.append((url, res.error))
            ctx.log(f"Could not fetch {url}: {res.error}", "warning")
            continue
        if not _same_origin(res.final_url, start_url):
            continue

        ctype = res.content_type
        page = PageInfo(url=res.final_url, status=res.status, headers=dict(res.headers),
                        set_cookies=res.set_cookies, content_type=ctype, depth=depth)
        if res.is_html:
            soup = BeautifulSoup(res.text, "html.parser")
            page.title = (soup.title.string or "").strip()[:150] if soup.title and soup.title.string else ""
            page.snippet = res.text[:30000]
            result.forms.extend(_extract_forms(soup, res.final_url))
            if urlparse(res.final_url).query:
                pk = _key(res.final_url)
                if pk not in seen_param_keys:
                    seen_param_keys.add(pk)
                    result.param_urls.append(res.final_url)
            if depth < max_depth:
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                        continue
                    link = _clean(urljoin(res.final_url, href))
                    lp = urlparse(link)
                    if lp.scheme not in ("http", "https") or not _same_origin(link, start_url):
                        continue
                    if any(lp.path.lower().endswith(e) for e in SKIP_EXT):
                        continue
                    lk = _key(link)
                    if lp.query and lk not in seen_param_keys:
                        seen_param_keys.add(lk)
                        result.param_urls.append(link)
                    if lk not in result.visited:
                        queue.append((link, depth + 1))
        result.pages.append(page)
        ctx.stats["pages"] = len(result.pages)
        est = max(1, min(max_pages, len(result.pages) + len(queue)))
        ctx.stage(len(result.pages) / est, f"Crawling: {url}")
    return result


def build_injection_points(crawl_result, include_post, limit):
    """Turn discovered URL parameters and form fields into a bounded list of test points."""
    points, seen = [], set()

    def add(pt):
        sig = (pt.method, urlparse(pt.url).netloc, urlparse(pt.url).path, pt.param)
        if sig not in seen and len(points) < limit:
            seen.add(sig)
            points.append(pt)

    for url in crawl_result.param_urls:
        p = urlparse(url)
        params = dict(parse_qsl(p.query, keep_blank_values=True))
        base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
        for name in params:
            add(InjectionPoint(base, "GET", params, name, "url"))

    for form in crawl_result.forms:
        if form.method == "POST":
            hint = (form.action + " " + " ".join(i["name"] for i in form.inputs)).lower()
            if not include_post or any(w in hint for w in RISKY_FORM_WORDS):
                continue
        params = {}
        for i in form.inputs:
            val = i["value"]
            if not val and i["type"] in TEXT_INPUT_TYPES:
                val = "test"
            params[i["name"]] = val
        for i in form.inputs:
            if i["type"] in TEXT_INPUT_TYPES:
                add(InjectionPoint(form.action, form.method, params, i["name"], "form"))
    return points
