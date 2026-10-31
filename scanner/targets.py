"""Builds the list of injectable parameters (query strings and forms) for the active checkers."""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from scanner.crawler import Page

TOKEN_NAME = re.compile(r"csrf|xsrf|token|nonce|authenticity|viewstate|__|captcha|honeypot", re.I)
RISKY_ACTION = re.compile(r"log-?out|sign-?out|delete|remove|destroy|purchase|checkout|payment|"
                          r"transfer|reset|unsubscribe|install|upgrade", re.I)
TESTABLE_TYPES = {"text", "search", "email", "url", "tel", "number", "textarea", "hidden", "", "select"}
DEFAULTS_BY_TYPE = {"email": "test@example.com", "url": "http://example.com", "number": "1", "tel": "5550100"}


@dataclass
class TestTarget:
    method: str                 # GET | POST
    url: str                    # action URL without query string
    params: Dict[str, str]      # all parameters with benign default values
    test_params: List[str]      # parameters that will be probed
    source: str                 # "url" | "form"
    page_url: str
    has_password: bool = False

    @property
    def label(self) -> str:
        return f"{self.method} {urlsplit(self.url).path or '/'}"


def build_test_targets(pages: List[Page], profile: dict) -> List[TestTarget]:
    targets: List[TestTarget] = []
    seen = set()
    limit = profile.get("max_active_targets", 0)
    if limit <= 0:
        return targets

    def add(t: TestTarget):
        key = (t.method, t.url, tuple(sorted(t.params)))
        if key in seen or not t.test_params:
            return
        seen.add(key)
        targets.append(t)

    for page in pages:
        if page.status >= 400 or not page.is_html:
            continue
        # 1) parameters already present in the page URL
        parts = urlsplit(page.url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        if qs:
            params = {k: v for k, v in qs}
            names = [k for k in params if not TOKEN_NAME.search(k)]
            base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            add(TestTarget("GET", base, params, names, "url", page.url))
        # 2) forms
        for form in page.forms:
            if form.method not in ("GET", "POST"):
                continue
            if form.method == "POST" and not profile.get("test_post_forms"):
                continue
            if RISKY_ACTION.search(urlsplit(form.action).path):
                continue
            params: Dict[str, str] = {}
            test_params: List[str] = []
            for inp in form.inputs:
                value = inp.value or DEFAULTS_BY_TYPE.get(inp.type, "test")
                if inp.type in ("submit", "button", "image", "reset"):
                    if inp.value:
                        params[inp.name] = inp.value
                    continue
                if inp.type in ("checkbox", "radio"):
                    if inp.value:
                        params[inp.name] = inp.value
                    continue
                if inp.type == "file":
                    continue
                params[inp.name] = value
                if inp.type == "password":
                    continue                       # never probe credentials fields
                if inp.type in TESTABLE_TYPES and not TOKEN_NAME.search(inp.name):
                    test_params.append(inp.name)
            fparts = urlsplit(form.action)
            base = urlunsplit((fparts.scheme, fparts.netloc, fparts.path, "", ""))
            for k, v in parse_qsl(fparts.query, keep_blank_values=True):
                params.setdefault(k, v)
            add(TestTarget(form.method, base, params, test_params, "form", page.url, form.has_password))
        if len(targets) >= limit:
            break
    return targets[:limit]


def send_test_request(ctx, target: TestTarget, params: Dict[str, str]):
    if target.method == "GET":
        return ctx.client.try_request("GET", target.url, params=params)
    return ctx.client.try_request("POST", target.url, data=params)


def similarity(a: str, b: str) -> float:
    """0..1 similarity of two response bodies (first 3000 characters)."""
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000], autojunk=False).ratio()


def clean_snippet(text: str, limit: int = 160) -> str:
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]
