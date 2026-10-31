"""
SafeHTTP - the ONLY way scanner modules talk to the network.

* revalidates the target on every request and every redirect hop (SSRF protection)
* manual redirect following (max N hops)
* rate limiting, request budget, timeouts, response size cap
* cooperative cancellation
* never raises for network problems: returns an HttpResult with ``error`` set
"""
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
import urllib3
from requests.structures import CaseInsensitiveDict

from services.target_validator import TargetError, validate_target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ScanCancelled(Exception):
    pass


@dataclass
class HttpResult:
    url: str
    final_url: str = ""
    status: int = 0
    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    set_cookies: list = field(default_factory=list)
    text: str = ""
    error: str = ""
    redirects: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error and self.status > 0

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type


class SafeHTTP:
    def __init__(self, cfg, cancel_event=None):
        self.cfg = cfg
        self.cancel = cancel_event
        self.session = requests.Session()
        self.session.headers["User-Agent"] = cfg["USER_AGENT"]
        self.session.headers["Accept"] = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"
        self.verify = True
        self.tls_verification_failed = False
        self.requests_made = 0
        self._last = 0.0

    def get(self, url, params=None):
        return self.request("GET", url, params=params)

    def request(self, method, url, params=None, data=None) -> HttpResult:
        result = HttpResult(url=url, final_url=url)
        current = url
        for hop in range(self.cfg["MAX_REDIRECTS"] + 1):
            if self.cancel is not None and self.cancel.is_set():
                raise ScanCancelled()
            try:
                validate_target(current)
            except TargetError as exc:
                result.error = f"Blocked: {exc}"
                return result
            if self.requests_made >= self.cfg["MAX_REQUESTS_PER_SCAN"]:
                result.error = "Request budget for this scan was reached."
                return result
            wait = self.cfg["REQUEST_DELAY"] - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.requests_made += 1
            try:
                resp = self._send(method, current, params if hop == 0 else None, data if hop == 0 else None)
            except requests.exceptions.SSLError:
                if self.verify:
                    # Certificate problem: record it (TLS checker reports it) and continue unverified.
                    self.verify = False
                    self.tls_verification_failed = True
                    self.requests_made -= 1
                    try:
                        resp = self._send(method, current, params if hop == 0 else None, data if hop == 0 else None)
                    except requests.exceptions.RequestException as exc:
                        result.error = self._friendly(exc)
                        return result
                else:
                    result.error = "TLS handshake failed."
                    return result
            except requests.exceptions.RequestException as exc:
                result.error = self._friendly(exc)
                return result

            result.final_url = current
            result.status = resp.status_code
            result.headers = CaseInsensitiveDict(resp.headers)
            getter = getattr(resp.raw.headers, "getlist", None)
            result.set_cookies = list(getter("Set-Cookie")) if getter else []
            result.text = self._read(resp)
            resp.close()

            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                nxt = urljoin(current, resp.headers["Location"])
                result.redirects.append(nxt)
                current = nxt
                if resp.status_code == 303 or (resp.status_code in (301, 302) and method == "POST"):
                    method, data = "GET", None
                continue
            return result
        result.error = "Too many redirects."
        return result

    def _send(self, method, url, params, data):
        return self.session.request(
            method, url, params=params, data=data, timeout=self.cfg["REQUEST_TIMEOUT"],
            allow_redirects=False, stream=True, verify=self.verify,
        )

    def _read(self, resp) -> str:
        limit = self.cfg["MAX_RESPONSE_BYTES"]
        chunks, size = [], 0
        try:
            for chunk in resp.iter_content(chunk_size=16384):
                chunks.append(chunk)
                size += len(chunk)
                if size >= limit:
                    break
        except requests.exceptions.RequestException:
            pass
        raw = b"".join(chunks)[:limit]
        return raw.decode(resp.encoding or "utf-8", errors="replace")

    @staticmethod
    def _friendly(exc) -> str:
        if isinstance(exc, requests.exceptions.ConnectTimeout):
            return "Connection timed out."
        if isinstance(exc, requests.exceptions.ReadTimeout):
            return "The server took too long to respond."
        if isinstance(exc, requests.exceptions.ConnectionError):
            return "Could not connect to the website."
        if isinstance(exc, requests.exceptions.TooManyRedirects):
            return "Too many redirects."
        return "The request failed."
