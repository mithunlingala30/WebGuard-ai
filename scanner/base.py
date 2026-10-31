"""Shared scanner data structures."""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from services.http_client import ScanCancelled


@dataclass
class RawFinding:
    """A raw observation from a scanner module (before AI analysis)."""
    type: str                      # key into ai_engine.recommendations.KNOWLEDGE_BASE
    url: str
    evidence: str
    status: str = "observed"       # confirmed | suspected | observed
    param: str = ""
    detail: dict = field(default_factory=dict)   # e.g. {"confidence_hint": 0.6, "is_session": True}


class ScanContext:
    """Carries the HTTP client, options, collected findings and progress callbacks."""

    def __init__(self, http, target, profile, options, cancel_event, on_progress, on_log):
        self.http = http
        self.target = target
        self.profile = profile
        self.options = options
        self.cancel = cancel_event
        self.findings: list[RawFinding] = []
        self.stats = {"pages": 0, "tests": 0}
        self._on_progress = on_progress
        self._on_log = on_log
        self._range = (0, 100)

    def check_cancel(self):
        if self.cancel.is_set():
            raise ScanCancelled()

    def add(self, finding: RawFinding):
        self.findings.append(finding)

    def tick(self, n=1):
        self.stats["tests"] += n

    def log(self, message, level="info"):
        self._on_log(message, level)

    def set_range(self, lo, hi):
        self._range = (lo, hi)

    def stage(self, frac, activity):
        """Report progress inside the current range; frac is real completed work (0..1)."""
        lo, hi = self._range
        frac = max(0.0, min(1.0, frac))
        self._on_progress(round(lo + (hi - lo) * frac), activity)

    def site_url(self) -> str:
        return self.target.origin + "/"


def snippet(text: str, idx: int = 0, width: int = 160) -> str:
    """Single-line, length-limited excerpt around idx (evidence is untrusted content)."""
    start = max(0, idx - width // 4)
    s = re.sub(r"\s+", " ", text[start:start + width]).strip()
    return s


def url_host_path(url: str) -> str:
    p = urlparse(url)
    return f"{p.netloc}{p.path or '/'}"
