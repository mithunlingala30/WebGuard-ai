"""Optional OWASP ZAP integration (ZAP REST API, daemon mode).

Disabled by default. Enable with WEBGUARD_ZAP_ENABLED=true and run ZAP separately, e.g.

    zap.bat -daemon -port 8090 -config api.key=changeme

Only the "full" scan profile uses ZAP, and only for a target that already passed WebGuard's
authorisation / SSRF validation. Note: ZAP's active scanner is far more intrusive than WebGuard's
own checks and does not go through WebGuard's rate limiter - use it only on lab systems you own.
If ZAP is unreachable the scan simply continues without it.
"""
from __future__ import annotations

import re
import time
from typing import List

import requests

from scanner.base import RawFinding, ScanContext
from services.http_client import ScanCancelled

_RISK_TO_CONFIDENCE = {"High": "High", "Medium": "Medium", "Low": "Low"}
_TAG_RE = re.compile(r"<[^>]+>")


class ZapError(Exception):
    pass


def is_available(ctx: ScanContext) -> bool:
    cfg = ctx.config
    return bool(cfg.get("ZAP_ENABLED") and ctx.profile.get("zap") and cfg.get("ZAP_API_URL"))


def _call(cfg, path: str, **params):
    params["apikey"] = cfg.get("ZAP_API_KEY", "")
    try:
        r = requests.get(cfg["ZAP_API_URL"].rstrip("/") + path, params=params, timeout=15)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as exc:
        raise ZapError(f"ZAP API call failed: {exc.__class__.__name__}")


def _wait(ctx: ScanContext, status_path: str, scan_id: str, deadline: float, label: str,
          lo: int, hi: int) -> None:
    while True:
        ctx.check_cancel()
        status = int(_call(ctx.config, status_path, scanId=scan_id).get("status", 0))
        ctx.reporter.sub(lo + int((hi - lo) * status / 100), f"OWASP ZAP {label}: {status}%")
        if status >= 100:
            return
        if time.time() > deadline:
            ctx.note(f"OWASP ZAP {label} stopped after the configured time limit.")
            return
        time.sleep(2)


def run(ctx: ScanContext) -> List[RawFinding]:
    cfg = ctx.config
    findings: List[RawFinding] = []
    target = ctx.target.url
    deadline = time.time() + int(cfg.get("ZAP_MAX_SECONDS", 600))
    try:
        version = _call(cfg, "/JSON/core/view/version/").get("version", "unknown")
        ctx.log(f"OWASP ZAP {version} reachable; starting spider and active scan.")
        spider = _call(cfg, "/JSON/spider/action/scan/", url=target, recurse="true").get("scan")
        _wait(ctx, "/JSON/spider/view/status/", spider, deadline, "spider", 70, 76)
        active = _call(cfg, "/JSON/ascan/action/scan/", url=target, recurse="true").get("scan")
        try:
            _wait(ctx, "/JSON/ascan/view/status/", active, deadline, "active scan", 76, 84)
        except ScanCancelled:
            _call(cfg, "/JSON/ascan/action/stop/", scanId=active)
            raise
        else:
            _call(cfg, "/JSON/ascan/action/stop/", scanId=active)
        alerts = _call(cfg, "/JSON/core/view/alerts/", baseurl=target, start=0, count=300).get("alerts", [])
    except ZapError as exc:
        ctx.note(f"OWASP ZAP was enabled but could not be used ({exc}). The scan continued without it.")
        return findings

    for alert in alerts:
        risk = alert.get("risk", "Informational")
        if risk not in ("High", "Medium", "Low"):
            continue                              # informational alerts are not vulnerabilities
        if alert.get("confidence") == "False Positive":
            continue
        name = alert.get("alert") or alert.get("name") or "ZAP alert"
        evidence = (f"OWASP ZAP alert '{name}' (plugin {alert.get('pluginId')}, risk {risk}, confidence "
                    f"{alert.get('confidence')}). Parameter: {alert.get('param') or 'n/a'}. "
                    f"Evidence: {(alert.get('evidence') or 'n/a')[:200]}")
        findings.append(RawFinding(
            "zap_alert", f"{name} (OWASP ZAP)", alert.get("url") or target, evidence,
            confidence=_RISK_TO_CONFIDENCE.get(alert.get("confidence", ""), "Medium"),
            status="Suspected", parameter=alert.get("param") or None, source="owasp-zap",
            signals={"zap_risk": risk, "cwe": alert.get("cweid"), "alert": name,
                     "description": _TAG_RE.sub("", alert.get("description", ""))[:800],
                     "solution": _TAG_RE.sub("", alert.get("solution", ""))[:800]}))
    ctx.tick(len(alerts))
    ctx.log(f"OWASP ZAP reported {len(findings)} alert(s) of low risk or above.")
    return findings
