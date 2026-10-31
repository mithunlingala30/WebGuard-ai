"""
Target validation and SSRF protection.

Every URL the scanner touches (the initial target AND every redirect hop) goes through
``validate_target``. It enforces:
  * http/https only, no embedded credentials, sane length
  * approved ports only
  * the host must be an explicitly authorized domain (or a LAB host when LAB_MODE is on)
  * DNS is resolved and EVERY resolved address is checked: loopback, private, link-local,
    cloud-metadata, multicast, reserved and unspecified ranges are blocked
    (loopback/private are only tolerated for named LAB hosts in LAB_MODE)
"""
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

from flask import current_app


class TargetError(Exception):
    """Raised when a URL is invalid, unauthorized or unsafe. Message is user-presentable."""


@dataclass
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    ips: list = field(default_factory=list)
    lab: bool = False

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port == default else f":{self.port}"
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}{port}"


METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("Please enter a website URL.")
    if len(raw) > 2048:
        raise TargetError("The URL is too long.")
    if any(c in raw for c in ("\n", "\r", "\t", " ", "\x00")):
        raise TargetError("The URL contains invalid characters.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
        port = p.port
    except ValueError:
        raise TargetError("The URL is not valid.")
    if p.scheme.lower() not in ("http", "https"):
        raise TargetError("Only http:// and https:// URLs are supported.")
    if not p.hostname:
        raise TargetError("The URL does not contain a valid host name.")
    if p.username or p.password:
        raise TargetError("URLs with embedded credentials are not allowed.")
    try:
        host = p.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise TargetError("The host name is not valid.")
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc += f":{port}"
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", p.query, ""))


def _cfg(key):
    return current_app.config[key]


def is_lab_host(host: str) -> bool:
    return bool(_cfg("LAB_MODE")) and host in _cfg("LAB_HOSTS")


def is_authorized(host: str) -> bool:
    if _cfg("ALLOW_ANY_DOMAIN"):
        return True
    if is_lab_host(host):
        return True
    auth_list = _cfg("AUTHORIZED_DOMAINS")
    if "*" in auth_list or not auth_list:
        return True
    for d in auth_list:
        if host == d or host.endswith("." + d):
            return True
    return False


def _check_ip(ip_text: str, lab: bool) -> None:
    ip = ipaddress.ip_address(ip_text.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if str(ip) in METADATA_IPS:
        raise TargetError("Cloud metadata addresses are blocked.")
    if lab and (ip.is_loopback or ip.is_private) and not ip.is_link_local:
        return
    if ip.is_loopback:
        raise TargetError("Loopback addresses are blocked. (Enable LAB MODE for approved lab hosts.)")
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise TargetError("The target resolves to a blocked address range.")
    if ip.is_private or not ip.is_global:
        raise TargetError("Private and internal network addresses are blocked.")


def resolve_host(host: str, port: int, lab: bool) -> list:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise TargetError("The host name could not be resolved. Check the URL and your connection.")
    ips = []
    for info in infos:
        ip = info[4][0]
        _check_ip(ip, lab)
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise TargetError("The host name did not resolve to any address.")
    return ips


def validate_target(raw_url: str) -> ValidatedTarget:
    url = normalize_url(raw_url)
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)

    if host in _cfg("BLOCKED_HOSTNAMES"):
        raise TargetError("This host name is blocked.")
    if port not in _cfg("ALLOWED_PORTS"):
        raise TargetError(f"Port {port} is not an approved HTTP/HTTPS port.")
    if not is_authorized(host):
        raise TargetError(
            "This domain is not on the authorized targets list. WebGuard AI only scans systems you "
            "are explicitly permitted to test. Ask the administrator to add it to WEBGUARD_AUTHORIZED_DOMAINS."
        )
    lab = is_lab_host(host)
    ips = resolve_host(host, port, lab)
    return ValidatedTarget(url=url, scheme=p.scheme, host=host, port=port, ips=ips, lab=lab)
