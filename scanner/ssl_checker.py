"""HTTPS availability, certificate validity/expiry/hostname and basic TLS connection info."""
import socket
import ssl
from datetime import datetime, timezone

from scanner.base import RawFinding
from services.target_validator import TargetError, validate_target


def _connect(ip, host, port, verify):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version(), tls.cipher()


def run(ctx, home):
    t, site = ctx.target, ctx.site_url()
    ctx.tick()

    if t.scheme == "http":
        port = 443
        try:
            vt = validate_target(f"https://{t.host}/")
        except TargetError:
            vt = None
        available = False
        if vt:
            try:
                _connect(vt.ips[0], t.host, port, verify=False)
                available = True
            except (OSError, ssl.SSLError):
                available = False
        if not available:
            ctx.add(RawFinding("no_https", site,
                               f"{t.host} is served over plain HTTP and no TLS service answered on port 443.",
                               "observed", detail={"confidence_hint": 0.92}))
            ctx.log("HTTPS is not available on this site.", "warning")
            return
        if home is not None and home.ok and home.final_url.startswith("http://"):
            ctx.add(RawFinding("https_not_enforced", site,
                               "HTTPS is available but HTTP requests are not redirected to HTTPS.",
                               "observed", detail={"confidence_hint": 0.85}))
        host_port = 443
    else:
        host_port = t.port

    ip = t.ips[0]
    try:
        cert, version, cipher = _connect(ip, t.host, host_port, verify=True)
    except ssl.SSLCertVerificationError as exc:
        msg = (getattr(exc, "verify_message", "") or str(exc)).lower()
        if "expired" in msg:
            key = "ssl_expired"
        elif "mismatch" in msg:
            key = "ssl_hostname_mismatch"
        else:
            key = "ssl_invalid_cert"
        ctx.add(RawFinding(key, site, f"TLS certificate verification failed for {t.host}:{host_port} - "
                                      f"{getattr(exc, 'verify_message', None) or 'verification error'}.",
                           "confirmed", detail={"confidence_hint": 0.95}))
        ctx.log(f"TLS certificate problem: {getattr(exc, 'verify_message', 'verification failed')}", "warning")
        return
    except (OSError, ssl.SSLError) as exc:
        ctx.log(f"TLS handshake with {t.host}:{host_port} failed: {exc.__class__.__name__}", "warning")
        return

    not_after = ssl.cert_time_to_seconds(cert["notAfter"]) if cert and cert.get("notAfter") else None
    days = None
    if not_after:
        days = int((datetime.fromtimestamp(not_after, timezone.utc) - datetime.now(timezone.utc)).days)
    issuer = dict(x[0] for x in cert.get("issuer", ())) if cert else {}
    ctx.log(f"TLS: {version}, cipher {cipher[0] if cipher else 'n/a'}, certificate issuer "
            f"{issuer.get('organizationName', issuer.get('commonName', 'unknown'))}, "
            f"{'expires in %d days' % days if days is not None else 'expiry unknown'}.", "success")
    if days is not None and 0 <= days < 30:
        ctx.add(RawFinding("ssl_expiring", site, f"The TLS certificate expires in {days} days.", "observed",
                           detail={"confidence_hint": 0.95}))
    if version in ("TLSv1", "TLSv1.1"):
        ctx.add(RawFinding("ssl_weak_protocol", site, f"The server negotiated the deprecated protocol {version}.",
                           "confirmed", detail={"confidence_hint": 0.95}))
