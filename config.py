"""
WebGuard AI - central configuration.

Everything security-relevant is configurable through environment variables so the
defaults stay SAFE: only explicitly authorized domains can be scanned, and loopback /
private networks are blocked unless LAB MODE is switched on for named lab hosts.

Environment variables
---------------------
WEBGUARD_SECRET_KEY          Flask secret key (auto-generated into instance/secret.key if unset)
WEBGUARD_AUTHORIZED_DOMAINS  Comma separated list of domains you are allowed to test
WEBGUARD_LAB_MODE            "1" lets the scanner reach the LAB hosts below (Juice Shop, WebGoat, ...)
WEBGUARD_LAB_HOSTS           Comma separated lab host names (default: localhost,127.0.0.1)
WEBGUARD_ALLOWED_PORTS       Comma separated list of approved ports
WEBGUARD_HOST / WEBGUARD_PORT  Where WebGuard itself listens (default 127.0.0.1:5000)
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
REPORTS_DIR = BASE_DIR / "reports"
INSTANCE_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


def _env_list(name, default):
    raw = os.environ.get(name)
    items = raw.split(",") if raw is not None else default
    return [i.strip().lower() for i in items if i.strip()]


def _env_bool(name, default=False):
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


def _secret_key():
    env = os.environ.get("WEBGUARD_SECRET_KEY")
    if env:
        return env
    key_file = INSTANCE_DIR / "secret.key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    return key


class Config:
    APP_NAME = "WebGuard AI"
    SECRET_KEY = _secret_key()
    HOST = os.environ.get("WEBGUARD_HOST", "127.0.0.1")
    PORT = int(os.environ.get("WEBGUARD_PORT", "5000"))

    # ---- Database -------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + (INSTANCE_DIR / "webguard.db").as_posix()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30, "check_same_thread": False}}

    # ---- Sessions (expire after 30 min of inactivity) ---------------------
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("WEBGUARD_SECURE_COOKIES", False)  # enable behind HTTPS
    REMEMBER_COOKIE_HTTPONLY = True

    # ---- Scan authorization / SSRF protection ---------------------------
    # ALLOW_ANY_DOMAIN allows scanning any public website domain.
    ALLOW_ANY_DOMAIN = _env_bool("WEBGUARD_ALLOW_ANY_DOMAIN", True)
    # Intentionally vulnerable public training sites and allow-list defaults.
    AUTHORIZED_DOMAINS = _env_list(
        "WEBGUARD_AUTHORIZED_DOMAINS", ["*"]
    )
    LAB_MODE = _env_bool("WEBGUARD_LAB_MODE", False)
    LAB_HOSTS = _env_list("WEBGUARD_LAB_HOSTS", ["localhost", "127.0.0.1"])
    ALLOWED_PORTS = [
        int(p) for p in _env_list(
            "WEBGUARD_ALLOWED_PORTS", ["80", "443", "3000", "5001", "8000", "8080", "8081", "8443", "9090"]
        )
    ]
    BLOCKED_HOSTNAMES = ["metadata.google.internal", "metadata", "instance-data"]

    # ---- Scan limits -------------------------------------------------------
    REQUEST_TIMEOUT = (5, 12)          # connect, read (seconds)
    REQUEST_DELAY = 0.15               # seconds between requests (rate limit)
    MAX_REDIRECTS = 5
    MAX_RESPONSE_BYTES = 1_000_000
    MAX_REQUESTS_PER_SCAN = 500
    MAX_CONCURRENT_SCANS = 2           # worker threads
    MAX_ACTIVE_SCANS_PER_USER = 2
    USER_AGENT = "WebGuardAI/1.0 (authorized security assessment; academic project)"

    # ---- Reports -------------------------------------------------------------
    REPORTS_DIR = str(REPORTS_DIR)

    # ---- Brute-force protection for login ------------------------------------
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_SECONDS = 300
