"""
Knowledge base: one entry per finding type produced by the scanner modules.

``severity`` maps the evidence status (confirmed / suspected / observed) to a base severity.
Remediation text is authored guidance, keyed by the REAL finding type - it is only ever attached
to findings the scanners actually produced.
"""

A02 = "A02:2021 - Cryptographic Failures"
A03 = "A03:2021 - Injection"
A05 = "A05:2021 - Security Misconfiguration"
A06 = "A06:2021 - Vulnerable and Outdated Components"

KNOWLEDGE_BASE = {
    "sqli_error": dict(
        name="SQL Injection (error-based)", category="SQL Injection", owasp=A03, exploitability=0.9,
        severity={"confirmed": "Critical", "suspected": "High"},
        description="User-controlled input is concatenated into a database query. A stray quote caused the "
                    "application to return a database error, which indicates the input reaches the SQL parser.",
        impact="An attacker may read, modify or delete database content, bypass authentication and in some "
               "configurations execute commands on the server.",
        recommendation="Use parameterized queries / prepared statements or an ORM for all database access, "
                       "validate input against an allow-list, disable verbose database errors in production and "
                       "run the application with a least-privilege database account."),
    "xss_reflected": dict(
        name="Reflected Cross-Site Scripting (XSS)", category="Cross-Site Scripting", owasp=A03, exploitability=0.8,
        severity={"confirmed": "High", "suspected": "Medium"},
        description="Input supplied in a request is reflected in the HTML response without proper output encoding.",
        impact="An attacker can craft a link that runs script in a victim's browser, stealing sessions or "
               "performing actions as the user.",
        recommendation="Apply context-aware output encoding for every reflected value, validate input, and add a "
                       "restrictive Content-Security-Policy as defence in depth."),
    "missing_csp": dict(
        name="Missing Content-Security-Policy", category="Security Headers", owasp=A05, exploitability=0.4,
        severity={"observed": "Medium"},
        description="The website does not define a Content-Security-Policy response header.",
        impact="Certain client-side injection risks (such as XSS and data injection) may be increased.",
        recommendation="Configure an appropriate Content-Security-Policy header on the web server, starting with "
                       "default-src 'self' and allowing only the sources the site needs."),
    "weak_csp": dict(
        name="Weak Content-Security-Policy", category="Security Headers", owasp=A05, exploitability=0.3,
        severity={"observed": "Low"},
        description="A Content-Security-Policy is present but contains directives that weaken its protection.",
        impact="The policy may not stop script injection because unsafe sources are permitted.",
        recommendation="Remove 'unsafe-inline', 'unsafe-eval' and wildcard sources; use nonces or hashes for scripts."),
    "missing_hsts": dict(
        name="Missing Strict-Transport-Security (HSTS)", category="Security Headers", owasp=A02, exploitability=0.3,
        severity={"observed": "Medium"},
        description="The HTTPS site does not send the Strict-Transport-Security header.",
        impact="Users can be downgraded to HTTP by a network attacker (SSL stripping) on first or later visits.",
        recommendation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere."),
    "weak_hsts": dict(
        name="Weak Strict-Transport-Security configuration", category="Security Headers", owasp=A02, exploitability=0.2,
        severity={"observed": "Low"},
        description="HSTS is enabled but with a short max-age.",
        impact="Protection against protocol downgrade expires quickly.",
        recommendation="Increase max-age to at least 15552000 seconds (preferably 31536000)."),
    "missing_xcto": dict(
        name="Missing X-Content-Type-Options", category="Security Headers", owasp=A05, exploitability=0.2,
        severity={"observed": "Low"},
        description="The X-Content-Type-Options: nosniff header is not set.",
        impact="Browsers may MIME-sniff responses and execute content as an unintended type.",
        recommendation="Add the response header X-Content-Type-Options: nosniff."),
    "missing_xfo": dict(
        name="Missing clickjacking protection (X-Frame-Options)", category="Security Headers", owasp=A05, exploitability=0.4,
        severity={"observed": "Medium"},
        description="Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
        impact="The site can be embedded in a hostile page, enabling clickjacking attacks.",
        recommendation="Send X-Frame-Options: DENY (or SAMEORIGIN) or Content-Security-Policy: frame-ancestors 'self'."),
    "missing_referrer_policy": dict(
        name="Missing Referrer-Policy", category="Security Headers", owasp=A05, exploitability=0.1,
        severity={"observed": "Low"},
        description="The website does not define a Referrer-Policy response header.",
        impact="Full URLs, which may include sensitive tokens, can leak to third-party sites.",
        recommendation="Add Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
    "weak_referrer_policy": dict(
        name="Weak Referrer-Policy", category="Security Headers", owasp=A05, exploitability=0.1,
        severity={"observed": "Low"},
        description="The Referrer-Policy value may disclose full URLs to other origins.",
        impact="Sensitive URL data may leak to external sites.",
        recommendation="Use strict-origin-when-cross-origin, same-origin or no-referrer."),
    "cookie_missing_secure": dict(
        name="Cookie without Secure flag", category="Cookie Security", owasp=A02, exploitability=0.4,
        severity={"observed": "Low"},
        description="A cookie set over HTTPS is missing the Secure attribute.",
        impact="The cookie may be transmitted over unencrypted connections and intercepted.",
        recommendation="Set the Secure attribute on all cookies, especially session and authentication cookies."),
    "cookie_missing_httponly": dict(
        name="Cookie without HttpOnly flag", category="Cookie Security", owasp=A05, exploitability=0.4,
        severity={"observed": "Low"},
        description="A cookie is missing the HttpOnly attribute.",
        impact="Client-side script (for example injected via XSS) can read the cookie value.",
        recommendation="Set the HttpOnly attribute on cookies that do not need to be read by JavaScript."),
    "cookie_missing_samesite": dict(
        name="Cookie without SameSite attribute", category="Cookie Security", owasp=A05, exploitability=0.3,
        severity={"observed": "Low"},
        description="A cookie has no (or an unsafe) SameSite attribute.",
        impact="The cookie may be sent on cross-site requests, increasing cross-site request forgery risk.",
        recommendation="Set SameSite=Lax or SameSite=Strict (SameSite=None requires the Secure attribute)."),
    "no_https": dict(
        name="HTTPS not available", category="TLS/SSL", owasp=A02, exploitability=0.6,
        severity={"observed": "High"},
        description="The website is served over plain HTTP and does not offer TLS on port 443.",
        impact="All traffic, including credentials and session cookies, can be read or modified in transit.",
        recommendation="Obtain a TLS certificate (for example from Let's Encrypt), enable HTTPS and redirect all HTTP traffic."),
    "https_not_enforced": dict(
        name="HTTPS not enforced", category="TLS/SSL", owasp=A02, exploitability=0.4,
        severity={"observed": "Medium"},
        description="HTTPS is available but HTTP requests are not redirected to it.",
        impact="Users who visit over HTTP remain exposed to interception.",
        recommendation="Redirect all HTTP requests to HTTPS and enable HSTS."),
    "ssl_invalid_cert": dict(
        name="Invalid TLS certificate", category="TLS/SSL", owasp=A02, exploitability=0.5,
        severity={"confirmed": "High"},
        description="The TLS certificate could not be verified (untrusted issuer or self-signed).",
        impact="Users cannot be sure they are talking to the real server; man-in-the-middle attacks are easier.",
        recommendation="Install a certificate issued by a trusted CA with the full chain."),
    "ssl_expired": dict(
        name="Expired TLS certificate", category="TLS/SSL", owasp=A02, exploitability=0.5,
        severity={"confirmed": "High"},
        description="The TLS certificate has expired.",
        impact="Browsers show security warnings and users may be trained to ignore them.",
        recommendation="Renew the certificate immediately and automate renewal."),
    "ssl_expiring": dict(
        name="TLS certificate expiring soon", category="TLS/SSL", owasp=A02, exploitability=0.2,
        severity={"observed": "Medium"},
        description="The TLS certificate expires in less than 30 days.",
        impact="If it lapses the site will show security errors and may become unavailable.",
        recommendation="Renew the certificate and set up automatic renewal and monitoring."),
    "ssl_hostname_mismatch": dict(
        name="TLS certificate hostname mismatch", category="TLS/SSL", owasp=A02, exploitability=0.5,
        severity={"confirmed": "High"},
        description="The certificate does not match the host name of the site.",
        impact="Clients cannot validate the server identity.",
        recommendation="Issue a certificate that includes the exact host name (SAN)."),
    "ssl_weak_protocol": dict(
        name="Deprecated TLS protocol version", category="TLS/SSL", owasp=A02, exploitability=0.4,
        severity={"confirmed": "Medium"},
        description="The server negotiated TLS 1.0 or 1.1, which are deprecated.",
        impact="Known weaknesses in old protocol versions may allow traffic decryption.",
        recommendation="Disable TLS 1.0/1.1 and support TLS 1.2 and 1.3 only."),
    "directory_listing": dict(
        name="Directory listing enabled", category="Information Disclosure", owasp=A05, exploitability=0.5,
        severity={"confirmed": "Medium"},
        description="The web server shows an index of files for a directory.",
        impact="Attackers can discover backups, logs or other files not meant to be public.",
        recommendation="Disable directory indexing (for example Options -Indexes in Apache, autoindex off in nginx)."),
    "git_exposed": dict(
        name="Exposed Git repository metadata", category="Information Disclosure", owasp=A05, exploitability=0.8,
        severity={"confirmed": "High"},
        description="Files from the .git directory are publicly downloadable.",
        impact="Source code, credentials and history may be reconstructed from the exposed repository.",
        recommendation="Block access to dotfiles/.git at the web server and remove the directory from the web root."),
    "env_file_exposed": dict(
        name="Exposed environment file (.env)", category="Information Disclosure", owasp=A05, exploitability=0.9,
        severity={"confirmed": "Critical"},
        description="A .env style configuration file is publicly accessible.",
        impact="API keys, database passwords and secrets are likely disclosed.",
        recommendation="Remove the file from the web root, rotate every secret it contained and deny access to dotfiles."),
    "config_file_exposed": dict(
        name="Exposed configuration file", category="Information Disclosure", owasp=A05, exploitability=0.7,
        severity={"confirmed": "High"},
        description="A server or application configuration file is publicly accessible.",
        impact="Configuration details and potentially credentials are disclosed.",
        recommendation="Move configuration outside the web root and deny direct access to it."),
    "phpinfo_exposed": dict(
        name="Exposed phpinfo() page", category="Information Disclosure", owasp=A05, exploitability=0.5,
        severity={"confirmed": "Medium"},
        description="A page that prints the PHP configuration is publicly accessible.",
        impact="Reveals versions, paths and settings that help target further attacks.",
        recommendation="Delete the phpinfo page from production servers."),
    "server_status_exposed": dict(
        name="Exposed server status page", category="Information Disclosure", owasp=A05, exploitability=0.4,
        severity={"confirmed": "Medium"},
        description="A server status page is reachable by the public.",
        impact="Reveals request URLs, client addresses and server internals.",
        recommendation="Restrict /server-status to trusted IP addresses."),
    "actuator_exposed": dict(
        name="Exposed Spring Boot actuator endpoint", category="Information Disclosure", owasp=A05, exploitability=0.7,
        severity={"confirmed": "High"},
        description="A Spring Boot actuator endpoint exposes environment properties.",
        impact="Configuration values and secrets may be disclosed.",
        recommendation="Disable or secure actuator endpoints and expose only /health."),
    "ds_store_exposed": dict(
        name="Exposed .DS_Store file", category="Information Disclosure", owasp=A05, exploitability=0.3,
        severity={"confirmed": "Low"},
        description="A macOS .DS_Store file is publicly accessible.",
        impact="Reveals file and directory names present on the server.",
        recommendation="Remove .DS_Store files from deployments and block dotfiles."),
    "server_version_disclosure": dict(
        name="Server version disclosure", category="Information Disclosure", owasp=A05, exploitability=0.2,
        severity={"observed": "Low"},
        description="The Server header discloses software name and version.",
        impact="Helps attackers match the server to known vulnerabilities.",
        recommendation="Configure the server to send a generic Server header (e.g. server_tokens off / ServerTokens Prod)."),
    "x_powered_by_disclosure": dict(
        name="Technology disclosure header", category="Information Disclosure", owasp=A05, exploitability=0.2,
        severity={"observed": "Low"},
        description="A response header discloses the server-side technology or framework version.",
        impact="Helps attackers choose framework-specific exploits.",
        recommendation="Remove X-Powered-By and similar headers in the framework or web server configuration."),
}

DEFAULT_ENTRY = dict(
    name="Security finding", category="Other", owasp=A05, exploitability=0.3, severity={"observed": "Low"},
    description="A potential security weakness was observed.", impact="Impact depends on the context.",
    recommendation="Review the evidence and apply vendor hardening guidance.")


def get_entry(finding_type: str) -> dict:
    return KNOWLEDGE_BASE.get(finding_type, DEFAULT_ENTRY)
