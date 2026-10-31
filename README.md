<div align="center">

# 🛡️ WebGuard AI

**An intelligent web vulnerability scanner powered by AI and OWASP best practices.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)](README.md)

[Features](#-features) · [Quick Start](#-quick-start) · [Setup](#%EF%B8%8F-setup) · [Scanner Modules](#-scanner-modules) · [AI Engine](#-ai-engine) · [Configuration](#%EF%B8%8F-configuration) · [FAQ](#-faq)

</div>

---

## 🚀 What is WebGuard AI?

WebGuard AI is a **full-stack security assessment platform** that combines traditional vulnerability scanning techniques with an AI-powered analysis engine. It helps developers, security researchers, and students discover, understand, and remediate web security issues — all through a clean browser-based dashboard.

> ⚠️ **Ethical Use Only.** WebGuard AI must only be used against targets you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Multi-module Scanner** | XSS, SQLi, SSL/TLS, Headers, Cookies, Info Disclosure |
| 🤖 **AI Analysis Engine** | scikit-learn powered classification, false-positive reduction, near-duplicate detection |
| 📊 **Risk Scoring** | Severity × confidence × exploitability prioritization |
| 📄 **PDF & HTML Reports** | Downloadable professional reports via ReportLab |
| 🔄 **Real-time Updates** | WebSocket-based live scan progress via Socket.IO |
| 🔐 **Auth & Sessions** | Login, registration, brute-force lockout, CSRF protection |
| 🗂️ **Scan History** | Full scan history with comparison between runs |
| ⚙️ **OWASP ZAP Integration** | Optional deep scan with ZAP in daemon mode |
| 🧪 **Built-in Lab Mode** | Safely scan local OWASP Juice Shop / WebGoat targets |

---

## 🏁 Quick Start

### Windows (One-Click)

```bat
run_windows.bat
```

This script automatically:
1. Creates a Python virtual environment
2. Installs all dependencies from `requirements.txt`
3. Starts WebGuard AI at **http://127.0.0.1:5000**

---

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/mithunlingala30/WebGuard-ai.git
cd WebGuard-ai

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env as needed

# 5. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

---

## 🛠️ Setup

### Prerequisites

- Python **3.10+**
- pip
- (Optional) [OWASP ZAP](https://www.zaproxy.org/) for deep scanning

### Environment Configuration

Copy `.env.example` to `.env` and adjust the values:

```bash
cp .env.example .env
```

Key settings:

| Variable | Default | Description |
|---|---|---|
| `WEBGUARD_SECRET_KEY` | *(auto-generated)* | Flask session secret key |
| `WEBGUARD_HOST` | `127.0.0.1` | Bind host |
| `WEBGUARD_PORT` | `5000` | Bind port |
| `WEBGUARD_LAB_MODE` | `true` | Allow scanning local lab targets |
| `WEBGUARD_ZAP_ENABLED` | `false` | Enable OWASP ZAP integration |
| `WEBGUARD_ZAP_API_KEY` | `changeme` | ZAP API key |

---

## 📁 Project Structure

```
WebGuard-AI/
│
├── app.py                  # Application factory & entry point
├── config.py               # Centralized configuration (env-driven)
├── database.py             # SQLAlchemy & extensions setup
├── run_windows.bat         # One-click Windows launcher
│
├── ai_engine/              # AI analysis pipeline
│   ├── analyzer.py         # De-duplication, classification, prioritization
│   ├── classifier.py       # OWASP category + severity classifier
│   ├── recommendations.py  # Remediation advice engine
│   ├── risk_score.py       # Overall risk scoring
│   └── train_model.py      # Model training utilities
│
├── scanner/                # Vulnerability scanner modules
│   ├── xss_scanner.py      # Cross-Site Scripting detection
│   ├── sqli_scanner.py     # SQL Injection detection
│   ├── ssl_checker.py      # SSL/TLS configuration checks
│   ├── header_checker.py   # HTTP security headers audit
│   ├── cookie_checker.py   # Cookie security attributes
│   ├── information_disclosure.py  # Sensitive info leakage
│   ├── crawler.py          # Site crawler & URL discovery
│   ├── targets.py          # Target validation & SSRF protection
│   └── zap_integration.py  # OWASP ZAP bridge
│
├── routes/                 # Flask blueprints (URL routing)
│   ├── auth.py             # Login, register, logout
│   ├── dashboard.py        # Main dashboard
│   ├── scanner.py          # Scan initiation & results API
│   ├── history.py          # Scan history
│   ├── reports.py          # PDF/HTML report generation
│   └── sockets.py          # WebSocket events (real-time updates)
│
├── models/                 # SQLAlchemy database models
│   ├── user.py             # User accounts
│   ├── scan.py             # Scan records
│   ├── vulnerability.py    # Findings per scan
│   └── report.py           # Generated reports
│
├── services/               # Business logic layer
│   ├── scan_manager.py     # Scan lifecycle management
│   ├── report_generator.py # PDF/HTML report builder
│   ├── http_client.py      # Shared HTTP client (rate limiting)
│   ├── target_validator.py # URL validation & safety checks
│   └── comparison.py       # Diff between scan runs
│
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, vendor libraries
│   ├── css/neumorphism.css # Custom neumorphic UI theme
│   └── js/                 # Dashboard, scan, reports scripts
│
└── tests/                  # Pytest test suite
    ├── test_app.py
    ├── test_analyzer.py
    ├── test_scan_flow.py
    └── test_validator.py
```

---

## 🔍 Scanner Modules

WebGuard AI runs several independent scanner modules during each assessment:

| Module | What it checks |
|---|---|
| **XSS Scanner** | Reflected & DOM-based Cross-Site Scripting via payload injection |
| **SQLi Scanner** | SQL Injection via error-based and boolean detection |
| **SSL Checker** | Certificate validity, protocol versions, cipher suites |
| **Header Checker** | Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **Cookie Checker** | HttpOnly, Secure, SameSite attributes on session cookies |
| **Info Disclosure** | Server version leaks, debug pages, sensitive file exposure |
| **Crawler** | Discovers URLs and forms for the other modules to test |

---

## 🤖 AI Engine

The AI pipeline runs **after** raw scanner findings are collected:

```
Raw Findings
     │
     ▼
1. Exact De-duplication (SHA-1 fingerprint per finding type / URL / parameter)
     │
     ▼
2. False-Positive Suppression (confidence < 30% → dropped)
     │
     ▼
3. OWASP Classification (category + severity + confidence)
     │
     ▼
4. Near-Duplicate Detection (TF-IDF cosine similarity ≥ 90% → grouped)
     │
     ▼
5. Prioritization Score = severity × confidence × exploitability
     │
     ▼
6. Overall Risk Score (0 – 100)
     │
     ▼
Final Analyzed Report
```

---

## 🧪 Running Tests

```bash
# Activate virtual environment first
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate.bat      # Windows

# Run the full test suite
pytest

# Run a specific test file
pytest tests/test_analyzer.py -v
```

---

## 🧩 OWASP ZAP Integration (Optional)

For deeper scanning, WebGuard AI can use [OWASP ZAP](https://www.zaproxy.org/) in daemon mode:

```bash
# 1. Start ZAP in daemon mode
zap.bat -daemon -port 8090 -config api.key=changeme

# 2. Enable ZAP in .env
WEBGUARD_ZAP_ENABLED=true
WEBGUARD_ZAP_API_KEY=changeme
```

Select the **Full** scan profile in the UI to trigger ZAP alongside the built-in modules.

---

## 🧪 Lab Mode (Testing on Local Vulnerable Apps)

WebGuard AI ships with lab mode for safely scanning locally running vulnerable apps like **OWASP Juice Shop** or **WebGoat**.

```bash
# Start Juice Shop (requires Docker)
docker run -p 3000:3000 bkimminich/juice-shop

# Start WebGoat (requires Docker)
docker run -p 8080:8080 webgoat/webgoat

# Launch the lab runner
run_lab.bat
```

Then scan `http://localhost:3000` or `http://localhost:8080` from the WebGuard AI dashboard.

---

## ⚙️ Configuration

All configuration is driven by environment variables (via `.env`). Defaults are **safe for development**. For production:

- Set a strong `WEBGUARD_SECRET_KEY`
- Set `WEBGUARD_SESSION_COOKIE_SECURE=true` behind HTTPS
- Set `WEBGUARD_LAB_MODE=false`
- Restrict `WEBGUARD_AUTHORIZED_DOMAINS` to your approved targets

---

## 🔒 Security Design

- **CSRF protection** on all state-changing requests
- **SSRF protection** — target validator blocks RFC-1918 / loopback addresses unless lab mode is explicitly enabled
- **Brute-force lockout** — 5 failed logins → 5-minute cooldown
- **Secure session cookies** (HttpOnly, SameSite=Lax, optional Secure flag)
- **Strict Content-Security-Policy** header on all responses
- **Rate limiting** — configurable delay between scanner requests

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## ❓ FAQ

**Q: Can I scan any public website?**  
A: Only targets you own or have explicit permission to test. Unauthorized scanning violates laws in most countries.

**Q: Does WebGuard AI store my scan data?**  
A: All data is stored locally in `instance/webguard.db` (SQLite). Nothing is sent to external servers.

**Q: How do I reset the database?**  
A: Delete `instance/webguard.db` and restart the app — it will recreate an empty database.

**Q: Can I run it on a server?**  
A: Yes, but set `WEBGUARD_LAB_MODE=false`, use HTTPS, and restrict `WEBGUARD_AUTHORIZED_DOMAINS`.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ for the security community · <a href="https://github.com/mithunlingala30/WebGuard-ai">GitHub</a>
</div>
