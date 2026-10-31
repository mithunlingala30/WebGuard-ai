@echo off
REM Starts WebGuard AI with LAB MODE enabled so you can scan LOCAL lab targets
REM (OWASP Juice Shop on :3000, WebGoat on :8080, tests\vuln_test_site.py on :5001).
REM Only localhost / 127.0.0.1 are opened up. Everything else stays blocked.
cd /d "%~dp0"
if not exist venv (
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -q -r requirements.txt
set WEBGUARD_LAB_MODE=1
set WEBGUARD_LAB_HOSTS=localhost,127.0.0.1
echo LAB MODE ON - local targets allowed.
start "" http://127.0.0.1:5000
python app.py
pause
