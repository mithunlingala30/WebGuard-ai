@echo off
REM Starts the intentionally weak local test website on http://127.0.0.1:5001
cd /d "%~dp0"
if not exist venv ( python -m venv venv )
call venv\Scripts\activate.bat
pip install -q -r requirements.txt
python tests\vuln_test_site.py
pause
