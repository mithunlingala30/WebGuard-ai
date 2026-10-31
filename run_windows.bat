@echo off
REM WebGuard AI - one-click start for Windows (creates venv, installs deps, runs the app)
cd /d "%~dp0"
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate.bat
echo Installing dependencies...
python -m pip install -q --upgrade pip
pip install -q -r requirements.txt
echo.
echo Starting WebGuard AI on http://127.0.0.1:5000
start "" http://127.0.0.1:5000
python app.py
pause
