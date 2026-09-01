@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.12 from https://www.python.org/downloads/windows/ and enable the Python launcher.
  pause
  exit /b 1
)
echo VulnOrbit will open at http://127.0.0.1:8787
echo Keep this window open to receive real-source updates.
py -3 start.py
if errorlevel 1 pause
