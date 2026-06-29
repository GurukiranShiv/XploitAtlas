# Local Windows runner for SQLite mode. Run from the project root:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\scripts\run_local.ps1

$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\..\backend"

if (!(Test-Path ".venv")) {
    py -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
