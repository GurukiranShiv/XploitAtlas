#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
python3 -m venv .venv
. .venv/bin/activate
pip install --disable-pip-version-check -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
