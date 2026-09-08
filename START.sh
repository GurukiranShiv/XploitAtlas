#!/bin/sh
set -eu
MASTERMONK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$MASTERMONK_ROOT"
MASTERMONK_PYTHON=''
for candidate in python3 python python3.14 python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -E -c 'import sys, sqlite3, ssl; sys.exit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
        MASTERMONK_PYTHON=$candidate
        break
    fi
done
if [ -z "$MASTERMONK_PYTHON" ]; then
    printf '%s\n' 'MasterMonk requires Python 3.11 or newer: https://www.python.org/downloads/' >&2
    exit 1
fi
if [ "${1:-}" = '--check-python' ]; then
    exec "$MASTERMONK_PYTHON" -E -c 'import sys; print(sys.executable); print(sys.version)'
fi
exec "$MASTERMONK_PYTHON" -E start.py "$@"
