#!/bin/sh
set -eu
MASTERMONK_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$MASTERMONK_ROOT/START.sh" "$@"
