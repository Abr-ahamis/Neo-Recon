#!/usr/bin/env bash
set -euo pipefail
if (($# == 0)); then exit 64; fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python3 -m scr.dependencies.bootstrap "$1"
exec "$@"
