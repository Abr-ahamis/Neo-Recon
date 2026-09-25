#!/usr/bin/env bash
set -euo pipefail
if (($# == 0)); then
    exit 64
fi
exec "$@"
