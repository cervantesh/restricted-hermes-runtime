#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python "$root/tests/deployment/test_mattermost_esr_staging.py" "$@"
