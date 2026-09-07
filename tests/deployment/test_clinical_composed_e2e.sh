#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if command -v python3 >/dev/null 2>&1; then
  python_bin=python3
elif command -v python >/dev/null 2>&1; then
  python_bin=python
else
  echo "clinical-composed-e2e: DENIED python-unavailable" >&2
  exit 2
fi
exec "$python_bin" "$root/tests/deployment/test_clinical_composed_e2e.py" "$@"
