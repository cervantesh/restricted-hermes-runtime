#!/usr/bin/env bash
# Bounded Linux runner for the AC10 suites that require POSIX or real PostgreSQL.
set -euo pipefail

project="${1:-}"
if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]{2,48}$ ]]; then
  echo "usage: $0 unique-lowercase-project-name" >&2
  exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
if docker compose version >/dev/null 2>&1; then
  compose=(docker compose --project-name "$project" -f tests/deployment/compose.ac10.yaml)
elif command -v docker.exe >/dev/null 2>&1 && docker.exe compose version >/dev/null 2>&1; then
  compose=(docker.exe compose --project-name "$project" -f tests/deployment/compose.ac10.yaml)
else
  echo "Docker Compose is required" >&2
  exit 1
fi

cleanup() {
  local status=$?
  set +e
  if (( status != 0 )); then
    "${compose[@]}" ps -a
    "${compose[@]}" logs --no-color --tail 200
  fi
  "${compose[@]}" down --volumes --remove-orphans
  return "$status"
}
trap cleanup EXIT

echo "Target inventory before create:"
"${compose[@]}" ps -a
"${compose[@]}" up -d --wait postgres

timeout 600 "${compose[@]}" run --rm tests sh -ec \
  "cp -a /workspace /tmp/workspace && cd /tmp/workspace && pip install --no-cache-dir '.[test,google]' >/tmp/pip.log && python -m pytest -p no:cacheprovider \
    tests/api \
    tests/integration --ignore=tests/integration/test_local_three_socket_composition.py \
    tests/unit/test_local_crypto_posix.py \
    tests/unit/test_local_uds_profile.py \
    tests/unit/test_migration_supervisor_posix.py \
    tests/unit/test_uds_entrypoint.py \
    tests/unit/test_local_deployment_preflight_posix.py -q"

timeout 300 "${compose[@]}" run --rm tests sh -ec \
  "cp -a /workspace /tmp/workspace && cd /tmp/workspace && pip install --no-cache-dir '.[test,google]' >/tmp/pip.log && python -m pytest -p no:cacheprovider \
    tests/integration/test_local_three_socket_composition.py -q"

echo "AC10 Linux/PostgreSQL/POSIX suites passed."
