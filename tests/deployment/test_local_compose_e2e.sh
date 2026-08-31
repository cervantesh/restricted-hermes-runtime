#!/usr/bin/env bash
# Real Linux/Docker Compose E2E. Uses only SYNTHETIC_NON_PHI_ONLY content.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="${1:-}"
if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]{2,48}$ ]]; then
  echo "usage: $0 unique-lowercase-project-name" >&2
  exit 2
fi
runtime="$(mktemp -d -t restricted-synthetic-non-phi-only.XXXXXX)"
compose=(docker compose --project-name "$project" --env-file "$runtime/.env.generated" -f "$repo_root/deploy/local/compose.yaml" -f "$repo_root/deploy/local/compose.synthetic-non-phi-only.yaml")
external=(
  "${project}_inference_sockets"
  "${project}_conversation_authorization"
  "${project}_gateway_authorization"
  "${project}_conversation_keys"
  "${project}_gateway_keys"
  "${project}_postgres_admin_secret"
)

cleanup() {
  set +e
  "${compose[@]}" --profile synthetic-non-phi-only down --volumes --remove-orphans
  for volume in "${external[@]}"; do
    if docker volume inspect "$volume" >/dev/null 2>&1; then
      docker volume rm "$volume"
    fi
  done
  rm -rf -- "$runtime"
}
trap cleanup EXIT

echo "Target inventory before create:"
docker ps -a --filter "label=com.docker.compose.project=$project" --format '{{.ID}} {{.Names}} {{.Status}}'
for volume in "${external[@]}"; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "refusing pre-existing target volume: $volume" >&2
    exit 1
  fi
done

PYTHONPATH="$repo_root/src" python3 "$repo_root/deploy/local/synthetic/prepare_synthetic_non_phi_only.py" \
  --output-root "$runtime" --project-name "$project" --policy-output "$repo_root/policy/generated"
for volume in "${external[@]}"; do docker volume create "$volume" >/dev/null; done

copy_volume() {
  local volume="$1" source="$2" uid="$3" gid="$4"
  docker run --rm --network none -v "$volume:/dest" -v "$source:/src:ro" alpine:3.20.3 \
    sh -ec "cp -a /src/. /dest/; chown -R $uid:$gid /dest; find /dest -type f -exec chmod 0600 {} +"
}
copy_volume "${project}_conversation_authorization" "$runtime/conversation-authorization" 10006 20001
copy_volume "${project}_gateway_authorization" "$runtime/gateway-authorization" 10005 20002
copy_volume "${project}_conversation_keys" "$runtime/conversation-keys" 10006 20001
copy_volume "${project}_gateway_keys" "$runtime/gateway-keys" 10005 20002
copy_volume "${project}_postgres_admin_secret" "$runtime/postgres-admin-secret" 999 999

"${compose[@]}" --profile synthetic-non-phi-only config >/dev/null
"${compose[@]}" --profile synthetic-non-phi-only build
"${compose[@]}" --profile synthetic-non-phi-only up -d synthetic-non-phi-only-broker
"${compose[@]}" up -d --wait postgres gateway conversation

SYNTHETIC_NON_PHI_ONLY_MODE=disabled "${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-probe
count="$(docker run --rm --network none -v "${project}_synthetic_non_phi_only_state:/state:ro" alpine:3.20.3 cat /state/broker-count)"
test "$count" = 0

"${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-enable
SYNTHETIC_NON_PHI_ONLY_MODE=create "${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-probe
SYNTHETIC_NON_PHI_ONLY_MODE=replay "${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-probe
count="$(docker run --rm --network none -v "${project}_synthetic_non_phi_only_state:/state:ro" alpine:3.20.3 cat /state/broker-count)"
test "$count" = 1

"${compose[@]}" up -d --force-recreate --wait gateway conversation
SYNTHETIC_NON_PHI_ONLY_MODE=replay "${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-probe
count="$(docker run --rm --network none -v "${project}_synthetic_non_phi_only_state:/state:ro" alpine:3.20.3 cat /state/broker-count)"
test "$count" = 1

# Peer roles and privilege negatives.
"${compose[@]}" exec -T -u 10006:20004 postgres psql -h /run/restricted-postgres -U restricted_local_conversation -d restricted_runtime -Atqc 'SELECT count(*) FROM restricted_content.turns' >/dev/null
! "${compose[@]}" exec -T -u 10006:20004 postgres psql -h /run/restricted-postgres -U restricted_local_conversation -d restricted_runtime -Atqc 'SELECT count(*) FROM inference_ledger.attempts' >/dev/null 2>&1
"${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'SELECT count(*) FROM inference_ledger.attempts' >/dev/null
! "${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'SELECT count(*) FROM restricted_content.turns' >/dev/null 2>&1
! "${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'UPDATE inference_ledger.runtime_controls SET dispatch_enabled=false' >/dev/null 2>&1

# Runtime network namespace rejects Internet IPv4, IPv6 and DNS; proxy vars are absent.
for service in conversation gateway; do
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.create_connection(("1.1.1.1",443),1)' >/dev/null 2>&1
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.create_connection(("2606:4700:4700::1111",443),1)' >/dev/null 2>&1
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.getaddrinfo("example.com",443)' >/dev/null 2>&1
  "${compose[@]}" exec -T "$service" python -c 'import os; assert not any(k.upper() in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"} for k in os.environ)'
done

echo 'SYNTHETIC_NON_PHI_ONLY Compose E2E passed.'
echo 'model_attested=false deployment_conformant=false phi_authorized=false'
