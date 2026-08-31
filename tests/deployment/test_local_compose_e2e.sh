#!/usr/bin/env bash
# Real Linux/Docker Compose E2E. Uses only SYNTHETIC_NON_PHI_ONLY content.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="${1:-}"
if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]{2,48}$ ]]; then
  echo "usage: $0 unique-lowercase-project-name" >&2
  exit 2
fi
if docker compose version >/dev/null 2>&1; then
  docker_cli=(docker)
  compose_cli=(docker compose)
  runtime_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/tmp}"
  compose_env_file=""
elif command -v docker.exe >/dev/null 2>&1 && docker.exe compose version >/dev/null 2>&1; then
  docker_cli=(docker.exe)
  compose_cli=(docker.exe compose)
  runtime_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/mnt/c/Temp}"
  compose_env_file="windows"
else
  echo "Docker Compose is required" >&2
  exit 1
fi
mkdir -p "$runtime_root"
runtime="$(mktemp -d "$runtime_root/${project}.SYNTHETIC_NON_PHI_ONLY.XXXXXX")"
env_file="$runtime/.env.generated"
if [[ "$compose_env_file" == "windows" ]]; then env_file="$(wslpath -w "$env_file")"; fi
compose=("${compose_cli[@]}" --project-name "$project" --env-file "$env_file" -f deploy/local/compose.yaml -f deploy/local/compose.synthetic-non-phi-only.yaml)
external=(
  "${project}_inference_sockets"
  "${project}_conversation_authorization"
  "${project}_gateway_authorization"
  "${project}_conversation_keys"
  "${project}_gateway_keys"
  "${project}_postgres_admin_secret"
)

cleanup() {
  local status=$?
  set +e
  if (( status != 0 )); then
    "${compose[@]}" ps -a
    "${compose[@]}" logs --no-color --tail 200
  fi
  "${compose[@]}" --profile synthetic-non-phi-only down --volumes --remove-orphans
  for volume in "${external[@]}"; do
    if "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1; then
      "${docker_cli[@]}" volume rm "$volume"
    fi
  done
  rm -rf -- "$runtime"
  return "$status"
}
trap cleanup EXIT

echo "Target inventory before create:"
"${docker_cli[@]}" ps -a --filter "label=com.docker.compose.project=$project" --format '{{.ID}} {{.Names}} {{.Status}}'
for volume in "${external[@]}"; do
  if "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1; then
    echo "refusing pre-existing target volume: $volume" >&2
    exit 1
  fi
done

PYTHONPATH="$repo_root/src" python3 "$repo_root/deploy/local/synthetic/prepare_synthetic_non_phi_only.py" \
  --output-root "$runtime" --project-name "$project" --policy-output "$repo_root/policy/generated"
for volume in "${external[@]}"; do "${docker_cli[@]}" volume create "$volume" >/dev/null; done

copy_volume() {
  local volume="$1" source="$2" uid="$3" gid="$4"
  if [[ "$compose_env_file" == "windows" ]]; then source="$(wslpath -w "$source")"; fi
  "${docker_cli[@]}" run --rm --network none --mount "type=volume,source=$volume,target=/dest" --mount "type=bind,source=$source,target=/src,readonly" alpine:3.20.3 \
    sh -ec "cp -a /src/. /dest/; chown -R $uid:$gid /dest; find /dest -type f -exec chmod 0600 {} +"
}
copy_volume "${project}_conversation_authorization" "$runtime/conversation-authorization" 10006 20001
copy_volume "${project}_gateway_authorization" "$runtime/gateway-authorization" 10005 20002
copy_volume "${project}_conversation_keys" "$runtime/conversation-keys" 10006 20001
copy_volume "${project}_gateway_keys" "$runtime/gateway-keys" 10005 20002
copy_volume "${project}_postgres_admin_secret" "$runtime/postgres-admin-secret" 999 999

volume_exec() {
  local volume="$1" command="$2"
  "${docker_cli[@]}" run --rm --network none --user 0:0 -v "$volume:/data" alpine:3.20.3 sh -ec "$command"
}

broker_count() {
  "${docker_cli[@]}" run --rm --network none -v "${project}_synthetic_non_phi_only_state:/state:ro" alpine:3.20.3 cat /state/broker-count
}

preflight_must_fail() {
  local service="$1" role="$2" control="$3"
  echo "Fail-closed control: $control"
  if "${compose[@]}" run --rm --no-deps "$service" \
      python -m restricted_runtime.local_deployment_preflight check "$role"; then
    echo "preflight unexpectedly passed: $control" >&2
    exit 1
  fi
  test "$(broker_count)" = 0
}

"${compose[@]}" --profile synthetic-non-phi-only config >/dev/null
"${compose[@]}" --profile synthetic-non-phi-only build
"${compose[@]}" --profile synthetic-non-phi-only up -d synthetic-non-phi-only-broker
"${compose[@]}" up -d --wait postgres gateway conversation

# Exact live socket metadata and ACL connection matrix.
probe_image="${project}-synthetic-non-phi-only-probe:latest"
"${docker_cli[@]}" image inspect "$probe_image" >/dev/null
socket_volume="${project}_inference_sockets"
"${docker_cli[@]}" run --rm --network none --user 0:0 -v "$socket_volume:/run/restricted-inference:ro" "$probe_image" \
  python /app/socket_acl_probe.py /run/restricted-inference --uid 0 --gid 20000 --mode 1770
for spec in "conversation.sock:10006:20001" "gateway.sock:10005:20002" "broker.sock:10003:20003"; do
  IFS=: read -r socket_name socket_uid socket_gid <<<"$spec"
  "${docker_cli[@]}" run --rm --network none --user 0:0 -v "$socket_volume:/run/restricted-inference:ro" "$probe_image" \
    python /app/socket_acl_probe.py "/run/restricted-inference/$socket_name" --uid "$socket_uid" --gid "$socket_gid" --mode 660
done
acl_probe() {
  local uid_gid="$1" target="$2" expected="$3"
  shift 3
  "${docker_cli[@]}" run --rm --network none --user "$uid_gid" --group-add 20000 "$@" \
    -v "$socket_volume:/run/restricted-inference:ro" "$probe_image" \
    python /app/socket_acl_probe.py "/run/restricted-inference/$target" --expect-connect "$expected"
}
acl_probe 10007:20001 conversation.sock allow
acl_probe 10007:20001 gateway.sock deny
acl_probe 10007:20001 broker.sock deny
acl_probe 10006:20001 gateway.sock allow --group-add 20002
acl_probe 10006:20001 broker.sock deny --group-add 20002
acl_probe 10005:20002 broker.sock allow --group-add 20003
acl_probe 10008:20004 conversation.sock deny
acl_probe 10008:20004 gateway.sock deny
acl_probe 10008:20004 broker.sock deny

# The role-specific mount boundary keeps the other role's keys absent.
"${compose[@]}" exec -T conversation test ! -e /run/restricted-keys/gateway-mac.key
"${compose[@]}" exec -T gateway test ! -e /run/restricted-keys/service-mac.key
"${compose[@]}" exec -T gateway test ! -e /run/restricted-keys/content-wrap.key

# Exact-image artifact and dependency mutations. Runtime services are stopped,
# dispatch is still durably disabled, and every control must leave broker count 0.
"${compose[@]}" stop conversation gateway

volume_exec "${project}_gateway_authorization" "mv /data/authorization.json /data/authorization.saved"
preflight_must_fail gateway-preflight gateway "missing gateway authorization"
volume_exec "${project}_gateway_authorization" "mv /data/authorization.saved /data/authorization.json"

volume_exec "${project}_conversation_authorization" "mv /data/authorization.json /data/authorization.saved"
preflight_must_fail conversation conversation "missing conversation authorization"
volume_exec "${project}_conversation_authorization" "mv /data/authorization.saved /data/authorization.json"

volume_exec "${project}_gateway_keys" "mv /data/gateway-mac.key /data/gateway-mac.saved"
preflight_must_fail gateway-preflight gateway "missing gateway key"
volume_exec "${project}_gateway_keys" "mv /data/gateway-mac.saved /data/gateway-mac.key"

volume_exec "${project}_conversation_keys" "mv /data/service-mac.key /data/service-mac.saved"
preflight_must_fail conversation conversation "missing conversation key"
volume_exec "${project}_conversation_keys" "mv /data/service-mac.saved /data/service-mac.key"

volume_exec "${project}_gateway_authorization" "mv /data/authorization.json /data/authorization.saved; ln -s authorization.saved /data/authorization.json"
preflight_must_fail gateway-preflight gateway "symlinked authorization"
volume_exec "${project}_gateway_authorization" "rm /data/authorization.json; mv /data/authorization.saved /data/authorization.json"

volume_exec "${project}_gateway_authorization" "chown 10006:20001 /data/authorization.json"
preflight_must_fail gateway-preflight gateway "wrong-owner authorization"
volume_exec "${project}_gateway_authorization" "chown 10005:20002 /data/authorization.json"

volume_exec "${project}_gateway_authorization" "chmod 0660 /data/authorization.json"
preflight_must_fail gateway-preflight gateway "group-writable authorization"
volume_exec "${project}_gateway_authorization" "chmod 0600 /data/authorization.json"

volume_exec "${project}_gateway_authorization" "cp -a /data/authorization.json /data/authorization.saved; printf x >> /data/authorization.json"
preflight_must_fail gateway-preflight gateway "digest-mismatched authorization"
volume_exec "${project}_gateway_authorization" "mv -f /data/authorization.saved /data/authorization.json"

"${compose[@]}" stop synthetic-non-phi-only-broker
preflight_must_fail gateway-preflight gateway "missing broker socket"
"${compose[@]}" --profile synthetic-non-phi-only up -d synthetic-non-phi-only-broker

"${compose[@]}" stop postgres
preflight_must_fail gateway-preflight gateway "missing PostgreSQL socket"
"${compose[@]}" up -d --wait postgres gateway conversation
test "$(broker_count)" = 0

"${compose[@]}" --profile synthetic-non-phi-only run --rm -e SYNTHETIC_NON_PHI_ONLY_MODE=disabled synthetic-non-phi-only-probe
count="$(broker_count)"
test "$count" = 0

"${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-enable
"${compose[@]}" --profile synthetic-non-phi-only run --rm -e SYNTHETIC_NON_PHI_ONLY_MODE=create synthetic-non-phi-only-probe
"${compose[@]}" --profile synthetic-non-phi-only run --rm -e SYNTHETIC_NON_PHI_ONLY_MODE=replay synthetic-non-phi-only-probe
count="$(broker_count)"
test "$count" = 1

"${compose[@]}" up -d --force-recreate --wait gateway conversation
"${compose[@]}" --profile synthetic-non-phi-only run --rm -e SYNTHETIC_NON_PHI_ONLY_MODE=replay synthetic-non-phi-only-probe
count="$(broker_count)"
test "$count" = 1

# Peer roles and privilege negatives.
"${compose[@]}" exec -T -u 10006:20004 postgres psql -h /run/restricted-postgres -U restricted_local_conversation -d restricted_runtime -Atqc 'SELECT count(*) FROM restricted_content.turns' >/dev/null
! "${compose[@]}" exec -T -u 10006:20004 postgres psql -h /run/restricted-postgres -U restricted_local_conversation -d restricted_runtime -Atqc 'SELECT count(*) FROM inference_ledger.attempts' >/dev/null 2>&1
"${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'SELECT count(*) FROM inference_ledger.attempts' >/dev/null
! "${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'SELECT count(*) FROM restricted_content.turns' >/dev/null 2>&1
# This is the same row-lock shape used by the production gateway reservation path.
"${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'BEGIN; SELECT dispatch_enabled FROM inference_ledger.runtime_controls WHERE control_key=true FOR SHARE; ROLLBACK' >/dev/null
# The one column-level privilege needed by PostgreSQL for FOR SHARE remains
# unusable for mutation because the local-bootstrap-only trigger is fail-closed.
! "${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'UPDATE inference_ledger.runtime_controls SET updated_at=updated_at' >/dev/null 2>&1
! "${compose[@]}" exec -T -u 10005:20004 postgres psql -h /run/restricted-postgres -U restricted_local_gateway -d restricted_runtime -Atqc 'UPDATE inference_ledger.runtime_controls SET dispatch_enabled=false' >/dev/null 2>&1

# Runtime network namespace rejects Internet IPv4, IPv6 and DNS; proxy vars are absent.
for service in conversation gateway; do
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.create_connection(("1.1.1.1",443),1)' >/dev/null 2>&1
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.create_connection(("2606:4700:4700::1111",443),1)' >/dev/null 2>&1
  ! "${compose[@]}" exec -T "$service" python -c 'import socket; socket.getaddrinfo("example.com",443)' >/dev/null 2>&1
  "${compose[@]}" exec -T "$service" python -c 'import os; assert not any(k.upper() in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"} for k in os.environ)'
done

# Return durable dispatch to its fail-closed state before normal exit.
"${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-disable
dispatch="$("${compose[@]}" exec -T -u 999:20004 postgres psql -h /run/restricted-postgres -U postgres -d restricted_runtime -Atqc 'SELECT dispatch_enabled FROM inference_ledger.runtime_controls WHERE control_key=true')"
test "$dispatch" = f

echo 'SYNTHETIC_NON_PHI_ONLY Compose E2E passed.'
echo 'model_attested=false deployment_conformant=false phi_authorized=false'
