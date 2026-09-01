#!/usr/bin/env bash
# Real four-container proof for the closed Hermes restricted runner.
# All message data is SYNTHETIC_NON_PHI_ONLY and is never written to evidence.
set -euo pipefail

runtime_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="${1:-}"
readonly RUNTIME_HEAD="7ce40dad644521c658f2985958be6cfc745d06be"
readonly HERMES_HEAD="f04d9162a98902926f36e94034821be8f0027bff"
hermes_source="${HERMES_RESTRICTED_SOURCE:-/mnt/c/dev/hermes-restricted-config}"
if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]{2,48}$ ]]; then
  echo "usage: $0 unique-lowercase-project-name" >&2
  exit 2
fi
if command -v git.exe >/dev/null 2>&1 && hermes_source_windows="$(wslpath -w "$hermes_source" 2>/dev/null)" && git.exe -C "$hermes_source_windows" rev-parse HEAD >/dev/null 2>&1; then
  hermes_git=(git.exe -C "$hermes_source_windows")
else
  hermes_git=(git -C "$hermes_source")
fi
if [[ "$("${hermes_git[@]}" rev-parse HEAD)" != "$HERMES_HEAD" ]]; then
  echo "required Hermes restricted source revision is unavailable" >&2
  exit 1
fi
for source_file in hermes_cli/restricted_bootstrap.py hermes_cli/restricted_entry.py hermes_cli/restricted_runtime.py hermes_cli/subcommands/restricted.py; do
  "${hermes_git[@]}" diff --quiet -- "$source_file" || { echo "restricted Hermes source file is dirty: $source_file" >&2; exit 1; }
done

if docker compose version >/dev/null 2>&1; then
  docker_cli=(docker); compose_cli=(docker compose); runtime_tmp_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/tmp}"; windows_cli=false
elif command -v docker.exe >/dev/null 2>&1 && docker.exe compose version >/dev/null 2>&1; then
  docker_cli=(docker.exe); compose_cli=(docker.exe compose); runtime_tmp_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/mnt/c/Temp}"; windows_cli=true
else
  echo "Docker Compose is required" >&2
  exit 1
fi

mkdir -p "$runtime_tmp_root"
runtime="$(mktemp -d "$runtime_tmp_root/${project}.SYNTHETIC_NON_PHI_ONLY.XXXXXX")"
stage_archive="$runtime/runtime-head.tar"
stage_root="$runtime/runtime-head"
failure_logs="$runtime_tmp_root/${project}.hermes-restricted-failure-logs"
success_evidence="$runtime_tmp_root/${project}.hermes-restricted-success-evidence.txt"
test ! -e "$success_evidence" || { echo "refusing to overwrite prior success evidence" >&2; exit 1; }
env_file="$runtime/.env.generated"
runtime_windows="$(wslpath -w "$runtime_root")"
runtime_head="$(git.exe -C "$runtime_windows" rev-parse "$RUNTIME_HEAD^{commit}")"
runtime_tree="$(git.exe -C "$runtime_windows" rev-parse "$runtime_head^{tree}")"
# The Windows worktree is configured with core.autocrlf=true.  Compose bind
# mounts scripts, so run the deployment from the exact LF Git blob tree rather
# than silently transforming files in the worktree.
git.exe -C "$runtime_windows" -c core.autocrlf=false archive --format=tar "$runtime_head" > "$stage_archive"
archive_sha256="$(sha256sum "$stage_archive" | awk '{print $1}')"
mkdir "$stage_root"
tar -xf "$stage_archive" -C "$stage_root"
test "$(head -c 24 "$stage_root/deploy/local/socket-init.sh" | od -An -tx1 | tr -d ' \n')" = "23212f62696e2f73680a736574202d65750a696e7374616c"

build_root="$stage_root"
hermes_build_context="$hermes_source"
client_dockerfile="$runtime_root/tests/deployment/Dockerfile.restricted_hermes_client"
if [[ "$windows_cli" == true ]]; then
  env_file="$(wslpath -w "$env_file")"
  build_root="$(wslpath -w "$stage_root")"
  hermes_build_context="$(wslpath -w "$hermes_source")"
  client_dockerfile="$(wslpath -w "$client_dockerfile")"
fi
compose=("${compose_cli[@]}" --project-name "$project" --env-file "$env_file" -f "$build_root/deploy/local/compose.yaml" -f "$build_root/deploy/local/compose.synthetic-non-phi-only.yaml")
external=(
  "${project}_inference_sockets"
  "${project}_conversation_authorization"
  "${project}_gateway_authorization"
  "${project}_conversation_keys"
  "${project}_gateway_keys"
  "${project}_postgres_admin_secret"
  "${project}_hermes_home"
)
socket_volume="${project}_inference_sockets"
home_volume="${project}_hermes_home"
client_image="${project}-hermes-restricted-client:latest"
fake_container="${project}-altered-readiness"

cleanup() {
  local status=$? cleanup_ok=true
  set +e
  if (( status != 0 )); then
    mkdir -p "$failure_logs"
    "${compose[@]}" ps -a >"$failure_logs/compose-ps.txt" 2>&1
    "${compose[@]}" logs --no-color --tail 200 >"$failure_logs/compose-services.log" 2>&1
    echo "failure logs: $failure_logs" >&2
  fi
  "${docker_cli[@]}" rm -f "$fake_container" >/dev/null 2>&1 || true
  "${compose[@]}" --profile synthetic-non-phi-only down --volumes --remove-orphans || cleanup_ok=false
  for volume in "${external[@]}"; do
    "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1 && "${docker_cli[@]}" volume rm "$volume" >/dev/null || true
    "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1 && cleanup_ok=false
  done
  "${docker_cli[@]}" image inspect "$client_image" >/dev/null 2>&1 && "${docker_cli[@]}" image rm "$client_image" >/dev/null || true
  "${docker_cli[@]}" image inspect "$client_image" >/dev/null 2>&1 && cleanup_ok=false
  "${docker_cli[@]}" ps -a --filter "label=com.docker.compose.project=$project" --format '{{.ID}}' | grep -q . && cleanup_ok=false
  rm -rf -- "$runtime"
  if (( status == 0 )) && [[ "$cleanup_ok" == true ]]; then
    printf 'exact_cleanup=completed\n' >> "$success_evidence"
  elif (( status == 0 )); then
    echo "exact cleanup failed" >&2
    status=1
  fi
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

PYTHONPATH="$stage_root/src" python3 "$stage_root/deploy/local/synthetic/prepare_synthetic_non_phi_only.py" --output-root "$runtime" --project-name "$project" --policy-output "$stage_root/policy/generated"
for volume in "${external[@]}"; do "${docker_cli[@]}" volume create "$volume" >/dev/null; done

copy_volume() {
  local volume="$1" source="$2" uid="$3" gid="$4"
  [[ "$windows_cli" == true ]] && source="$(wslpath -w "$source")"
  "${docker_cli[@]}" run --rm --network none --mount "type=volume,source=$volume,target=/dest" --mount "type=bind,source=$source,target=/src,readonly" alpine:3.20.3 sh -ec "cp -a /src/. /dest/; chown -R $uid:$gid /dest; find /dest -type f -exec chmod 0600 {} +"
}
copy_volume "${project}_conversation_authorization" "$runtime/conversation-authorization" 10006 20001
copy_volume "${project}_gateway_authorization" "$runtime/gateway-authorization" 10005 20002
copy_volume "${project}_conversation_keys" "$runtime/conversation-keys" 10006 20001
copy_volume "${project}_gateway_keys" "$runtime/gateway-keys" 10005 20002
copy_volume "${project}_postgres_admin_secret" "$runtime/postgres-admin-secret" 999 999
"${docker_cli[@]}" run --rm --network none --user 0:0 -v "$home_volume:/hermes-home" alpine:3.20.3 sh -ec 'install -d -o 10007 -g 20001 -m 0700 /hermes-home'

capture_conversation_readiness() {
  # Header/body bytes contain no turn content; retain them only on failed
  # startup so a contract failure is diagnosable without weakening it.
  mkdir -p "$failure_logs"
  "${docker_cli[@]}" run --rm --network none --user 10007:20001 --group-add 20000 \
    -v "$socket_volume:/run/restricted-inference:ro" --entrypoint python "${project}-conversation" \
    -c 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect("/run/restricted-inference/conversation.sock"); s.sendall(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n"); print(repr(b"".join(iter(lambda: s.recv(4096), b""))))' > "$failure_logs/conversation-readyz-response.txt" 2>&1 || true
}

wait_for_conversation_health() {
  local deadline=$((SECONDS + 75)) status
  while (( SECONDS < deadline )); do
    status="$("${compose[@]}" ps --format json conversation 2>/dev/null | sed -n 's/.*"Health":"\([^"]*\)".*/\1/p' | head -n 1)"
    if [[ "$status" == healthy ]]; then
      return 0
    fi
    if [[ "$status" == unhealthy ]]; then
      capture_conversation_readiness
      return 1
    fi
    sleep 2
  done
  capture_conversation_readiness
  return 1
}

"${compose[@]}" --profile synthetic-non-phi-only config >/dev/null
"${compose[@]}" --profile synthetic-non-phi-only build
"${compose[@]}" --profile synthetic-non-phi-only up -d synthetic-non-phi-only-broker
"${compose[@]}" up -d postgres gateway conversation
wait_for_conversation_health
"${compose[@]}" --profile synthetic-non-phi-only run --rm synthetic-non-phi-only-enable >/dev/null
"${docker_cli[@]}" image inspect "${project}-conversation" >/dev/null
"${docker_cli[@]}" build --build-arg "RUNTIME_BASE=${project}-conversation" -f "$client_dockerfile" -t "$client_image" "$hermes_build_context" >/dev/null

client_args=(--rm --network none --user 10007:20001 --group-add 20000 --read-only --tmpfs /tmp:mode=0700,uid=10007,gid=20001 --env HERMES_HOME=/hermes-home -v "$home_volume:/hermes-home" -v "$socket_volume:/run/restricted-inference:ro")
run_client() { "${docker_cli[@]}" run "${client_args[@]}" "$client_image" "$@"; }
expect_client_failure() {
  local expected_code="$1" expected_symbol="$2" output status
  shift 2
  if output="$(run_client "$@" 2>&1)"; then
    echo "restricted client unexpectedly succeeded" >&2
    exit 1
  else
    status=$?
  fi
  if [[ "$status" != "$expected_code" || "$output" != "$expected_symbol" ]]; then
    printf 'expected restricted failure code=%s symbol=%s; got code=%s symbol=%s\n' "$expected_code" "$expected_symbol" "$status" "$output" >&2
    exit 1
  fi
}
broker_count() { "${docker_cli[@]}" run --rm --network none -v "${project}_synthetic_non_phi_only_state:/state:ro" alpine:3.20.3 cat /state/broker-count; }
client_socket_identity() {
  "${docker_cli[@]}" run "${client_args[@]}" --entrypoint python "$client_image" -c 'import os,socket,stat,struct; p="/run/restricted-inference/conversation.sock"; info=os.lstat(p); sock=socket.socket(socket.AF_UNIX); sock.connect(p); pid,uid,gid=struct.unpack("3i",sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"))); print(f"path={info.st_uid}:{info.st_gid}:{stat.S_IMODE(info.st_mode):o} peer={pid}:{uid}:{gid}")'
}
epoch="$(sed -n 's/^RESTRICTED_POLICY_EPOCH=//p' "$runtime/.env.generated")"
digest="$(sed -n 's/^RESTRICTED_POLICY_DIGEST=//p' "$runtime/.env.generated")"

# The operator stopping pre-existing Hermes processes is an external
# precondition. The required flag below records that declaration only.
socket_identity="$(client_socket_identity)"
printf 'e2e_socket_identity=%s\n' "$socket_identity"
test "$socket_identity" = 'path=10006:20001:660 peer=0:10006:20001'
client_readiness="$("${docker_cli[@]}" run "${client_args[@]}" --entrypoint python "$client_image" -c "from hermes_cli.restricted_runtime import RestrictedUdsClient; print(RestrictedUdsClient().ready('$epoch', '$digest')['status'])")"
printf 'e2e_client_readiness=%s\n' "$client_readiness"
test "$client_readiness" = ready
printf 'e2e_step=policy-mismatch-control\n'
expect_client_failure 76 RESTRICTED_POLICY_MISMATCH restricted enable --policy-epoch "$epoch" --policy-digest "$(printf '0%.0s' {1..64})" --confirm-stopped
printf 'e2e_step=enable\n'
run_client restricted enable --policy-epoch "$epoch" --policy-digest "$digest" --confirm-stopped >/dev/null
printf 'e2e_step=doctor\n'
doctor="$(run_client restricted doctor)"
for claim in '"runtime_reachable":true' '"policy_bound":true' '"application_restricted":false' '"deployment_conformant":false' '"model_attested":false' '"phi_authorized":false'; do grep -Fq "$claim" <<<"$doctor"; done

"${docker_cli[@]}" run --rm --network none --entrypoint python "$client_image" -c 'from pathlib import Path; forbidden=("run_agent.py","model_tools.py","agent","plugins","tools","memory"); assert all(not (Path("/opt/hermes") / item).exists() for item in forbidden)'
marker='SYNTHETIC_NON_PHI_ONLY_HERMES_RESTRICTED_E2E'
printf 'e2e_step=three-uds-turn\n'
turn_started=$SECONDS
if ! response="$(printf '%s' "$marker" | "${docker_cli[@]}" run -i "${client_args[@]}" "$client_image" restricted run --stdin)"; then
  echo "restricted three-UDS turn failed" >&2
  exit 1
fi
turn_elapsed=$((SECONDS - turn_started))
test "$turn_elapsed" -le 40
test "$response" = 'SYNTHETIC_NON_PHI_ONLY response'
test "$(broker_count)" = 1
! "${docker_cli[@]}" run --rm --network none --user 0:0 -v "$home_volume:/hermes-home:ro" alpine:3.20.3 sh -ec "grep -R -F -- '$marker' /hermes-home >/dev/null 2>&1"

# The three controls below mutate only this fresh project and prove fail-closed
# handling through the same Hermes client, never a mock client.
"${compose[@]}" stop conversation
expect_client_failure 74 RESTRICTED_RUNTIME_UNAVAILABLE restricted doctor
"${compose[@]}" up -d --wait conversation
"${docker_cli[@]}" run --rm --network none --user 0:0 -v "$socket_volume:/run/restricted-inference" alpine:3.20.3 chmod 0600 /run/restricted-inference/conversation.sock
expect_client_failure 74 RESTRICTED_RUNTIME_UNAVAILABLE restricted doctor
"${docker_cli[@]}" run --rm --network none --user 0:0 -v "$socket_volume:/run/restricted-inference" alpine:3.20.3 chmod 0660 /run/restricted-inference/conversation.sock
run_client restricted doctor >/dev/null

"${compose[@]}" stop conversation
fake_code='import json,os,socket; p="/run/restricted-inference/conversation.sock"; os.unlink(p); s=socket.socket(socket.AF_UNIX); s.bind(p); os.chmod(p,0o660); s.listen(1); c,_=s.accept(); c.recv(65536); body=json.dumps({"schema_version":"restricted-conversation-readiness.v1","status":"ready","policy_epoch":"altered","policy_digest":"'"$digest"'","classification":"PHI","system_instruction_version":"restricted-phi-system.v1","allowed_modalities":["text"],"tools_allowed":False,"fallbacks":[],"max_provider_attempts":1,"streaming":False,"max_output_tokens":4096,"max_canonical_input_utf8_bytes":131072,"response_profile":"restricted-local-text-response.v1"},separators=(",",":")).encode(); c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+str(len(body)).encode()+b"\r\n\r\n"+body); c.close(); s.close()'
"${docker_cli[@]}" run -d --name "$fake_container" --network none --user 10006:20001 --group-add 20000 -v "$socket_volume:/run/restricted-inference" --entrypoint python "${project}-conversation" -c "$fake_code" >/dev/null
for _ in $(seq 1 20); do "${docker_cli[@]}" run --rm --network none --user 0:0 -v "$socket_volume:/run/restricted-inference:ro" alpine:3.20.3 test -S /run/restricted-inference/conversation.sock && break; sleep 1; done
expect_client_failure 76 RESTRICTED_POLICY_MISMATCH restricted doctor
"${docker_cli[@]}" wait "$fake_container" >/dev/null
"${docker_cli[@]}" rm "$fake_container" >/dev/null
"${compose[@]}" up -d --wait conversation
test "$(broker_count)" = 1

{
  printf 'runtime_head=%s\n' "$runtime_head"
  printf 'runtime_tree=%s\n' "$runtime_tree"
  printf 'runtime_stage_archive_sha256=%s\n' "$archive_sha256"
  printf 'runtime_stage=exact_git_head_lf_blob_export\n'
  printf 'hermes_head=%s\n' "$HERMES_HEAD"
  printf 'operator_stop_assertion=external_precondition\n'
  printf 'commands=enable,doctor,run--stdin,policy-mismatch,socket-absent,acl-denied,readiness-altered\n'
  printf 'three_uds_turn_seconds=%s\n' "$turn_elapsed"
  printf 'three_uds_committed=passed\n'
  printf 'normal_hermes_surface_absent=passed\n'
  printf 'marker_plaintext_absent_from_hermes_home=passed\n'
  printf 'nonclaims_false=passed\n'
  printf 'policy_mismatch_fail_closed=passed\n'
  printf 'socket_absent_fail_closed=passed\n'
  printf 'acl_denied_fail_closed=passed\n'
  printf 'readiness_altered_fail_closed=passed\n'
  printf 'model_attested=false\n'
  printf 'deployment_conformant=false\n'
  printf 'phi_authorized=false\n'
} > "$success_evidence"
echo "success evidence: $success_evidence"
