#!/usr/bin/env bash
# Real pinned-Ollama GPU witness. It accepts only synthetic, non-PHI content.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
project="${1:-}"
if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]{2,48}$ ]]; then echo "usage: $0 unique-project" >&2; exit 2; fi
model_store="${RESTRICTED_OLLAMA_MODEL_STORE:-/mnt/d/Ollama/models}"
if [[ ! -f "$model_store/manifests/registry.ollama.ai/library/qwen2.5/7b" ]]; then echo "required qwen2.5:7b model store is unavailable" >&2; exit 1; fi
if command -v docker.exe >/dev/null 2>&1 && docker.exe compose version >/dev/null 2>&1; then
  docker_cli=(docker.exe); compose_cli=(docker.exe compose); runtime_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/mnt/c/Temp}"; windows_cli=true
elif docker compose version >/dev/null 2>&1; then
  docker_cli=(docker); compose_cli=(docker compose); runtime_root="${RESTRICTED_SYNTHETIC_TMP_ROOT:-/tmp}"; windows_cli=false
else
  echo "Docker Compose is required" >&2; exit 1
fi
runtime="$(mktemp -d "$runtime_root/${project}.SYNTHETIC_NON_PHI_ONLY.XXXXXX")"
env_file="$runtime/.env.generated"; model_store_for_compose="$model_store"; build_root="$root"
if [[ "$windows_cli" == true ]]; then env_file="$(wslpath -w "$env_file")"; model_store_for_compose="$(wslpath -w "$model_store")"; build_root="$(wslpath -w "$root")"; fi
compose=("${compose_cli[@]}" --project-name "$project" --env-file "$env_file" -f deploy/local/compose.yaml -f deploy/local/compose.ollama-synthetic-non-phi-only.yaml)
external=("${project}_inference_sockets" "${project}_conversation_authorization" "${project}_gateway_authorization" "${project}_conversation_keys" "${project}_gateway_keys" "${project}_postgres_admin_secret")
cleanup() { local status=$?; set +e; if (( status != 0 )); then "${compose[@]}" ps -a; "${compose[@]}" logs --no-color --tail 100; fi; "${compose[@]}" --profile ollama-synthetic-non-phi-only down --volumes --remove-orphans; for volume in "${external[@]}"; do "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1 && "${docker_cli[@]}" volume rm "$volume"; done; "${docker_cli[@]}" image inspect "${project}-ollama-probe:latest" >/dev/null 2>&1 && "${docker_cli[@]}" image rm "${project}-ollama-probe:latest"; rm -rf -- "$runtime"; return "$status"; }
trap cleanup EXIT
echo "Target inventory before create:"; "${docker_cli[@]}" ps -a --filter "label=com.docker.compose.project=$project" --format '{{.ID}} {{.Names}} {{.Status}}'
for volume in "${external[@]}"; do if "${docker_cli[@]}" volume inspect "$volume" >/dev/null 2>&1; then echo "refusing pre-existing target volume: $volume" >&2; exit 1; fi; done
before_inventory="$(find "$model_store" -type f -printf '%s %p\n' | sort | sha256sum | awk '{print $1}')"
PYTHONPATH="$root/src" python3 "$root/deploy/local/synthetic/prepare_synthetic_non_phi_only.py" --output-root "$runtime" --project-name "$project" --policy-output "$root/policy/generated" --model-display-name qwen2.5:7b --model-sha256 845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e
printf 'RESTRICTED_OLLAMA_MODEL_STORE=%s\n' "$model_store_for_compose" >> "$runtime/.env.generated"
for volume in "${external[@]}"; do "${docker_cli[@]}" volume create "$volume" >/dev/null; done
copy() { local volume="$1" source="$2" uid="$3" gid="$4"; [[ "$windows_cli" == true ]] && source="$(wslpath -w "$source")"; "${docker_cli[@]}" run --rm --network none -v "$volume:/dest" -v "$source:/src:ro" alpine:3.20.3 sh -ec "cp -a /src/. /dest/; chown -R $uid:$gid /dest; find /dest -type f -exec chmod 0600 {} +"; }
copy "${project}_conversation_authorization" "$runtime/conversation-authorization" 10006 20001; copy "${project}_gateway_authorization" "$runtime/gateway-authorization" 10005 20002; copy "${project}_conversation_keys" "$runtime/conversation-keys" 10006 20001; copy "${project}_gateway_keys" "$runtime/gateway-keys" 10005 20002; copy "${project}_postgres_admin_secret" "$runtime/postgres-admin-secret" 999 999
"${compose[@]}" --profile ollama-synthetic-non-phi-only config >/dev/null
"${compose[@]}" --profile ollama-synthetic-non-phi-only build ollama-synthetic-non-phi-only-adapter
"${compose[@]}" --profile ollama-synthetic-non-phi-only up -d ollama-synthetic-non-phi-only ollama-synthetic-non-phi-only-adapter
# Bundle verification deliberately streams the 4.7 GB declared model blob before
# exposure. This is a readiness bound, distinct from the 40-second real request
# bound below; it does not weaken the inference deadline.
ready_started=$SECONDS; readiness_deadline=$((SECONDS + 180)); while ! "${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter test -S /run/restricted-inference/broker.sock >/dev/null 2>&1; do
  "${compose[@]}" ps --status exited --services | grep -Fxq ollama-synthetic-non-phi-only-adapter && { echo "adapter exited before verified warm-up" >&2; exit 1; }
  (( SECONDS < readiness_deadline )) || { echo "adapter did not bind after verified warm-up within 180 seconds" >&2; exit 1; }
  sleep 1
done; echo "verified_warmup_seconds=$((SECONDS - ready_started))"
test "$("${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter stat -c '%u:%g:%a' /run/restricted-inference/broker.sock)" = 10003:20003:660
"${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter sh -ec 'test "$(id -u)" = 10003 && test -r /models/manifests/registry.ollama.ai/library/qwen2.5/7b && test ! -S /var/run/docker.sock'
"${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter python -c 'import os; assert not any(k.upper() in {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"} for k in os.environ)'
! "${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter python -c 'import socket; socket.create_connection(("1.1.1.1",443),1)' >/dev/null 2>&1
! "${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter python -c 'import socket; socket.create_connection(("2606:4700:4700::1111",443),1)' >/dev/null 2>&1
! "${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter python -c 'import socket; socket.getaddrinfo("example.com",443)' >/dev/null 2>&1
"${compose[@]}" exec -T ollama-synthetic-non-phi-only-adapter python -c 'import socket; socket.create_connection(("127.0.0.1",11434),1)'
"${compose[@]}" exec -T ollama-synthetic-non-phi-only ollama ps | grep -Eqi 'gpu|100%'
"${compose[@]}" up -d --wait postgres gateway conversation
"${compose[@]}" exec -T -u 999:20004 postgres psql -h /run/restricted-postgres -U postgres -d restricted_runtime -v ON_ERROR_STOP=1 -c 'UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true' >/dev/null
"${docker_cli[@]}" build -f deploy/local/ollama/Dockerfile.probe -t "${project}-ollama-probe:latest" "$build_root" >/dev/null
request_started=$SECONDS; "${docker_cli[@]}" run --rm --network none --user 10007:20001 --group-add 20000 -v "${project}_inference_sockets:/run/restricted-inference:ro" "${project}-ollama-probe:latest"; request_elapsed=$((SECONDS - request_started)); (( request_elapsed <= 40 )) || { echo "real three-UDS request exceeded 40 seconds: ${request_elapsed}" >&2; exit 1; }; echo "three_uds_response_seconds=${request_elapsed}"
"${compose[@]}" exec -T -u 999:20004 postgres psql -h /run/restricted-postgres -U postgres -d restricted_runtime -v ON_ERROR_STOP=1 -c 'UPDATE inference_ledger.runtime_controls SET dispatch_enabled=false WHERE control_key=true' >/dev/null
test "$("${compose[@]}" exec -T -u 999:20004 postgres psql -h /run/restricted-postgres -U postgres -d restricted_runtime -Atqc 'SELECT dispatch_enabled FROM inference_ledger.runtime_controls WHERE control_key=true')" = f
after_inventory="$(find "$model_store" -type f -printf '%s %p\n' | sort | sha256sum | awk '{print $1}')"; test "$before_inventory" = "$after_inventory"
echo 'OLLAMA_SYNTHETIC_NON_PHI_ONLY E2E passed.'; echo 'model_attested=false deployment_conformant=false phi_authorized=false'
