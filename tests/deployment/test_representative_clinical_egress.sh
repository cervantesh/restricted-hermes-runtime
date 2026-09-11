#!/usr/bin/env bash
# Real Linux witness: a disposable external network must make each restricted
# service reach a controlled sink, and its removal must restore the receipt.
set -euo pipefail

runtime="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
hrh_root="${1:?usage: $0 /absolute/path/to/Health-Record-Hub /absolute/path/to/receipt.json}"
receipt="${2:?usage: $0 /absolute/path/to/Health-Record-Hub /absolute/path/to/receipt.json}"
[[ "$(uname -s)" == "Linux" ]] || { echo "representative-clinical-egress: SKIP linux-required"; exit 77; }
[[ "$hrh_root" = /* && -d "$hrh_root/.git" ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
[[ "$receipt" = /* && ! -e "$receipt" && -d "$(dirname "$receipt")" ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
evidence_dir="$receipt.evidence"
diagnostic_dir="$receipt.diagnostic"
[[ ! -e "$evidence_dir" ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
[[ ! -e "$diagnostic_dir" ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
if command -v python3 >/dev/null 2>&1; then python_bin=python3
elif command -v python >/dev/null 2>&1; then python_bin=python
else echo "representative-clinical-egress: DENIED" >&2; exit 2
fi
"$python_bin" "$runtime/tools/p2_host_platform_admission.py" >/dev/null 2>&1 || {
  echo "representative-clinical-egress: DENIED class=unsupported-host" >&2
  exit 2
}
docker info >/dev/null 2>&1 || { echo "representative-clinical-egress: SKIP docker-unavailable"; exit 77; }

head="$(git -C "$runtime" rev-parse HEAD)"
tree="$(git -C "$runtime" rev-parse HEAD^{tree})"
project="clinicalstaginge$(date +%s%N)"
scratch="$(mktemp -d)"
state="$scratch/$project.synthetic-clinical-staging"
network="$project-egress-red"
sink="$project-egress-sink"
staging="$runtime/deploy/clinical-staging/clinical_staging.py"
collector="$runtime/tools/representative_clinical_egress.py"
target_ids=()
passed=0
phase=preflight
collector_class=not-applicable
cleanup_network_absent=false
cleanup_sink_absent=false
cleanup_state_absent=false

collector_class_from() {
  local outcome="$1"
  local candidate=unclassified
  if [[ "$outcome" =~ ^representative-clinical-egress:\ DENIED\ class=([a-z-]+(/[a-z0-9-]+)?)$ ]]; then
    candidate="${BASH_REMATCH[1]}"
  fi
  case "$candidate" in
    source-binding|marker-binding|proof-binding|image-binding|network-probe|cleanup|local-command|input|collector-generic|unclassified|\
    receipt-policy/source-marker|receipt-policy/marker-proof|receipt-policy/green-proof|receipt-policy/service-lookup|\
    receipt-policy/service-inspection|receipt-policy/service-observation|receipt-policy/red-proof|receipt-policy/cleanup|\
    receipt-policy/build|receipt-policy/output)
      printf '%s' "$candidate" ;;
    green-policy/target-denial|green-policy/controlled-sink|green-policy/public-dns-control|green-policy/fixed-shape|\
    green-policy/ingress-fixed-shape|green-policy/clinical-adapter-fixed-shape|\
    green-policy/ingress-target-public-dns|green-policy/clinical-adapter-target-public-dns|\
    green-policy/ingress-control-public-dns|green-policy/clinical-adapter-control-public-dns|\
    green-policy/ingress-target-metadata-ipv4|green-policy/clinical-adapter-target-metadata-ipv4|\
    green-policy/ingress-target-metadata-ipv6|green-policy/clinical-adapter-target-metadata-ipv6|\
    green-policy/ingress-control-metadata-ipv4|green-policy/clinical-adapter-control-metadata-ipv4|\
    green-policy/ingress-control-metadata-ipv6|green-policy/clinical-adapter-control-metadata-ipv6|\
    green-policy/ingress-metadata-ipv4-discrimination|green-policy/clinical-adapter-metadata-ipv4-discrimination|\
    green-policy/ingress-metadata-ipv6-attribution|green-policy/clinical-adapter-metadata-ipv6-attribution)
      printf '%s' "$candidate" ;;
    receipt-policy/verification-*)
      case "$candidate" in
        receipt-policy/verification-receipt-object|receipt-policy/verification-receipt-fields|\
        receipt-policy/verification-receipt-schema|receipt-policy/verification-runtime-head|\
        receipt-policy/verification-runtime-tree|receipt-policy/verification-staging-marker|\
        receipt-policy/verification-host-versions|receipt-policy/verification-docker-versions|\
        receipt-policy/verification-service-classes|receipt-policy/verification-witness-fields|\
        receipt-policy/verification-red-proof|receipt-policy/verification-green-proof|\
        receipt-policy/verification-green-probes|receipt-policy/verification-metadata-scope|\
        receipt-policy/verification-fixed|receipt-policy/verification-cleanup|\
        receipt-policy/verification-retained-proofs|receipt-policy/verification-unknown|\
        receipt-policy/verification-ingress-observation|receipt-policy/verification-ingress-image|\
        receipt-policy/verification-ingress-image-binding|receipt-policy/verification-ingress-networks|\
        receipt-policy/verification-ingress-proxy|receipt-policy/verification-ingress-controls|\
        receipt-policy/verification-ingress-denied-classes|receipt-policy/verification-ingress-denied-probe|\
        receipt-policy/verification-ingress-permitted-internal|receipt-policy/verification-ingress-denied-internal|\
        receipt-policy/verification-clinical-adapter-observation|receipt-policy/verification-clinical-adapter-image|\
        receipt-policy/verification-clinical-adapter-image-binding|receipt-policy/verification-clinical-adapter-networks|\
        receipt-policy/verification-clinical-adapter-proxy|receipt-policy/verification-clinical-adapter-controls|\
        receipt-policy/verification-clinical-adapter-denied-classes|receipt-policy/verification-clinical-adapter-denied-probe|\
        receipt-policy/verification-clinical-adapter-permitted-internal|receipt-policy/verification-clinical-adapter-denied-internal)
          printf '%s' "$candidate" ;;
        *) printf '%s' unclassified ;;
      esac ;;
    *) printf '%s' unclassified ;;
  esac
}

write_diagnostic() {
  local safe_phase="$phase"
  case "$safe_phase" in
    preflight|initialize|marker-proof|red-ingress|red-clinical-adapter|green-live-control|cleanup-proof|receipt|verify) ;;
    *) safe_phase=unknown ;;
  esac
  mkdir -m 0700 "$diagnostic_dir" 2>/dev/null || return 0
  local temporary="$diagnostic_dir/packet.json.tmp"
  (umask 077
    printf '{"schema":"restricted-runtime-representative-clinical-egress-diagnostic.v1","runtime":{"head":"%s","tree":"%s"},"phase":"%s","collector_error_class":"%s","cleanup":{"network_absent":%s,"sink_absent":%s,"state_absent":%s}}\n' \
      "$head" "$tree" "$safe_phase" "$collector_class" "$cleanup_network_absent" "$cleanup_sink_absent" "$cleanup_state_absent" > "$temporary"
    chmod 0600 "$temporary"
    mv -f "$temporary" "$diagnostic_dir/packet.json") || rm -f "$temporary"
}

exact_name_absent() {
  local resource="$1" name="$2" output listed
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 1
  case "$resource" in
    network)
      if ! output="$(docker network ls --format '{{.Name}}' 2>/dev/null)"; then return 1; fi ;;
    container)
      if ! output="$(docker container ls --all --format '{{.Names}}' 2>/dev/null)"; then return 1; fi ;;
    *) return 1 ;;
  esac
  [[ -z "$output" ]] && return 0
  while IFS= read -r listed || [[ -n "$listed" ]]; do
    [[ "$listed" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 1
    [[ "$listed" != "$name" ]] || return 1
  done <<< "$output"
}

cleanup() {
  for target in "${target_ids[@]:-}"; do docker network disconnect --force "$network" "$target" >/dev/null 2>&1 || true; done
  docker container rm --force "$sink" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ -f "$state/staging-state.json" ]]; then
    "$python_bin" "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" destroy >/dev/null 2>&1 || true
  fi
  if exact_name_absent network "$network"; then cleanup_network_absent=true; fi
  if exact_name_absent container "$sink"; then cleanup_sink_absent=true; fi
  if [[ ! -e "$state" ]]; then cleanup_state_absent=true; fi
  if [[ "$passed" != 1 ]]; then
    rm -f "$receipt"; rm -rf "$evidence_dir"
    write_diagnostic
    printf 'representative-clinical-egress: DENIED phase=%s\n' "$phase" >&2
  fi
  rmdir "$scratch" >/dev/null 2>&1 || true
}
trap cleanup EXIT
mkdir -m 0700 "$evidence_dir"

phase=initialize
"$python_bin" "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" init >/dev/null 2>&1
compose=(docker compose --env-file "$state/compose.env" --project-name "$project" --file "$runtime/tests/deployment/clinical-composed-e2e/compose.yaml" --file "$runtime/deploy/clinical-staging/compose.yaml")
if ! docker network create --ipv6 "$network" >/dev/null; then
  echo "representative-clinical-egress: SKIP controlled-ipv6-network-unavailable"
  exit 77
fi
docker run --detach --name "$sink" --network "$network" --network-alias controlled-probe --network-alias synthetic-metadata-probe nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284 >/dev/null
controlled_ipv4="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$sink")"
controlled_ipv6="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$sink")"
[[ -n "$controlled_ipv4" && -n "$controlled_ipv6" ]] || { echo "representative-clinical-egress: SKIP controlled-ipv6-address-unavailable"; exit 77; }
phase=marker-proof
set +e
outcome="$("$python_bin" "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --marker-proof "$evidence_dir/marker.json" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 2>&1)"
status=$?
set -e
if [[ "$status" != 5 || ! "$outcome" =~ ^representative-clinical-egress:\ MARKER-PROVED\ proof_sha256=[a-f0-9]{64}$ || ! -f "$evidence_dir/marker.json" ]]; then
  collector_class="$(collector_class_from "$outcome")"
  echo "representative-clinical-egress: DENIED" >&2
  exit 2
fi

for service in ingress clinical-adapter; do
  phase="red-$service"
  target="$("${compose[@]}" ps --quiet "$service")"
  [[ "$target" =~ ^[a-f0-9]{12,64}$ ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
  target_ids+=("$target")
  docker network connect "$network" "$target"
  proof="$evidence_dir/red-$service.json"
  set +e
  outcome="$("$python_bin" "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --marker-proof "$evidence_dir/marker.json" --red-service "$service" --red-network "$network" --red-sink "$sink" --red-proof "$proof" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 2>&1)"
  status=$?
  set -e
  if [[ "$status" != 3 || ! "$outcome" =~ ^representative-clinical-egress:\ RED-DETECTED\ proof_sha256=[a-f0-9]{64}$ || ! -f "$proof" ]]; then
    collector_class="$(collector_class_from "$outcome")"
    echo "representative-clinical-egress: DENIED" >&2
    exit 2
  fi
  docker network disconnect "$network" "$target"
done

phase=green-live-control
set +e
outcome="$("$python_bin" "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --marker-proof "$evidence_dir/marker.json" --green-proof "$evidence_dir/green.json" --control-network "$network" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 2>&1)"
status=$?
set -e
if [[ "$status" != 4 || ! "$outcome" =~ ^representative-clinical-egress:\ GREEN-PROVED\ proof_sha256=[a-f0-9]{64}$ || ! -f "$evidence_dir/green.json" ]]; then
  collector_class="$(collector_class_from "$outcome")"
  echo "representative-clinical-egress: DENIED" >&2
  exit 2
fi
docker container rm --force "$sink" >/dev/null
docker network rm "$network" >/dev/null
phase=cleanup-proof
if ! exact_name_absent container "$sink" || ! exact_name_absent network "$network"; then
  echo "representative-clinical-egress: DENIED" >&2
  exit 2
fi
phase=receipt
set +e
outcome="$("$python_bin" "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --marker-proof "$evidence_dir/marker.json" --red-ingress-proof "$evidence_dir/red-ingress.json" --red-clinical-adapter-proof "$evidence_dir/red-clinical-adapter.json" --green-proof "$evidence_dir/green.json" --cleanup-network "$network" --cleanup-sink "$sink" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 --output "$receipt" 2>&1 >/dev/null)"
status=$?
set -e
if [[ "$status" != 0 ]]; then
  collector_class="$(collector_class_from "$outcome")"
  exit 2
fi
phase=verify
set +e
outcome="$("$python_bin" "$collector" --verify "$receipt" --expected-head "$head" --expected-tree "$tree" --evidence-dir "$evidence_dir" 2>&1 >/dev/null)"
status=$?
set -e
if [[ "$status" != 0 ]]; then
  collector_class="$(collector_class_from "$outcome")"
  exit 2
fi
passed=1
printf 'representative-clinical-egress: PASS receipt_sha256=%s\n' "$(sha256sum "$receipt" | awk '{print $1}')"
