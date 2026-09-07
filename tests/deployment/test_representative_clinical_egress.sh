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

cleanup() {
  for target in "${target_ids[@]:-}"; do docker network disconnect --force "$network" "$target" >/dev/null 2>&1 || true; done
  docker container rm --force "$sink" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ -f "$state/staging-state.json" ]]; then
    python "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" destroy >/dev/null 2>&1 || true
  fi
  if [[ "$passed" != 1 ]]; then rm -f "$receipt"; fi
  rmdir "$scratch" >/dev/null 2>&1 || true
}
trap cleanup EXIT

python "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" init >/dev/null
compose=(docker compose --env-file "$state/compose.env" --project-name "$project" --file "$runtime/tests/deployment/clinical-composed-e2e/compose.yaml" --file "$runtime/deploy/clinical-staging/compose.yaml")
if ! docker network create --ipv6 "$network" >/dev/null; then
  echo "representative-clinical-egress: SKIP controlled-ipv6-network-unavailable"
  exit 77
fi
docker run --detach --name "$sink" --network "$network" --network-alias controlled-probe --network-alias synthetic-metadata-probe nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284 >/dev/null
controlled_ipv4="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$sink")"
controlled_ipv6="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$sink")"
[[ -n "$controlled_ipv4" && -n "$controlled_ipv6" ]] || { echo "representative-clinical-egress: SKIP controlled-ipv6-address-unavailable"; exit 77; }

for service in ingress clinical-adapter; do
  target="$("${compose[@]}" ps --quiet "$service")"
  [[ "$target" =~ ^[a-f0-9]{12,64}$ ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
  target_ids+=("$target")
  docker network connect "$network" "$target"
  proof="$scratch/red-$service.json"
  set +e
  outcome="$(python "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --red-service "$service" --red-network "$network" --red-sink "$sink" --red-proof "$proof" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 2>/dev/null)"
  status=$?
  set -e
  if [[ "$status" != 3 || ! "$outcome" =~ ^representative-clinical-egress:\ RED-DETECTED\ proof_sha256=[a-f0-9]{64}$ || ! -f "$proof" ]]; then
    echo "representative-clinical-egress: DENIED" >&2
    exit 2
  fi
  docker network disconnect "$network" "$target"
done

docker container rm --force "$sink" >/dev/null
docker network rm "$network" >/dev/null
if docker container inspect "$sink" >/dev/null 2>&1 || docker network inspect "$network" >/dev/null 2>&1; then
  echo "representative-clinical-egress: DENIED" >&2
  exit 2
fi
python "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --red-ingress-proof "$scratch/red-ingress.json" --red-clinical-adapter-proof "$scratch/red-clinical-adapter.json" --cleanup-network "$network" --cleanup-sink "$sink" --controlled-ipv4 "$controlled_ipv4" --controlled-ipv6 "$controlled_ipv6" --controlled-dns controlled-probe --synthetic-metadata-dns synthetic-metadata-probe --controlled-port 80 --output "$receipt" >/dev/null
python "$collector" --verify "$receipt" --expected-head "$head" --expected-tree "$tree" >/dev/null
passed=1
printf 'representative-clinical-egress: PASS receipt_sha256=%s\n' "$(sha256sum "$receipt" | awk '{print $1}')"
