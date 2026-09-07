#!/usr/bin/env bash
# Real Linux witness: a disposable external network must make each restricted
# service reach a controlled sink, and its removal must restore the receipt.
set -euo pipefail

runtime="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
hrh_root="${1:?usage: $0 /absolute/path/to/Health-Record-Hub}"
[[ "$(uname -s)" == "Linux" ]] || { echo "representative-clinical-egress: SKIP linux-required"; exit 77; }
[[ "$hrh_root" = /* && -d "$hrh_root/.git" ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "representative-clinical-egress: SKIP docker-unavailable"; exit 77; }

head="$(git -C "$runtime" rev-parse HEAD)"
tree="$(git -C "$runtime" rev-parse HEAD^{tree})"
project="clinicalstaginge$(date +%s)"
scratch="$(mktemp -d)"
state="$scratch/$project.synthetic-clinical-staging"
network="$project-egress-red"
sink="$project-egress-sink"
receipt="$scratch/receipt.json"
staging="$runtime/deploy/clinical-staging/clinical_staging.py"
collector="$runtime/tools/representative_clinical_egress.py"
target_ids=()

cleanup() {
  for target in "${target_ids[@]:-}"; do docker network disconnect --force "$network" "$target" >/dev/null 2>&1 || true; done
  docker container rm --force "$sink" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ -f "$state/staging-state.json" ]]; then
    python "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" destroy >/dev/null 2>&1 || true
  fi
  rm -f "$receipt"
  rmdir "$scratch" >/dev/null 2>&1 || true
}
trap cleanup EXIT

python "$staging" --runtime-root "$runtime" --hrh-root "$hrh_root" --state-dir "$state" --project "$project" init >/dev/null
compose=(docker compose --env-file "$state/compose.env" --project-name "$project" --file "$runtime/tests/deployment/clinical-composed-e2e/compose.yaml" --file "$runtime/deploy/clinical-staging/compose.yaml")
docker network create "$network" >/dev/null
docker run --detach --name "$sink" --network "$network" nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284 >/dev/null

for service in ingress clinical-adapter; do
  target="$("${compose[@]}" ps --quiet "$service")"
  [[ "$target" =~ ^[a-f0-9]{12,64}$ ]] || { echo "representative-clinical-egress: DENIED" >&2; exit 2; }
  target_ids+=("$target")
  docker network connect "$network" "$target"
  if python "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --red-service "$service" --red-host "$sink" --red-port 80 --output "$receipt" >/dev/null 2>&1; then
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
python "$collector" --runtime-root "$runtime" --state-dir "$state" --project "$project" --expected-head "$head" --expected-tree "$tree" --red-detected --cleanup-complete --cleanup-network "$network" --cleanup-sink "$sink" --output "$receipt" >/dev/null
python "$collector" --verify "$receipt" --expected-head "$head" --expected-tree "$tree" >/dev/null
printf 'representative-clinical-egress: PASS receipt_sha256=%s\n' "$(sha256sum "$receipt" | awk '{print $1}')"
