#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
tag="${RESTRICTED_MATTERMOST_IMAGE_TAG:-restricted-mattermost-ingress-closure:sg-mattermost-004}"

docker build -f Dockerfile.mattermost-ingress -t "$tag" .
docker run --rm --network none --entrypoint python "$tag" -c '
import importlib
import importlib.util
from pathlib import Path

allowed = (
    "restricted_runtime.contracts",
    "restricted_runtime.mattermost_policy",
    "restricted_runtime.mattermost_ingress",
    "restricted_runtime.services.production_mattermost_ingress",
)
for name in allowed:
    importlib.import_module(name)

forbidden = (
    "restricted_runtime.auth",
    "restricted_runtime.conversation",
    "restricted_runtime.conversation_storage",
    "restricted_runtime.crypto",
    "restricted_runtime.gateway",
    "restricted_runtime.gateway_client",
    "restricted_runtime.gateway_contracts",
    "restricted_runtime.google_kms",
    "restricted_runtime.kms_config",
    "restricted_runtime.local_crypto",
    "restricted_runtime.local_deployment_preflight",
    "restricted_runtime.local_gateway_client",
    "restricted_runtime.local_probe_receipt",
    "restricted_runtime.local_uds",
    "restricted_runtime.messages",
    "restricted_runtime.migration_runner",
    "restricted_runtime.migration_supervisor",
    "restricted_runtime.operator_authorization",
    "restricted_runtime.policy",
    "restricted_runtime.policy_binding",
    "restricted_runtime.reconciliation",
    "restricted_runtime.reconciliation_driver",
    "restricted_runtime.storage",
    "restricted_runtime.uds_entrypoint",
    "restricted_runtime.vertex",
    "restricted_runtime.services.gateway_api",
    "restricted_runtime.services.production_conversation",
    "restricted_runtime.services.production_gateway",
    "restricted_runtime.services.production_local_conversation",
    "restricted_runtime.services.production_local_gateway",
    "run_agent",
    "agent",
    "cli",
    "gateway",
    "model_tools",
    "plugins",
    "tools",
    "fastapi",
    "uvicorn",
    "psycopg",
)
present = [name for name in forbidden if importlib.util.find_spec(name) is not None]
assert not present, present

root = Path(importlib.import_module("restricted_runtime").__file__).parent
files = {path.relative_to(root).as_posix() for path in root.rglob("*.py")}
assert files == {
    "__init__.py",
    "contracts.py",
    "mattermost_policy.py",
    "mattermost_ingress.py",
    "services/production_mattermost_ingress.py",
}, files
'
printf '%s\n' 'mattermost ingress image closure: PASS'
