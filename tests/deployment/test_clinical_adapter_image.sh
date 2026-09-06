#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
tag="${RESTRICTED_CLINICAL_ADAPTER_IMAGE_TAG:-restricted-clinical-adapter-closure:sg-clinical-005}"

docker build -f Dockerfile.clinical-adapter -t "$tag" .
docker run --rm --network none --entrypoint python "$tag" -c '
import importlib
import importlib.util
from pathlib import Path

allowed = (
    "restricted_runtime.contracts",
    "restricted_runtime.upstream_deadline",
    "restricted_runtime.clinical_adapter",
    "restricted_runtime.services.production_clinical_adapter",
)
for name in allowed:
    importlib.import_module(name)

forbidden = (
    "restricted_runtime.mattermost_ingress", "restricted_runtime.gateway",
    "restricted_runtime.vertex", "restricted_runtime.storage",
    "restricted_runtime.conversation", "restricted_runtime.crypto",
    "run_agent", "tools", "plugins", "fastapi", "uvicorn", "psycopg",
)
present = [name for name in forbidden if importlib.util.find_spec(name) is not None]
assert not present, present

root = Path(importlib.import_module("restricted_runtime").__file__).parent
files = {path.relative_to(root).as_posix() for path in root.rglob("*.py")}
assert files == {
    "__init__.py", "contracts.py", "upstream_deadline.py", "clinical_adapter.py",
    "services/production_clinical_adapter.py",
}, files
'
printf '%s\n' 'clinical adapter image closure: PASS'
