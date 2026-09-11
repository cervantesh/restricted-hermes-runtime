#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
if [[ "${RESTRICTED_PUBLISHED_CANDIDATE:-}" == "1" && -z "${RESTRICTED_CLINICAL_ADAPTER_IMAGE_DIGEST:-}" ]]; then
  printf '%s\n' 'published candidate requires an immutable digest' >&2
  exit 64
fi
image="${RESTRICTED_CLINICAL_ADAPTER_IMAGE_DIGEST:-${RESTRICTED_CLINICAL_ADAPTER_IMAGE_TAG:-restricted-clinical-adapter-closure:sg-clinical-005}}"
if [[ -n "${RESTRICTED_CLINICAL_ADAPTER_IMAGE_DIGEST:-}" ]]; then
  if [[ "$image" != *@sha256:* ]]; then
    printf '%s\n' 'published clinical adapter subject must be immutable' >&2
    exit 64
  fi
  docker pull "$image"
else
  docker build -f Dockerfile.clinical-adapter -t "$image" .
fi
docker run --rm --network none --entrypoint python "$image" -c '
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
docker run --rm --network none --entrypoint python "$image" -c '
import os
import socket
from restricted_runtime.clinical_adapter import ClinicalAdapter, peer_uid, receive_one
from restricted_runtime.contracts import jcs_bytes

class Upstream:
    def request(self, path, body):
        assert path == "/api/restricted-hermes/clinical/next-appointment"
        return {"clinicTimezone": "America/New_York", "appointment": None, "responseDigest": "b" * 64}

listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind("/tmp/adapter-protocol.sock")
listener.listen(1)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect("/tmp/adapter-protocol.sock")
connection, _ = listener.accept()
body = jcs_bytes({"mattermostActorId": "actor000000000000000000000", "patientId": "123e4567-e89b-42d3-a456-426614174000", "requestId": "request_123", "integrationId": "hrh-mattermost-01", "clinicalPolicyId": "clinical-read-v1", "policyEpoch": "mattermost-e1", "policyDigest": "a" * 64})
client.sendall(b"POST /v1/clinical/query HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
client.shutdown(socket.SHUT_WR)
raw = receive_one(connection, timeout_seconds=2)
response = ClinicalAdapter(expected_ingress_uid=os.geteuid(), expected_clinical_timezone="America/New_York", upstream=Upstream()).handle(peer_uid(connection), raw)
assert response.startswith(b"HTTP/1.1 200 OK\r\n"), response
connection.close()
client.close()
listener.close()
os.unlink("/tmp/adapter-protocol.sock")
'
printf '%s\n' 'clinical adapter image closure: PASS'
