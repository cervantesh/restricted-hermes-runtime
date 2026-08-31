"""Create disposable SYNTHETIC_NON_PHI_ONLY artifacts for the opt-in E2E only."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from restricted_runtime.contracts import jcs_bytes  # noqa: E402
from restricted_runtime.local_crypto import (  # noqa: E402
    LocalKeyRef,
    conversation_keyset_digest,
    keyset_digest,
)
from restricted_runtime.policy import PolicyBundle  # noqa: E402


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return hashlib.sha256(data).hexdigest()


def _public(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--policy-output", type=Path, default=ROOT / "policy" / "generated")
    args = parser.parse_args()
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,48}", args.project_name) is None:
        raise SystemExit("synthetic project name rejected")
    output = args.output_root.resolve()
    if ROOT == output or ROOT in output.parents:
        raise SystemExit("synthetic private artifacts must remain outside the repository")

    model_digest = hashlib.sha256(b"SYNTHETIC_NON_PHI_ONLY_BROKER").hexdigest()
    policy_private = Ed25519PrivateKey.generate()
    auth_private = Ed25519PrivateKey.generate()
    values = json.loads((ROOT / "policy" / "local.policy.template.json").read_text(encoding="utf-8"))
    values.update({
        "policy_epoch": "synthetic-non-phi-only-e1",
        "tenant_id": "synthetic-non-phi-only-tenant",
        "external_runner_principal": "synthetic-non-phi-only-runner",
        "gateway_invoker_principal": "synthetic-non-phi-only-gateway",
        "model": "SYNTHETIC_NON_PHI_ONLY_BROKER",
        "model_sha256": model_digest,
    })
    canonical_policy = jcs_bytes(values)
    policy = PolicyBundle(values, hashlib.sha256(canonical_policy).hexdigest())
    policy.validate()
    args.policy_output.mkdir(parents=True, exist_ok=True)
    (args.policy_output / "policy.json").write_bytes(canonical_policy)
    (args.policy_output / "policy.sig").write_text(base64.b64encode(policy_private.sign(canonical_policy)).decode("ascii"), encoding="ascii")

    empty_digest = hashlib.sha256(b"[]").hexdigest()
    conversation = output / "conversation-keys"
    gateway = output / "gateway-keys"
    service_digest = _write(conversation / "service-mac.key", secrets.token_bytes(32))
    wrap_digest = _write(conversation / "content-wrap.key", secrets.token_bytes(32))
    gateway_digest = _write(gateway / "gateway-mac.key", secrets.token_bytes(32))
    _write(conversation / "service-retired.json", b"[]")
    _write(conversation / "content-retired.json", b"[]")
    _write(gateway / "gateway-retired.json", b"[]")
    service_ref = LocalKeyRef("synthetic-service-mac", "v1", "/run/restricted-keys/service-mac.key", service_digest)
    wrap_ref = LocalKeyRef("synthetic-content-wrap", "v1", "/run/restricted-keys/content-wrap.key", wrap_digest)
    gateway_ref = LocalKeyRef("synthetic-gateway-mac", "v1", "/run/restricted-keys/gateway-mac.key", gateway_digest)
    gateway_keyset = keyset_digest("gateway-mac", gateway_ref)
    conversation_keyset = conversation_keyset_digest(keyset_digest("service-mac", service_ref), keyset_digest("content-wrap", wrap_ref))

    now = datetime.now(UTC) - timedelta(minutes=1)
    authorization = {
        "schema_version": "restricted-operator-authorization.v1",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "tenant_id": values["tenant_id"],
        "provider": "local-uds",
        "model_sha256": model_digest,
        "gateway_keyset_sha256": gateway_keyset,
        "conversation_keyset_sha256": conversation_keyset,
        "permitted_use_id": "SYNTHETIC_NON_PHI_ONLY_E2E",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
    }
    auth_bytes = jcs_bytes(authorization)
    auth_signature = base64.b64encode(auth_private.sign(auth_bytes))
    auth_digest = hashlib.sha256(auth_bytes).hexdigest()
    auth_signature_digest = hashlib.sha256(auth_signature).hexdigest()
    for role in ("conversation", "gateway"):
        target = output / f"{role}-authorization"
        _write(target / "authorization.json", auth_bytes)
        _write(target / "authorization.sig", auth_signature)
    _write(output / "postgres-admin-secret" / "password", secrets.token_urlsafe(32).encode())

    prefix = args.project_name
    env = {
        "RESTRICTED_INFERENCE_VOLUME": f"{prefix}_inference_sockets",
        "RESTRICTED_CONVERSATION_AUTHORIZATION_VOLUME": f"{prefix}_conversation_authorization",
        "RESTRICTED_GATEWAY_AUTHORIZATION_VOLUME": f"{prefix}_gateway_authorization",
        "RESTRICTED_CONVERSATION_KEYS_VOLUME": f"{prefix}_conversation_keys",
        "RESTRICTED_GATEWAY_KEYS_VOLUME": f"{prefix}_gateway_keys",
        "RESTRICTED_POSTGRES_ADMIN_SECRET_VOLUME": f"{prefix}_postgres_admin_secret",
        "RESTRICTED_POLICY_PUBLIC_KEY_B64": _public(policy_private),
        "RESTRICTED_POLICY_EPOCH": policy.epoch,
        "RESTRICTED_POLICY_DIGEST": policy.digest,
        "RESTRICTED_OPERATOR_AUTHORIZATION_PUBLIC_KEY_B64": _public(auth_private),
        "RESTRICTED_OPERATOR_AUTHORIZATION_SHA256": auth_digest,
        "RESTRICTED_OPERATOR_AUTHORIZATION_SIGNATURE_SHA256": auth_signature_digest,
        "RESTRICTED_LOCAL_GATEWAY_MAC_KEY_RESOURCE": gateway_ref.key_resource,
        "RESTRICTED_LOCAL_GATEWAY_MAC_KEY_VERSION": gateway_ref.key_version,
        "RESTRICTED_LOCAL_GATEWAY_MAC_KEY_SHA256": gateway_digest,
        "RESTRICTED_LOCAL_GATEWAY_RETIRED_MAC_KEYS_SHA256": empty_digest,
        "RESTRICTED_LOCAL_CONVERSATION_KEYSET_SHA256": conversation_keyset,
        "RESTRICTED_LOCAL_SERVICE_MAC_KEY_RESOURCE": service_ref.key_resource,
        "RESTRICTED_LOCAL_SERVICE_MAC_KEY_VERSION": service_ref.key_version,
        "RESTRICTED_LOCAL_SERVICE_MAC_KEY_SHA256": service_digest,
        "RESTRICTED_LOCAL_SERVICE_MAC_KEY_RETIRED_KEYS_SHA256": empty_digest,
        "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_RESOURCE": wrap_ref.key_resource,
        "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_VERSION": wrap_ref.key_version,
        "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_SHA256": wrap_digest,
        "RESTRICTED_LOCAL_CONTENT_WRAP_KEY_RETIRED_KEYS_SHA256": empty_digest,
        "RESTRICTED_LOCAL_GATEWAY_KEYSET_SHA256": gateway_keyset,
        "RESTRICTED_ADMISSION_ENABLED": "true",
        "RESTRICTED_TENANT_ID": values["tenant_id"],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / ".env.generated").write_text("".join(f"{key}={value}\n" for key, value in env.items()), encoding="utf-8")
    (output / ".env.generated").chmod(0o600)
    print("SYNTHETIC_NON_PHI_ONLY artifacts prepared; they are not PHI authorization.")


if __name__ == "__main__":
    main()
