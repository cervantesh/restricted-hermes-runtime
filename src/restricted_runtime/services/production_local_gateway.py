"""Fail-closed composition root for the separate self-hosted local-UDS image."""
from __future__ import annotations

import os
from pathlib import Path

from ..auth import LocalSocketAuthenticator
from ..gateway import Gateway
from ..local_uds import LocalUdsClient
from ..local_crypto import LocalFileHmacKey, LocalKeyRef, keyset_digest, load_retired_key_refs
from ..operator_authorization import OperatorAuthorizationGate
from ..policy import LOCAL_POLICY_SCHEMA, load_signed_policy
from ..policy_binding import require_policy_pair
from ..storage import PostgresLedger
from .gateway_api import create_app


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value


def local_ref(prefix: str) -> LocalKeyRef:
    return LocalKeyRef(required(prefix + "_RESOURCE"), required(prefix + "_VERSION"), required(prefix + "_PATH"), required(prefix + "_SHA256"))


def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE", "production") != "production":
        raise RuntimeError("synthetic composition is prohibited in production image")
    policy = load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")), Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")), required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA:
        raise RuntimeError("local production root requires local-uds policy")
    require_policy_pair(policy, epoch=required("RESTRICTED_POLICY_EPOCH"), digest=required("RESTRICTED_POLICY_DIGEST"))
    active = local_ref("RESTRICTED_LOCAL_GATEWAY_MAC_KEY"); retired = load_retired_key_refs(required("RESTRICTED_LOCAL_GATEWAY_RETIRED_MAC_KEYS_PATH"))
    authorization = OperatorAuthorizationGate(Path(required("RESTRICTED_OPERATOR_AUTHORIZATION_PATH")), Path(required("RESTRICTED_OPERATOR_AUTHORIZATION_SIGNATURE_PATH")), required("RESTRICTED_OPERATOR_AUTHORIZATION_PUBLIC_KEY_B64"), policy, gateway_keyset_sha256=keyset_digest("gateway-mac",(active,*retired)), conversation_keyset_sha256=required("RESTRICTED_LOCAL_CONVERSATION_KEYSET_SHA256"))
    authorization()
    admission = required("RESTRICTED_ADMISSION_ENABLED")
    if admission not in {"true", "false"}:
        raise RuntimeError("RESTRICTED_ADMISSION_ENABLED must be true or false")
    key = LocalFileHmacKey(active, retired)
    gateway = Gateway(policy, key, PostgresLedger(required("DATABASE_URL"), policy, key), LocalUdsClient(policy), admission_enabled=admission == "true", authorization_gate=authorization)
    return create_app(gateway, LocalSocketAuthenticator(policy.values["gateway_invoker_principal"]))


app = build_app()
