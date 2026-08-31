"""Self-hosted conversation root: local files, PostgreSQL, and AF_UNIX only."""
from __future__ import annotations
import os
from pathlib import Path
from ..auth import LocalSocketAuthenticator
from ..conversation import ConversationService
from ..gateway import Gateway
from ..local_crypto import LocalAesDataKeyWrapper, LocalFileHmacKey, LocalKeyRef, load_retired_key_refs
from ..local_uds import LocalUdsClient
from ..operator_authorization import OperatorAuthorizationGate
from ..policy import LOCAL_POLICY_SCHEMA, load_signed_policy
from ..policy_binding import require_policy_pair
from ..storage import PostgresContentStore, PostgresLedger
from .restricted_api import create_app

def required(name: str) -> str:
    value = os.environ.get(name)
    if not value: raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value
def ref(prefix: str) -> LocalKeyRef:
    return LocalKeyRef(required(prefix+"_RESOURCE"), required(prefix+"_VERSION"), required(prefix+"_PATH"))
def retired(prefix: str): return load_retired_key_refs(required(prefix+"_RETIRED_KEYS_PATH"))
def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE", "production") != "production": raise RuntimeError("synthetic composition is prohibited in production image")
    policy=load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")),Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")),required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA: raise RuntimeError("local conversation root requires local-uds policy")
    require_policy_pair(policy,epoch=required("RESTRICTED_POLICY_EPOCH"),digest=required("RESTRICTED_POLICY_DIGEST"))
    authority=OperatorAuthorizationGate(Path(required("RESTRICTED_OPERATOR_AUTHORIZATION_PATH")),Path(required("RESTRICTED_OPERATOR_AUTHORIZATION_SIGNATURE_PATH")),required("RESTRICTED_OPERATOR_AUTHORIZATION_PUBLIC_KEY_B64"),policy); authority()
    admission=required("RESTRICTED_ADMISSION_ENABLED")
    if admission not in {"true","false"}: raise RuntimeError("RESTRICTED_ADMISSION_ENABLED must be true or false")
    service=LocalFileHmacKey(ref("RESTRICTED_LOCAL_SERVICE_MAC_KEY"),retired("RESTRICTED_LOCAL_SERVICE_MAC_KEY"))
    gateway_key=LocalFileHmacKey(ref("RESTRICTED_LOCAL_GATEWAY_MAC_KEY"),retired("RESTRICTED_LOCAL_GATEWAY_MAC_KEY"))
    wrapper=LocalAesDataKeyWrapper(ref("RESTRICTED_LOCAL_CONTENT_WRAP_KEY"),retired("RESTRICTED_LOCAL_CONTENT_WRAP_KEY"))
    gateway=Gateway(policy,gateway_key,PostgresLedger(required("DATABASE_URL"),policy,gateway_key),LocalUdsClient(policy),admission_enabled=admission=="true",authorization_gate=authority)
    runtime=ConversationService(PostgresContentStore(required("DATABASE_URL")),gateway,service,wrapper,policy,required("RESTRICTED_TENANT_ID"),admission_enabled=admission=="true")
    return create_app(runtime,LocalSocketAuthenticator(policy.values["external_runner_principal"]),lambda: True)
app=build_app()
