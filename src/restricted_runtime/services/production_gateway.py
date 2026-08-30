"""Fail-closed Cloud Run composition root for the sole Vertex-capable image."""
from __future__ import annotations
import os
from pathlib import Path
import google.auth
from google.auth.transport.requests import Request
from ..auth import production_authenticator
from ..google_kms import GoogleKmsHmacKey
from ..kms_config import parse_retired_versions
from ..gateway import Gateway
from ..policy import load_signed_policy
from ..policy_binding import require_policy_pair
from ..storage import PostgresLedger
from ..vertex import VertexClient
from .gateway_api import create_app
def required(name:str)->str:
    value=os.environ.get(name)
    if not value:raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value
def retired_versions(name:str,active_resource:str,active_version:str)->dict[tuple[str,str],str]:
    return parse_retired_versions(required(name),active_resource=active_resource,active_version=active_version)
class AccessToken:
    def __call__(self):
        credentials,_=google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"]);credentials.refresh(Request());return credentials.token
def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE","production")!="production":raise RuntimeError("synthetic composition is prohibited in production image")
    policy=load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")),Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")),required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    require_policy_pair(policy,epoch=required("RESTRICTED_POLICY_EPOCH"),digest=required("RESTRICTED_POLICY_DIGEST"))
    key_resource=required("RESTRICTED_GATEWAY_MAC_KEY_RESOURCE");key_version=required("RESTRICTED_GATEWAY_MAC_KEY_VERSION")
    key=GoogleKmsHmacKey(key_resource,key_version,retired_versions("RESTRICTED_GATEWAY_RETIRED_MAC_KEYS_JSON",key_resource,key_version))
    gateway=Gateway(policy,key,PostgresLedger(required("DATABASE_URL"),policy,key),VertexClient(policy,AccessToken()))
    return create_app(gateway,production_authenticator(audience=required("RESTRICTED_GATEWAY_AUDIENCE"),caller_principal=policy.values["gateway_invoker_principal"]))
app=build_app()
