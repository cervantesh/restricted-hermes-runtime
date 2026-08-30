"""Fail-closed Cloud Run composition root for the sole Vertex-capable image."""
from __future__ import annotations
import os
import json
from pathlib import Path
import google.auth
from google.auth.transport.requests import Request
from ..auth import production_authenticator
from ..google_kms import GoogleKmsHmacKey
from ..gateway import Gateway
from ..policy import load_signed_policy
from ..storage import PostgresLedger
from ..vertex import VertexClient
from .gateway_api import create_app
def required(name:str)->str:
    value=os.environ.get(name)
    if not value:raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value
def retired_versions(name:str)->dict[tuple[str,str],str]:
    try:parsed=json.loads(required(name))
    except (ValueError,TypeError) as exc:raise RuntimeError("retired KMS map must be closed JSON") from exc
    if not isinstance(parsed,list):raise RuntimeError("retired KMS map must be an array")
    result={}
    for item in parsed:
        if not isinstance(item,dict) or set(item)!={"key_resource","key_version","verify_version"} or not all(isinstance(item[k],str) and item[k] for k in item):raise RuntimeError("invalid retired KMS map")
        key=(item["key_resource"],item["key_version"])
        if key in result:raise RuntimeError("duplicate retired KMS map")
        result[key]=item["verify_version"]
    return result
class AccessToken:
    def __call__(self):
        credentials,_=google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"]);credentials.refresh(Request());return credentials.token
def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE","production")!="production":raise RuntimeError("synthetic composition is prohibited in production image")
    policy=load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")),Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")),required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    key=GoogleKmsHmacKey(required("RESTRICTED_GATEWAY_MAC_KEY_RESOURCE"),required("RESTRICTED_GATEWAY_MAC_KEY_VERSION"),retired_versions("RESTRICTED_GATEWAY_RETIRED_MAC_KEYS_JSON"))
    gateway=Gateway(policy,key,PostgresLedger(required("DATABASE_URL"),policy,key),VertexClient(policy,AccessToken()))
    return create_app(gateway,production_authenticator(audience=required("RESTRICTED_GATEWAY_AUDIENCE"),caller_principal=policy.values["caller_principal"]))
app=build_app()
