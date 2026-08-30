"""Fail-closed Cloud Run composition root for the conversation image."""
from __future__ import annotations
import os
from pathlib import Path
from ..auth import production_authenticator
from ..conversation import ConversationService
from ..gateway_client import HttpGatewayClient
from ..google_kms import GoogleKmsDataKeyWrapper,GoogleKmsHmacKey
from ..policy import load_signed_policy
from ..storage import PostgresContentStore
from .restricted_api import create_app

def required(name:str)->str:
    value=os.environ.get(name)
    if not value:raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value
def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE","production")!="production":raise RuntimeError("synthetic composition is prohibited in production image")
    policy=load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")),Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")),required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    if policy.values["tenant_id"]!=required("RESTRICTED_TENANT_ID"):raise RuntimeError("policy tenant mismatch")
    active=GoogleKmsHmacKey(required("RESTRICTED_SERVICE_MAC_KEY_RESOURCE"),required("RESTRICTED_SERVICE_MAC_KEY_VERSION"),{})
    runtime=ConversationService(PostgresContentStore(required("DATABASE_URL")),HttpGatewayClient(required("RESTRICTED_GATEWAY_URL"),required("RESTRICTED_GATEWAY_AUDIENCE")),active,GoogleKmsDataKeyWrapper(required("RESTRICTED_CONTENT_WRAP_KEY")),policy,required("RESTRICTED_TENANT_ID"))
    return create_app(runtime,production_authenticator(audience=required("RESTRICTED_EXTERNAL_AUDIENCE"),caller_principal=required("RESTRICTED_CALLER_PRINCIPAL")))
app=build_app()
