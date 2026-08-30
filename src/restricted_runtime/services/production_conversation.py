"""Fail-closed Cloud Run composition root for the conversation image."""
from __future__ import annotations
import os
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from ..auth import production_authenticator
from ..conversation import ConversationService
from ..gateway_client import HttpGatewayClient
from ..google_kms import GoogleKmsDataKeyWrapper,GoogleKmsHmacKey
from ..kms_config import parse_retired_versions
from ..policy import load_signed_policy
from ..storage import PostgresContentStore
from ..reconciliation import Reconciler
from ..reconciliation_driver import ReconciliationDriver
from .restricted_api import create_app

def required(name:str)->str:
    value=os.environ.get(name)
    if not value:raise RuntimeError(f"required restricted runtime configuration missing: {name}")
    return value
def retired_versions(name:str,active_resource:str,active_version:str)->dict[tuple[str,str],str]:
    return parse_retired_versions(required(name),active_resource=active_resource,active_version=active_version)
def build_app():
    if os.environ.get("RESTRICTED_RUNTIME_MODE","production")!="production":raise RuntimeError("synthetic composition is prohibited in production image")
    policy=load_signed_policy(Path(required("RESTRICTED_POLICY_PATH")),Path(required("RESTRICTED_POLICY_SIGNATURE_PATH")),required("RESTRICTED_POLICY_PUBLIC_KEY_B64"))
    if policy.values["tenant_id"]!=required("RESTRICTED_TENANT_ID"):raise RuntimeError("policy tenant mismatch")
    active_resource=required("RESTRICTED_SERVICE_MAC_KEY_RESOURCE");active_version=required("RESTRICTED_SERVICE_MAC_KEY_VERSION")
    active=GoogleKmsHmacKey(active_resource,active_version,retired_versions("RESTRICTED_SERVICE_RETIRED_MAC_KEYS_JSON",active_resource,active_version))
    store=PostgresContentStore(required("DATABASE_URL"));gateway=HttpGatewayClient(required("RESTRICTED_GATEWAY_URL"),required("RESTRICTED_GATEWAY_AUDIENCE"))
    runtime=ConversationService(store,gateway,active,GoogleKmsDataKeyWrapper(required("RESTRICTED_CONTENT_WRAP_KEY")),policy,required("RESTRICTED_TENANT_ID"))
    driver=ReconciliationDriver(store,Reconciler(store,gateway),"conversation-reconciler",policy.epoch)
    @asynccontextmanager
    async def lifespan(app):
        # Status/fence only; failures retain durable rows and never produce output.
        await asyncio.to_thread(driver.run_once,32)
        stop=asyncio.Event()
        async def periodic():
            while not stop.is_set():
                try:await asyncio.to_thread(driver.run_once,32)
                except Exception:pass
                try:await asyncio.wait_for(stop.wait(),timeout=30)
                except asyncio.TimeoutError:pass
        task=asyncio.create_task(periodic())
        try:yield
        finally:
            stop.set();task.cancel()
            try:await task
            except asyncio.CancelledError:pass
    def gateway_ready():return gateway.ready(policy.epoch,policy.digest)
    app=create_app(runtime,production_authenticator(audience=required("RESTRICTED_EXTERNAL_AUDIENCE"),caller_principal=required("RESTRICTED_CALLER_PRINCIPAL")),gateway_ready)
    app.router.lifespan_context=lifespan
    return app
app=build_app()
