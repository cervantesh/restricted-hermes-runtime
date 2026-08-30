"""Gateway HTTP contract. Status/fence endpoints do not import a Vertex client."""
from __future__ import annotations
from fastapi import FastAPI, HTTPException, Request
from ..auth import Authenticator
from ..contracts import ContractError, load_closed_json
from ..gateway import Gateway, GatewayEnvelope

_ENVELOPE=set(GatewayEnvelope.__annotations__)
_IDENTITY={"tenant_id","turn_id","client_request_id","policy_epoch","policy_digest"}
def create_app(gateway:Gateway,authenticator:Authenticator)->FastAPI:
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    def auth(r:Request)->str:return authenticator.authenticate(r.headers.get("authorization"))
    @app.get("/readyz")
    def readyz(policy_epoch:str,policy_digest:str):
        if (policy_epoch,policy_digest)!=(gateway.policy.epoch,gateway.policy.digest):raise HTTPException(503,"policy pair mismatch")
        return {"status":"ready","policy_epoch":gateway.policy.epoch,"policy_digest":gateway.policy.digest}
    @app.post("/infer")
    async def infer(request:Request):
        try:
            principal=auth(request);body=load_closed_json(await request.body())
            if not isinstance(body,dict) or set(body)!={"schema_version",*_ENVELOPE} or body["schema_version"]!="restricted-gateway-envelope.v1":raise ContractError("closed inference envelope")
            result=gateway.infer_once(GatewayEnvelope(**{k:body[k] for k in _ENVELOPE}),principal)
            return {"status":result.state,"message":result.text} if result.state=="SUCCEEDED" else {"status":result.state}
        except ContractError as exc:raise HTTPException(400,"gateway inference rejected") from exc
    @app.post("/status")
    async def status(request:Request):
        try:
            auth(request);body=load_closed_json(await request.body())
            if not isinstance(body,dict) or set(body)!={"schema_version",*_IDENTITY} or body["schema_version"]!="restricted-gateway-status.v1":raise ContractError("closed status schema")
            state=gateway.status(body["tenant_id"],body["turn_id"],client_request_id=body["client_request_id"],policy_epoch=body["policy_epoch"],policy_digest=body["policy_digest"])
            return {"status":"NOT_FOUND" if state is None else state.value}
        except ContractError as exc:raise HTTPException(400,"gateway status rejected") from exc
    @app.post("/fence")
    async def fence(request:Request):
        try:
            auth(request);body=load_closed_json(await request.body())
            if not isinstance(body,dict) or set(body)!={"schema_version",*_IDENTITY} or body["schema_version"]!="restricted-gateway-fence.v1":raise ContractError("closed fence schema")
            state=gateway.ledger.fence(body["tenant_id"],body["turn_id"],client_request_id=body["client_request_id"],policy_epoch=body["policy_epoch"],policy_digest=body["policy_digest"])
            return {"status":state.value}
        except ContractError as exc:raise HTTPException(400,"gateway fence rejected") from exc
    return app
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
