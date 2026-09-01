"""External conversation API composed only with a verified authenticator and runtime."""
from __future__ import annotations
import sys
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from ..auth import Authenticator
from ..contracts import ContractError, TurnRequest, load_closed_json
from ..conversation import ConversationService
from ..policy import PolicyBundle

_TURN_REJECTION_CODES = {
    "inference outcome is indeterminate": "inference_outcome_indeterminate",
    "gateway result association mismatch": "gateway_result_association_mismatch",
    "response is not durably committed": "response_not_durably_committed",
    "lease lost during provider operation": "lease_lost_during_provider_operation",
}


def _turn_rejection_code(error: ContractError) -> str:
    """Return a closed diagnostic label; never log request content or exception text."""
    return _TURN_REJECTION_CODES.get(str(error), "closed_contract_rejection")


def readiness_document(policy: PolicyBundle) -> dict[str, object]:
    """Return the one closed, policy-derived conversation readiness contract."""
    policy.validate()
    return {
        "schema_version": "restricted-conversation-readiness.v1",
        "status": "ready",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "classification": policy.values["classification"],
        "system_instruction_version": policy.values["system_instruction_version"],
        "allowed_modalities": policy.values["allowed_modalities"],
        "tools_allowed": policy.values["tools_allowed"],
        "fallbacks": policy.values["fallbacks"],
        "max_provider_attempts": policy.values["max_provider_attempts"],
        "streaming": policy.values["streaming"],
        "max_output_tokens": policy.values["max_output_tokens"],
        "max_canonical_input_utf8_bytes": policy.values["max_canonical_input_utf8_bytes"],
        "response_profile": policy.values["response_profile"],
    }

def create_app(runtime: ConversationService, authenticator: Authenticator, gateway_ready=None) -> FastAPI:
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    @app.post("/v1/restricted/conversations/{conversation_id}")
    async def create_conversation(conversation_id:str,request:Request):
        try:
            if await request.body():raise ContractError("conversation creation has no caller body")
            authenticator.authenticate(request.headers.get("authorization"))
            if runtime.authorization_gate is not None: runtime.authorization_gate()
            epoch=runtime.store.create_conversation(runtime.tenant_id,conversation_id)
            return {"schema_version":"restricted-conversation.v1","conversation_id":conversation_id,"conversation_epoch":epoch}
        except ContractError as exc:raise HTTPException(400,"restricted conversation rejected") from exc
    @app.post("/v1/restricted/conversations/{conversation_id}/turns")
    async def create_turn(conversation_id:str,request:Request):
        try:
            turn=TurnRequest.parse(load_closed_json(await request.body()))
            principal=authenticator.authenticate(request.headers.get("authorization"))
            return runtime.submit(turn,principal=principal,conversation_id=conversation_id)
        except ContractError as exc:
            print(f"turn_rejected_reason={_turn_rejection_code(exc)}", file=sys.stderr, flush=True)
            raise HTTPException(409 if str(exc) in {"ACTIVE_TURN","idempotency association conflict","idempotency MAC verification failed","stale conversation epoch"} else 400,"restricted turn rejected") from exc
    @app.post("/v1/restricted/conversations/{conversation_id}/reset")
    async def reset(conversation_id:str,request:Request):
        try:
            principal=authenticator.authenticate(request.headers.get("authorization")); body=load_closed_json(await request.body())
            if set(body)!={"conversation_epoch"} or not isinstance(body["conversation_epoch"],str):raise ContractError("closed reset schema")
            if not principal:raise ContractError("unauthorized")
            if runtime.authorization_gate is not None: runtime.authorization_gate()
            epoch=runtime.store.reset(runtime.tenant_id,conversation_id,body["conversation_epoch"])
            return {"schema_version":"restricted-conversation-reset.v1","conversation_epoch":epoch}
        except ContractError as exc: raise HTTPException(409 if str(exc)=="ACTIVE_TURN" else 400,"restricted reset rejected") from exc
    @app.get("/readyz")
    async def readyz():
        try:
            ready = gateway_ready is not None and gateway_ready()
            if not ready:
                raise ContractError("gateway policy pair is not ready")
            return JSONResponse(
                readiness_document(runtime.policy),
                headers={"Connection": "close"},
            )
        except Exception:
            raise HTTPException(503,"gateway policy pair is not ready")
    return app

def unconfigured_app()->FastAPI:
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    @app.get("/readyz")
    def readyz():raise HTTPException(503,"runtime composition is required")
    return app
app=unconfigured_app()
