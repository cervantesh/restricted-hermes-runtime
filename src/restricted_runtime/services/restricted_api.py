"""Restricted conversation HTTP boundary. It contains no provider client."""
from __future__ import annotations

import os
from fastapi import FastAPI, HTTPException, Request

from ..contracts import ContractError, TurnRequest, load_closed_json

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
TENANT_ID = os.environ.get("RESTRICTED_TENANT_ID", "UNCONFIGURED")
ALLOWED_PRINCIPAL = os.environ.get("RESTRICTED_CALLER_PRINCIPAL", "UNCONFIGURED")

def authenticated_principal(request: Request) -> str:
    # Deployment adapter must validate Google issuer/audience/expiry before this point.
    principal = request.headers.get("x-restricted-verified-principal")
    if principal != ALLOWED_PRINCIPAL: raise HTTPException(401, "unauthorized")
    return principal

@app.post("/v1/restricted/conversations/{conversation_id}/turns")
async def create_turn(conversation_id: str, request: Request):
    try:
        body = TurnRequest.parse(load_closed_json(await request.body()))
        principal = authenticated_principal(request)
        # Store/admission integration is intentionally injected by deployment composition;
        # this boundary only accepts the closed request and trusted server identity.
        return {"schema_version": "restricted-turn-accepted.v1", "status": "RECEIVED", "classification": "PHI"}
    except ContractError as exc:
        raise HTTPException(400, "invalid restricted turn") from exc
