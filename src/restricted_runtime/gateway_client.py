"""Conversation-side internal gateway client; it has no Vertex knowledge."""
from __future__ import annotations
import json
import httpx
from google.auth.transport.requests import Request
from google.oauth2.id_token import fetch_id_token
from .contracts import ContractError, ProviderResult
from .gateway import GatewayEnvelope

class GoogleIdTokenSupplier:
    def __init__(self,audience:str): self.audience=audience
    def __call__(self)->str:return fetch_id_token(Request(),self.audience)

class HttpGatewayClient:
    def __init__(self,url:str,audience:str): self.url=url.rstrip("/");self.tokens=GoogleIdTokenSupplier(audience)
    def _post(self,path:str,body:dict)->dict:
        with httpx.Client(timeout=httpx.Timeout(5,read=35,write=5,pool=5),follow_redirects=False,trust_env=False) as client:
            response=client.post(self.url+path,headers={"Authorization":"Bearer "+self.tokens(),"Content-Type":"application/json"},content=json.dumps(body,separators=(",",":"),ensure_ascii=False).encode())
        if response.status_code!=200:raise ContractError("gateway unavailable")
        return response.json()
    def infer_once(self,envelope:GatewayEnvelope,principal:str)->ProviderResult:
        body={"schema_version":"restricted-gateway-envelope.v1",**envelope.__dict__};reply=self._post("/infer",body)
        return ProviderResult(reply["status"],reply.get("message"))
    def status(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str):
        from .contracts import AttemptState
        identity={"tenant_id":tenant_id,"turn_id":turn_id,"client_request_id":client_request_id,"policy_epoch":policy_epoch,"policy_digest":policy_digest}
        result=self._post("/status",{"schema_version":"restricted-gateway-status.v1",**identity})
        return None if result.get("status")=="NOT_FOUND" else AttemptState(result["status"])
    def fence(self, tenant_id: str, turn_id: str, *, client_request_id: str, policy_epoch: str, policy_digest: str):
        from .contracts import AttemptState
        identity={"tenant_id":tenant_id,"turn_id":turn_id,"client_request_id":client_request_id,"policy_epoch":policy_epoch,"policy_digest":policy_digest}
        return AttemptState(self._post("/fence",{"schema_version":"restricted-gateway-fence.v1",**identity})["status"])
