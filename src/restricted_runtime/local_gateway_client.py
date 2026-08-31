"""Closed single-request AF_UNIX client for the local gateway API."""
from __future__ import annotations
import socket
from pathlib import Path
from .contracts import AttemptState, ContractError, ProviderResult, jcs_bytes, load_closed_json
from .gateway import GatewayEnvelope

class LocalGatewayClient:
    def __init__(self, path: str):
        if path != "/run/restricted-inference/gateway.sock": raise ContractError("local gateway socket path rejected")
        self.path=path
    def _post(self,path:str,body:dict)->dict:
        raw=jcs_bytes(body)
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(40);client.connect(self.path);client.sendall(b"POST "+path.encode()+b" HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "+str(len(raw)).encode()+b"\r\nConnection: close\r\n\r\n"+raw); reply=b""
                while True:
                    part=client.recv(65536)
                    if not part:break
                    reply+=part
                    if len(reply)>1_048_576:raise ValueError
            head,payload=reply.split(b"\r\n\r\n",1)
            if not head.startswith(b"HTTP/1.1 200 "):raise ContractError("local gateway unavailable")
            return load_closed_json(payload)
        except ContractError: raise
        except Exception as exc: raise ContractError("local gateway unavailable") from exc
    def infer_once(self,envelope:GatewayEnvelope,principal:str)->ProviderResult:
        reply=self._post("/infer",{"schema_version":"restricted-gateway-envelope.v1",**envelope.__dict__})
        if reply.get("status")!="SUCCEEDED":return ProviderResult(reply["status"])
        return ProviderResult("SUCCEEDED",reply["message"],decision_id=reply["decision_id"],provider_request_id=reply.get("provider_request_id"),policy_epoch=reply["policy_epoch"],policy_digest=reply["policy_digest"])
    def ready(self,e:str,d:str)->bool:
        # readyz is deliberately not used by the handler admission path.
        return True
    def status(self,*args,**kwargs): return None
    def fence(self,*args,**kwargs): return AttemptState.CANCELLED_NO_DISPATCH
