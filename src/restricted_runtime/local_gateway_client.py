"""Closed single-request AF_UNIX client for the local gateway API."""
from __future__ import annotations
import socket,time
from pathlib import Path
from .contracts import AttemptState, ContractError, ProviderResult, jcs_bytes, load_closed_json
from .gateway_contracts import GatewayEnvelope

class LocalGatewayClient:
    def __init__(self, path: str):
        if path != "/run/restricted-inference/gateway.sock": raise ContractError("local gateway socket path rejected")
        self.path=path
    def _request(self,method:str,path:str,body:dict|None=None)->dict:
        if path.split("?",1)[0] not in {"/infer","/status","/fence","/readyz"}: raise ContractError("local gateway path rejected")
        raw=b"" if body is None else jcs_bytes(body)
        started=time.monotonic()
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                client.settimeout(5);client.connect(self.path);client.sendall(method.encode()+b" "+path.encode()+b" HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "+str(len(raw)).encode()+b"\r\nConnection: close\r\n\r\n"+raw); reply=b""
                while True:
                    if time.monotonic()-started>40: raise TimeoutError
                    client.settimeout(5);part=client.recv(65536)
                    if not part:break
                    reply+=part
                    if len(reply)>1_048_576:raise ValueError
            head,payload=reply.split(b"\r\n\r\n",1); lines=head.split(b"\r\n")
            if not lines or lines[0] != b"HTTP/1.1 200 OK":raise ContractError("local gateway unavailable")
            headers={}
            for line in lines[1:]:
                key,value=line.split(b":",1);key=key.lower()
                if key in headers or key not in {b"content-length",b"content-type"}:raise ValueError
                headers[key]=value.strip()
            if set(headers)!={b"content-length",b"content-type"} or headers[b"content-type"]!=b"application/json" or int(headers[b"content-length"])!=len(payload):raise ValueError
            value=load_closed_json(payload)
            if not isinstance(value,dict):raise ValueError
            return value
        except ContractError: raise
        except Exception as exc: raise ContractError("local gateway unavailable") from exc
    def infer_once(self,envelope:GatewayEnvelope,principal:str)->ProviderResult:
        reply=self._request("POST","/infer",{"schema_version":"restricted-gateway-envelope.v1",**envelope.__dict__})
        if reply.get("status")!="SUCCEEDED":return ProviderResult(reply["status"])
        return ProviderResult("SUCCEEDED",reply["message"],decision_id=reply["decision_id"],provider_request_id=reply.get("provider_request_id"),policy_epoch=reply["policy_epoch"],policy_digest=reply["policy_digest"])
    def ready(self,e:str,d:str)->bool:
        reply=self._request("GET","/readyz?policy_epoch="+e+"&policy_digest="+d)
        return reply=={"status":"ready","policy_epoch":e,"policy_digest":d}
    def status(self,tenant_id,turn_id,*,client_request_id,policy_epoch,policy_digest):
        reply=self._request("POST","/status",{"schema_version":"restricted-gateway-status.v1","tenant_id":tenant_id,"turn_id":turn_id,"client_request_id":client_request_id,"policy_epoch":policy_epoch,"policy_digest":policy_digest})
        if set(reply)!={"status"}:raise ContractError("local gateway status malformed")
        return None if reply["status"]=="NOT_FOUND" else AttemptState(reply["status"])
    def fence(self,tenant_id,turn_id,*,client_request_id,policy_epoch,policy_digest):
        reply=self._request("POST","/fence",{"schema_version":"restricted-gateway-fence.v1","tenant_id":tenant_id,"turn_id":turn_id,"client_request_id":client_request_id,"policy_epoch":policy_epoch,"policy_digest":policy_digest})
        if set(reply)!={"status"}:raise ContractError("local gateway fence malformed")
        return AttemptState(reply["status"])
