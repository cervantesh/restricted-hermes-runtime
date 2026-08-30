import copy
import hashlib
import json
from dataclasses import replace

from restricted_runtime.contracts import ProviderResult, TurnRequest, TurnState, jcs_bytes
from restricted_runtime.conversation import ConversationService, TurnRow
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.policy import PolicyBundle

def policy():
    data=json.loads(open("policy/policy.template.json",encoding="utf-8").read())
    data.update(policy_epoch="7",caller_principal="svc@example.com",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(data,hashlib.sha256(jcs_bytes(data)).hexdigest())

class Keys:
    def wrap(self,k): return k
    def unwrap(self,k): return k
class Store:
    def __init__(self): self.rows={}; self.calls=[]
    def admitted(self,r): return self.rows.get((r.tenant_id,r.client_request_id))
    def admit(self,r):
        key=(r.tenant_id,r.client_request_id)
        if key in self.rows:return self.rows[key],False
        if any(x.conversation_id==r.conversation_id and x.conversation_epoch==r.conversation_epoch and not x.state.terminal for x in self.rows.values()): raise ValueError("ACTIVE_TURN")
        self.rows[key]=r;return r,True
    def committed_history(self,*_): return [r for r in self.rows.values() if r.state is TurnState.COMMITTED]
    def set_state_cas(self,t,turn,g,expected,target,**updates):
        for k,r in self.rows.items():
            if r.tenant_id==t and r.turn_id==turn and r.lease_generation==g and r.state is expected:self.rows[k]=replace(r,state=target,**updates);return True
        return False
    def read_turn(self,t,turn): return next(r for r in self.rows.values() if r.tenant_id==t and r.turn_id==turn)
    def reset(self,*_): raise AssertionError
class Gateway:
    def __init__(self): self.calls=0
    def infer_once(self,envelope,principal): self.calls+=1;return ProviderResult("SUCCEEDED",text="stored response")

def request(key="00000000-0000-0000-0000-000000000001",message="hello"):
    return TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":key,"conversation_epoch":"epoch","message":message})

def test_real_turn_path_persists_then_commits_reads_back_and_duplicate_does_not_dispatch():
    p=policy();store=Store();gateway=Gateway();svc=ConversationService(store,gateway,LocalHmacKey("k","v",b"x"*32),Keys(),p,"tenant")
    result=svc.submit(request(),principal="svc@example.com",conversation_id="conversation")
    assert result=={"schema_version":"restricted-turn-result.v1","turn_id":result["turn_id"],"conversation_epoch":"epoch","status":"COMMITTED","message":"stored response"}
    assert gateway.calls==1
    assert svc.submit(request(),principal="svc@example.com",conversation_id="conversation")["message"]=="stored response"
    assert gateway.calls==1

def test_same_key_association_mismatch_never_releases_existing_content():
    p=policy();store=Store();gateway=Gateway();svc=ConversationService(store,gateway,LocalHmacKey("k","v",b"x"*32),Keys(),p,"tenant")
    svc.submit(request(),principal="svc@example.com",conversation_id="one")
    import pytest
    with pytest.raises(Exception):svc.submit(request(),principal="svc@example.com",conversation_id="other")
    assert gateway.calls==1
