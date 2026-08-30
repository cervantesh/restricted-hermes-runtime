import hashlib
import json
from pathlib import Path

import pytest

from restricted_runtime.contracts import Classification, ContractError, jcs_bytes
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway, GatewayEnvelope
from restricted_runtime.policy import PolicyBundle, SYSTEM_INSTRUCTION


def policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(policy_epoch="p1",tenant_id="tenant",vertex_project_id="project",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())


def test_gateway_kill_switch_blocks_an_already_reserved_turn_before_vertex_dispatch():
    class Ledger:
        def reserve(self,*_): raise AssertionError("disabled gateway must not reserve")
    class Vertex:
        calls=0
        def generate_content(self,_): self.calls+=1; raise AssertionError("disabled gateway must not call Vertex")
    p=policy(); vertex=Vertex()
    envelope=GatewayEnvelope("tenant","conversation","epoch","turn","request",p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,Classification.PHI,[{"role":"user","text":"synthetic"}],p.values["max_canonical_input_utf8_bytes"],authenticated_external_principal="caller")
    gateway=Gateway(p,LocalHmacKey("gateway","version",b"g"*32),Ledger(),vertex,admission_enabled=False)
    with pytest.raises(ContractError,match="gateway admission is disabled"):
        gateway.infer_once(envelope,"conversation")
    assert vertex.calls==0
