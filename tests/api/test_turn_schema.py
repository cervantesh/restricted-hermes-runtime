"""External API schema/status contract over the real PostgreSQL composition."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from restricted_runtime.auth import SyntheticAuthenticator
from restricted_runtime.contracts import ProviderResult, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.services.restricted_api import create_app
from restricted_runtime.storage import PostgresContentStore, PostgresLedger

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")

def policy():
    v=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));v.update(policy_epoch="1",caller_principal="caller",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(v,hashlib.sha256(jcs_bytes(v)).hexdigest())
class Keys:
    def wrap(self,k):return k
    def unwrap(self,k):return k
class Provider:
    def __init__(self):self.calls=0
    def generate_content(self,messages):self.calls+=1;return ProviderResult("SUCCEEDED",text="complete response")
@pytest.fixture
def client():
    with psycopg.connect(URL,autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE");c.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
    p=policy();provider=Provider();gkey=LocalHmacKey("gateway","1",b"g"*32);svc=ConversationService(PostgresContentStore(URL),Gateway(p,gkey,PostgresLedger(URL,p,gkey),provider),LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    return TestClient(create_app(svc,SyntheticAuthenticator("caller"))),provider

def test_sink_fields_are_rejected_before_content_or_dispatch(client):
    http,provider=client;body={"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"canary","model":"attacker-model"}
    response=http.post("/v1/restricted/conversations/c/turns",json=body,headers={"Authorization":"Synthetic test credential"})
    assert response.status_code==400 and "message" not in response.json() and provider.calls==0
    with psycopg.connect(URL) as c: assert c.execute("SELECT count(*) FROM restricted_content.turns").fetchone()[0]==0

def test_association_conflict_is_409_and_never_returns_partial_text(client):
    http,provider=client;key=str(uuid.uuid4());base={"schema_version":"restricted-turn.v1","client_request_id":key,"conversation_epoch":"epoch","message":"first"};headers={"Authorization":"Synthetic test credential"}
    assert http.post("/v1/restricted/conversations/c/turns",json=base,headers=headers).status_code==200
    changed={**base,"message":"second"};response=http.post("/v1/restricted/conversations/c/turns",json=changed,headers=headers)
    assert response.status_code==409 and "message" not in response.json() and provider.calls==1
