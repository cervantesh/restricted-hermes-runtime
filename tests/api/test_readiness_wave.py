"""Readiness must be a live policy-pair check, never a nominal route."""
import hashlib
import json
import os
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

class Keys:
    def wrap(self,key):return key
    def unwrap(self,key):return key
class Provider:
    def generate_content(self,messages):return ProviderResult("SUCCEEDED",text="unused")

def policy():
    v=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));v.update(policy_epoch="7",caller_principal="caller",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(v,hashlib.sha256(jcs_bytes(v)).hexdigest())

@pytest.mark.parametrize("gateway_ready,expected", [(lambda: True,200),(lambda: False,503)])
def test_conversation_readyz_is_live_and_rejects_gateway_down_or_malformed_pair(gateway_ready,expected):
    p=policy();key=LocalHmacKey("gateway","1",b"g"*32);service=ConversationService(PostgresContentStore(URL),Gateway(p,key,PostgresLedger(URL,p,key),Provider()),LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    response=TestClient(create_app(service,SyntheticAuthenticator("caller"),gateway_ready)).get("/readyz")
    assert response.status_code==expected

def test_conversation_readyz_maps_gateway_exception_to_unready():
    p=policy();key=LocalHmacKey("gateway","1",b"g"*32);service=ConversationService(PostgresContentStore(URL),Gateway(p,key,PostgresLedger(URL,p,key),Provider()),LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    def gateway_down(): raise OSError("gateway unavailable")
    response=TestClient(create_app(service,SyntheticAuthenticator("caller"),gateway_down)).get("/readyz")
    assert response.status_code==503
