"""Malformed internal messages are rejected before any ledger write or dispatch."""
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
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway, GatewayEnvelope
from restricted_runtime.policy import PolicyBundle, SYSTEM_INSTRUCTION
from restricted_runtime.services.gateway_api import create_app
from restricted_runtime.storage import PostgresLedger

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")

def policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));values.update(policy_epoch="1",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())

class Provider:
    def __init__(self):self.calls=0
    def generate_content(self,messages):self.calls+=1;return ProviderResult("SUCCEEDED",text="must not dispatch")

@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")

@pytest.mark.parametrize("messages",[[{"role":"system","text":"x"}],[{"role":"user","text":"x","extra":"no"}],[{"role":"user","text":""}]])
def test_infer_rejects_closed_internal_message_violations_before_ledger_or_provider(messages):
    p=policy();provider=Provider();key=LocalHmacKey("gateway","1",b"g"*32)
    envelope=GatewayEnvelope("tenant","conversation","epoch",str(uuid.uuid4()),str(uuid.uuid4()),p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",messages,p.values["max_canonical_input_utf8_bytes"],authenticated_external_principal="caller")
    response=TestClient(create_app(Gateway(p,key,PostgresLedger(URL,p,key),provider),SyntheticAuthenticator("conversation"))).post("/infer",headers={"Authorization":"Synthetic test credential"},json={"schema_version":"restricted-gateway-envelope.v1",**envelope.__dict__})
    assert response.status_code==400 and provider.calls==0
    with psycopg.connect(URL) as conn:
        assert conn.execute("SELECT count(*) FROM inference_ledger.dispatch_guards").fetchone()[0]==0
        assert conn.execute("SELECT count(*) FROM inference_ledger.attempts").fetchone()[0]==0
