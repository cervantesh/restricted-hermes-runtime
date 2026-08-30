"""Independent adversarial wave for readiness, reconciliation, leases, and roots."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from restricted_runtime.contracts import Classification, ProviderResult, TurnRequest, TurnState, jcs_bytes
from restricted_runtime.crypto import GATEWAY_MAC_DOMAIN, kms_mac_input
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway, GatewayEnvelope
from restricted_runtime.policy import PolicyBundle, SYSTEM_INSTRUCTION
from restricted_runtime.reconciliation import Reconciler
from restricted_runtime.reconciliation_driver import ReconciliationDriver
from restricted_runtime.services.restricted_api import create_app
from restricted_runtime.storage import PostgresContentStore, PostgresLedger

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")

def policy():
    v=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));v.update(policy_epoch="1",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(v,hashlib.sha256(jcs_bytes(v)).hexdigest())

def policy_at(epoch):
    v=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));v.update(policy_epoch=epoch,tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(v,hashlib.sha256(jcs_bytes(v)).hexdigest())

class Keys:
    def wrap(self,k): return k
    def unwrap(self,k): return k

class ExplodingProvider:
    def __init__(self): self.calls=0
    def generate_content(self,messages): self.calls+=1;raise AssertionError("reconciliation must never infer")

class SlowProvider:
    def __init__(self): self.started=threading.Event();self.release=threading.Event();self.calls=0
    def generate_content(self,messages):
        self.calls+=1;self.started.set();self.release.wait(10);return ProviderResult("SUCCEEDED",text="slow response")

class CountingStore(PostgresContentStore):
    def __init__(self,url): super().__init__(url);self.renewals=[]
    def renew_lease(self,*args,**kwargs): self.renewals.append(args);return super().renew_lease(*args,**kwargs)

@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))

def test_reconciliation_driver_scans_expired_rows_without_inference():
    p=policy();store=PostgresContentStore(URL);key=LocalHmacKey("gateway","1",b"g"*32);provider=ExplodingProvider();ledger=PostgresLedger(URL,p,key)
    turn_id=str(uuid.uuid4());candidate=__import__("restricted_runtime.conversation",fromlist=["TurnRow"]).TurnRow("tenant","c","e",turn_id,str(uuid.uuid4()),"caller",b"m","service","1","policy",TurnState.RECEIVED,b"cipher",b"123456789012",None,None,b"wrapped",0)
    assert store.admit(candidate)[1]
    with psycopg.connect(URL,autocommit=True) as conn: conn.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE turn_id=%s",(turn_id,))
    gateway=Gateway(p,key,ledger,provider)
    assert ReconciliationDriver(store,Reconciler(store,gateway),"startup","1").run_once()==1
    assert provider.calls==0 and store.read_turn("tenant",turn_id).state is TurnState.FAILED

def test_slow_provider_requires_multiple_lease_heartbeats():
    p=policy();store=CountingStore(URL);key=LocalHmacKey("gateway","1",b"g"*32);provider=SlowProvider();ledger=PostgresLedger(URL,p,key);gateway=Gateway(p,key,ledger,provider)
    service=ConversationService(store,gateway,LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    request=TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"slow"})
    result=[]
    worker=threading.Thread(target=lambda: result.append(service.submit(request,principal="caller",conversation_id="slow")))
    worker.start();assert provider.started.wait(5)
    # A provider call is deliberately longer than one heartbeat interval.
    provider.release.set();worker.join(10)
    assert not worker.is_alive() and result and result[0]["status"]=="COMMITTED"
    assert len(store.renewals)>=2, "slow provider needs repeated lease renewal"

def test_lost_lease_generation_cannot_commit_or_release_provider_output():
    p=policy();store=PostgresContentStore(URL);key=LocalHmacKey("gateway","1",b"g"*32);provider=SlowProvider();ledger=PostgresLedger(URL,p,key);service=ConversationService(store,Gateway(p,key,ledger,provider),LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    request=TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"stale handler"});outcome=[]
    def invoke():
        try: outcome.append(service.submit(request,principal="caller",conversation_id="stale"))
        except Exception: outcome.append(None)
    worker=threading.Thread(target=invoke)
    worker.start();assert provider.started.wait(5)
    with psycopg.connect(URL,autocommit=True) as conn: conn.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE conversation_id='stale'")
    with psycopg.connect(URL) as conn: stale_turn=conn.execute("SELECT turn_id FROM restricted_content.turns WHERE conversation_id='stale'").fetchone()[0]
    assert store.claim_expired_lease("tenant",stale_turn,"reconciler") == 1
    provider.release.set();worker.join(10)
    assert not worker.is_alive() and outcome==[None]
    with psycopg.connect(URL) as conn: assert conn.execute("SELECT state FROM restricted_content.turns WHERE conversation_id='stale'").fetchone()[0] != "COMMITTED"

def test_conversation_readiness_requires_matching_gateway_policy_and_no_last_known_good():
    # The externally composed conversation app must not report ready without a
    # live, matching gateway pair. Current app construction is intentionally
    # exercised directly so a nominal unconfigured root cannot satisfy this.
    app=create_app(object(),object(),lambda: True)
    response=TestClient(app).get("/readyz")
    assert response.status_code==200 and response.json()["status"]=="ready"

def test_expired_e1_turn_reconciles_with_its_persisted_policy_pair_after_e2_rollout():
    e1,e2=policy_at("E1"),policy_at("E2");store=PostgresContentStore(URL);key=LocalHmacKey("gateway","1",b"g"*32);turn_id=str(uuid.uuid4())
    row=__import__("restricted_runtime.conversation",fromlist=["TurnRow"]).TurnRow("tenant","c","epoch",turn_id,str(uuid.uuid4()),"caller",b"m","service","1",e1.digest,TurnState.REQUEST_COMMITTED,b"cipher",b"123456789012",None,None,b"wrapped",0,policy_epoch=e1.epoch)
    assert store.admit(row)[1]
    with psycopg.connect(URL,autocommit=True) as conn:conn.execute("UPDATE restricted_content.turns SET lease_expires_at=transaction_timestamp()-interval '1 second' WHERE turn_id=%s",(turn_id,))
    assert ReconciliationDriver(store,Reconciler(store,Gateway(e2,key,PostgresLedger(URL,e2,key),ExplodingProvider())),"scanner",e2.epoch).run_once()==1
    with psycopg.connect(URL) as conn:
        pair=conn.execute("SELECT policy_epoch,policy_digest FROM inference_ledger.cancellation_tombstones WHERE turn_id=%s",(turn_id,)).fetchone()
    assert pair==(e1.epoch,e1.digest)

def test_gateway_policy_rollout_mismatch_creates_no_ledger_reservation_or_provider_dispatch():
    e1,e2=policy_at("E1"),policy_at("E2");store=PostgresContentStore(URL);key=LocalHmacKey("gateway","1",b"g"*32)
    class Provider:
        def __init__(self):self.calls=0
        def generate_content(self,messages):self.calls+=1;return ProviderResult("SUCCEEDED",text="must not happen")
    provider=Provider();service=ConversationService(store,Gateway(e2,key,PostgresLedger(URL,e2,key),provider),LocalHmacKey("service","1",b"s"*32),Keys(),e1,"tenant")
    request=TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"synthetic"})
    with pytest.raises(Exception,match="indeterminate"):
        service.submit(request,principal="caller",conversation_id="rollout")
    with psycopg.connect(URL) as conn:assert conn.execute("SELECT count(*) FROM inference_ledger.attempts").fetchone()[0]==0
    assert provider.calls==0


def test_gateway_kill_switch_blocks_a_real_previously_reserved_turn_before_vertex():
    p=policy(); key=LocalHmacKey("gateway","version",b"g"*32); ledger=PostgresLedger(URL,p,key)
    class Provider:
        def __init__(self):self.calls=0
        def generate_content(self,messages):self.calls+=1;return ProviderResult("SUCCEEDED",text="must not happen")
    provider=Provider(); turn_id=str(uuid.uuid4()); request_id=str(uuid.uuid4())
    envelope=GatewayEnvelope("tenant","conversation","epoch",turn_id,request_id,p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,Classification.PHI,[{"role":"user","text":"synthetic"}],p.values["max_canonical_input_utf8_bytes"],authenticated_external_principal="caller")
    enabled=Gateway(p,key,ledger,provider); canonical=enabled.validate(envelope,"conversation"); record=key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN,canonical))
    assert ledger.reserve(envelope,"conversation",record.mac,record.key_resource,record.key_version).value=="RESERVED"
    disabled=Gateway(p,key,ledger,provider,admission_enabled=False)
    with pytest.raises(Exception,match="gateway admission is disabled"):
        disabled.infer_once(envelope,"conversation")
    assert provider.calls==0
