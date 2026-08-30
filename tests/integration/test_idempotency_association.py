"""Identity and status/fence association checks over PostgreSQL-backed code."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import psycopg
import pytest

from restricted_runtime.contracts import ContractError, TurnRequest, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey, GATEWAY_MAC_DOMAIN, kms_mac_input
from restricted_runtime.gateway import GatewayEnvelope
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle, SYSTEM_INSTRUCTION
from restricted_runtime.storage import PostgresContentStore, PostgresLedger
from restricted_runtime.contracts import ProviderResult

URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="requires isolated PostgreSQL")


def policy() -> PolicyBundle:
    values = json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(policy_epoch="1", tenant_id="tenant", vertex_project_id="p", vertex_project_number="123", model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash", generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())


class Keys:
    def wrap(self, key): return key
    def unwrap(self, key): return key


class Provider:
    def __init__(self): self.calls = 0
    def generate_content(self, messages): self.calls += 1; return ProviderResult("SUCCEEDED", text="private response")


@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")


def test_identity_dimensions_reject_replay_before_plaintext_read_or_dispatch():
    p=policy();provider=Provider();gateway_key=LocalHmacKey("gateway","1",b"g"*32)
    service=ConversationService(PostgresContentStore(URL), Gateway(p,gateway_key,PostgresLedger(URL,p,gateway_key),provider), LocalHmacKey("service","1",b"s"*32), Keys(), p, "tenant")
    key=str(uuid.uuid4());base={"schema_version":"restricted-turn.v1","client_request_id":key,"conversation_epoch":"epoch","message":"secret canary"}
    service.submit(TurnRequest.parse(base),principal="caller",conversation_id="conversation")
    mutations=[
        ("principal", {"principal":"other","conversation_id":"conversation","message":"secret canary","epoch":"epoch"}),
        ("conversation", {"principal":"caller","conversation_id":"other","message":"secret canary","epoch":"epoch"}),
        ("epoch", {"principal":"caller","conversation_id":"conversation","message":"secret canary","epoch":"other-epoch"}),
        ("message", {"principal":"caller","conversation_id":"conversation","message":"changed canary","epoch":"epoch"}),
    ]
    for _, mutation in mutations:
        request=TurnRequest.parse({**base,"conversation_epoch":mutation["epoch"],"message":mutation["message"]})
        with pytest.raises(ContractError, match="association|MAC|epoch"):
            service.submit(request,principal=mutation["principal"],conversation_id=mutation["conversation_id"])
    assert provider.calls == 1
    with psycopg.connect(URL) as conn:
        assert conn.execute("SELECT count(*) FROM restricted_content.turns").fetchone()[0] == 1


def test_status_and_fence_identity_mutations_fail_closed():
    p=policy();key=LocalHmacKey("gateway","1",b"g"*32);ledger=PostgresLedger(URL,p,key);turn_id=str(uuid.uuid4());request_id=str(uuid.uuid4())
    envelope=GatewayEnvelope("tenant","c","e",turn_id,request_id,p.epoch,p.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",[],p.values["max_canonical_input_utf8_bytes"])
    record=key.sign(kms_mac_input(GATEWAY_MAC_DOMAIN,envelope.canonical()))
    assert ledger.reserve(envelope,"caller",record.mac,record.key_resource,record.key_version).value == "RESERVED"
    for field, value in (("client_request_id",str(uuid.uuid4())), ("policy_epoch","stale"), ("policy_digest","stale")):
        identity={"client_request_id":request_id,"policy_epoch":p.epoch,"policy_digest":p.digest};identity[field]=value
        with pytest.raises(ContractError, match="identity"):
            ledger.status("tenant",turn_id,**identity)
        with pytest.raises(ContractError, match="identity|remap"):
            ledger.fence("tenant",turn_id,**identity)
    assert ledger.status("tenant",turn_id,client_request_id=request_id,policy_epoch=p.epoch,policy_digest=p.digest).value == "RESERVED"
