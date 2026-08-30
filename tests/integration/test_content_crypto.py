"""Authenticated encryption association and nonce checks."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg
import pytest

from restricted_runtime.contracts import ContractError, ProviderResult, TurnRequest, TurnState, content_aad, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import Ciphertext, LocalHmacKey, decrypt, encrypt
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.storage import PostgresContentStore, PostgresLedger

URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="requires isolated PostgreSQL")


def make_policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));values.update(policy_epoch="1",caller_principal="caller",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())


class Keys:
    def wrap(self,key): return key
    def unwrap(self,key): return key


class Provider:
    def __init__(self): self.calls=0
    def generate_content(self,messages): self.calls+=1;return ProviderResult("SUCCEEDED",text="response")


@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))


def _service():
    p=make_policy();provider=Provider();gkey=LocalHmacKey("gateway","1",b"g"*32)
    svc=ConversationService(PostgresContentStore(URL),Gateway(p,gkey,PostgresLedger(URL,p,gkey),provider),LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
    return svc,provider


def test_aad_binds_ciphertext_nonce_wrapped_key_direction_and_row_identity():
    svc, provider = _service(); request=TurnRequest.parse({"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":"epoch","message":"request secret"})
    result=svc.submit(request,principal="caller",conversation_id="conversation")
    row=svc.store.read_turn("tenant",result["turn_id"]);key=row.wrapped_data_key
    request_record=Ciphertext(row.request_nonce,row.request_ciphertext);response_record=Ciphertext(row.response_nonce,row.response_ciphertext)
    mutations=[
        ("request_ciphertext", replace(request_record,ciphertext=response_record.ciphertext), "request"),
        ("response_ciphertext", replace(response_record,ciphertext=request_record.ciphertext), "response"),
        ("request_nonce", replace(request_record,nonce=response_record.nonce), "request"),
        ("response_nonce", replace(response_record,nonce=request_record.nonce), "response"),
        ("wrapped_data_key", b"wrong wrapped key", "response"),
        ("direction", response_record, "request"),
        ("row_identity", response_record, "response"),
    ]
    for field, record, direction in mutations:
        if field == "wrapped_data_key":
            mutated_key=b"wrong wrapped key"
            mutated=replace(row,wrapped_data_key=mutated_key)
            with pytest.raises(ContractError): svc._committed_result(mutated)
        else:
            mutated_record=record
            aad_row=row
            if field == "direction": aad=svc._aad(aad_row,"request")
            elif field == "row_identity": aad=content_aad(tenant_id="tenant",conversation_id="other",conversation_epoch=row.conversation_epoch,turn_id=row.turn_id,client_request_id=row.client_request_id,direction=direction,policy_digest=row.policy_digest)
            else: aad=svc._aad(aad_row,direction)
            with pytest.raises(ContractError): decrypt(key,Ciphertext(mutated_record.nonce,mutated_record.ciphertext),aad)
    assert provider.calls == 1
    assert svc.store.read_turn("tenant",row.turn_id).state is TurnState.COMMITTED


def test_nonce_uniqueness_is_enforced_per_turn_key_even_if_entropy_repeats(monkeypatch):
    key=b"k"*32;aad=b"aad";real=os.urandom;calls=0
    def repeated(n):
        nonlocal calls
        calls+=1
        return b"n"*12
    monkeypatch.setattr("restricted_runtime.crypto.os.urandom",repeated)
    first=encrypt(key,b"one",aad)
    with pytest.raises(ContractError,match="nonce"):
        encrypt(key,b"two",aad)
    assert first.nonce == b"n"*12 and calls >= 2
    monkeypatch.setattr("restricted_runtime.crypto.os.urandom",real)
