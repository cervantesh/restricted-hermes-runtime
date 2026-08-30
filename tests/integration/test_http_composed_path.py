"""Two real local HTTP services: conversation API -> HTTP gateway -> provider."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path

import httpx
import psycopg
import pytest
import uvicorn

from restricted_runtime.auth import SyntheticAuthenticator
from restricted_runtime.contracts import ProviderResult, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.gateway_client import HttpGatewayClient
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.services.gateway_api import create_app as gateway_app
from restricted_runtime.services.restricted_api import create_app as conversation_app
from restricted_runtime.storage import PostgresContentStore, PostgresLedger

URL=os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="requires isolated PostgreSQL")

def policy():
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"));values.update(policy_epoch="1",tenant_id="tenant",vertex_project_id="p",vertex_project_number="123",model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent")
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())

class Keys:
    def wrap(self,key):return key
    def unwrap(self,key):return key

class CountedProvider:
    def __init__(self):self.calls=0
    def generate_content(self,messages):
        self.calls+=1
        return ProviderResult("SUCCEEDED",text="synthetic HTTP response",provider_request_id="synthetic-provider-request")

class InternalSyntheticAuthenticator:
    def authenticate(self, authorization):
        assert authorization=="Bearer synthetic"
        return "caller"

def start(app):
    sock=socket.socket();sock.bind(("127.0.0.1",0));port=sock.getsockname()[1];sock.close()
    server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=port,log_level="error",access_log=False))
    thread=threading.Thread(target=server.run,daemon=True);thread.start()
    deadline=time.monotonic()+5
    while not server.started and time.monotonic()<deadline:time.sleep(.01)
    assert server.started
    return server,thread,f"http://127.0.0.1:{port}"

@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL,autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))

def test_real_http_composition_commits_encrypted_readback_and_duplicate_dispatches_once():
    p=policy();provider=CountedProvider();key=LocalHmacKey("gateway","1",b"g"*32)
    gateway_server,gateway_thread,gateway_url=start(gateway_app(Gateway(p,key,PostgresLedger(URL,p,key),provider),InternalSyntheticAuthenticator()))
    try:
        client=HttpGatewayClient(gateway_url,"synthetic-audience");client.tokens=lambda:"synthetic"
        service=ConversationService(PostgresContentStore(URL),client,LocalHmacKey("service","1",b"s"*32),Keys(),p,"tenant")
        conversation_server,conversation_thread,conversation_url=start(conversation_app(service,SyntheticAuthenticator("caller"),lambda:client.ready(p.epoch,p.digest)))
        try:
            headers={"Authorization":"Synthetic test credential"}
            with httpx.Client(trust_env=False) as http:
                created=http.post(conversation_url+"/v1/restricted/conversations/http-conversation",headers=headers)
                assert created.status_code==200
                epoch=created.json()["conversation_epoch"]
                payload={"schema_version":"restricted-turn.v1","client_request_id":str(uuid.uuid4()),"conversation_epoch":epoch,"message":"synthetic request"}
                first=http.post(conversation_url+"/v1/restricted/conversations/http-conversation/turns",headers=headers,json=payload)
                second=http.post(conversation_url+"/v1/restricted/conversations/http-conversation/turns",headers=headers,json=payload)
            assert first.status_code==second.status_code==200,(first.text,second.text)
            assert first.json()["message"]==second.json()["message"]=="synthetic HTTP response"
            assert provider.calls==1
            with psycopg.connect(URL) as conn:
                turn=conn.execute("SELECT state,request_ciphertext,response_ciphertext,gateway_decision_id,gateway_attempt_classification FROM restricted_content.turns").fetchone()
                assert turn[0]=="COMMITTED" and b"synthetic request" not in bytes(turn[1]) and b"synthetic HTTP response" not in bytes(turn[2])
                assert turn[3] is not None and turn[4]=="SUCCEEDED"
                assert conn.execute("SELECT count(*) FROM inference_ledger.attempts").fetchone()[0]==1
        finally:
            conversation_server.should_exit=True;conversation_thread.join(5)
    finally:
        gateway_server.should_exit=True;gateway_thread.join(5)
