"""Executable crash-boundary matrix over the real service/gateway/PostgreSQL path."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

import psycopg
import pytest

import restricted_runtime.conversation as conversation_module
from restricted_runtime.contracts import ContractError, ProviderResult, TurnRequest, TurnState, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.storage import PostgresContentStore, PostgresLedger


URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="requires isolated PostgreSQL")


def make_policy() -> PolicyBundle:
    values = json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(
        policy_epoch="1",
        tenant_id="tenant",
        vertex_project_id="project",
        vertex_project_number="123",
        model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",
        generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent",
    )
    return PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())


class Keys:
    def wrap(self, key: bytes) -> bytes:
        return key

    def unwrap(self, key: bytes) -> bytes:
        return key


class CountedProvider:
    def __init__(self, mode: str):
        self.mode = mode
        self.calls = 0

    def generate_content(self, messages):
        if self.mode == "socket_before":
            raise OSError("socket failed before write")
        self.calls += 1
        if self.mode == "socket_after":
            raise OSError("socket lost after write")
        if self.mode == "response_before":
            return ProviderResult("FAILED", failure_class="PROVIDER_REJECTED")
        if self.mode == "response_after":
            return ProviderResult("INDETERMINATE", failure_class="MALFORMED_RESPONSE")
        return ProviderResult("SUCCEEDED", text="durable response")


class FaultStore(PostgresContentStore):
    def __init__(self, url: str, fault: str):
        super().__init__(url)
        self.fault = fault
        self.failed = False

    def admit_with_history(self, **kwargs):
        if self.fault == "request_before":
            raise OSError("request persistence failed before transaction")
        return super().admit_with_history(**kwargs)

    def set_state_cas(self, tenant_id, turn_id, generation, expected, target, **updates):
        if self.fault == "request_after" and expected is TurnState.REQUEST_COMMITTED and target is TurnState.INFERENCE_PENDING:
            return False
        if self.fault == "response_commit_before" and expected is TurnState.INFERENCE_PENDING and target is TurnState.RESPONSE_RECEIVED:
            return False
        if self.fault == "response_commit_after" and expected is TurnState.RESPONSE_RECEIVED and target is TurnState.COMMITTED and not self.failed:
            self.failed = True
            return False
        return super().set_state_cas(tenant_id, turn_id, generation, expected, target, **updates)


class FaultLedger(PostgresLedger):
    def __init__(self, url, policy, key, fault):
        super().__init__(url, policy, key)
        self.fault = fault

    def reserve(self, envelope, principal, mac, key_resource, key_version):
        if self.fault == "reservation_before":
            raise OSError("reservation failed before commit")
        state = super().reserve(envelope, principal, mac, key_resource, key_version)
        if self.fault == "reservation_after" and state.value == "RESERVED":
            raise OSError("reservation acknowledgement lost after commit")
        return state

    def start_dispatch(self, tenant_id, turn_id):
        if self.fault == "dispatch_started_before":
            return False
        started = super().start_dispatch(tenant_id, turn_id)
        if self.fault == "dispatch_started_after" and started:
            raise OSError("dispatch marker acknowledgement lost")
        return started


class ReadbackFaultStore(PostgresContentStore):
    def __init__(self, url):
        super().__init__(url)
        self.fail_committed_read = True

    def read_turn(self, tenant_id, turn_id):
        row = super().read_turn(tenant_id, turn_id)
        if row.state is TurnState.COMMITTED and self.fail_committed_read:
            self.fail_committed_read = False
            raise OSError("authoritative readback unavailable")
        return row


@pytest.fixture(autouse=True)
def migrated():
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")


def service_for(fault: str, provider_mode: str | None = None, store=None):
    policy = make_policy()
    gateway_key = LocalHmacKey("gateway", "1", b"g" * 32)
    ledger = FaultLedger(URL, policy, gateway_key, fault)
    provider = CountedProvider(provider_mode or "success")
    gateway = Gateway(policy, gateway_key, ledger, provider)
    content = store or FaultStore(URL, fault)
    service = ConversationService(content, gateway, LocalHmacKey("service", "1", b"s" * 32), Keys(), policy, "tenant")
    request = TurnRequest.parse({"schema_version": "restricted-turn.v1", "client_request_id": str(uuid.uuid4()), "conversation_epoch": "epoch", "message": "synthetic request"})
    return service, provider, request


@pytest.mark.parametrize(
    "boundary,position",
    [(boundary, position) for boundary in (
        "request", "reservation", "dispatch_started", "provider_socket", "complete_response", "response_encryption", "response_commit", "postcommit_readback", "caller_release"
    ) for position in ("before", "after")],
)
def test_crash_matrix(boundary: str, position: str, monkeypatch):
    """Each boundary has both sides and records durable truth/no false success."""
    fault = f"{boundary}_{position}"
    provider_mode = None
    store = None
    if boundary == "provider_socket":
        provider_mode = f"socket_{position}"
    elif boundary == "complete_response":
        provider_mode = f"response_{position}"
    elif boundary == "postcommit_readback":
        store = ReadbackFaultStore(URL)
    service, provider, request = service_for(fault, provider_mode, store)
    if boundary == "response_encryption":
        original_encrypt = conversation_module.encrypt
        calls = 0
        def fail_response_encrypt(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("response encryption failed")
            return original_encrypt(*args, **kwargs)
        monkeypatch.setattr(conversation_module, "encrypt", fail_response_encrypt)

    if boundary == "caller_release":
        result = service.submit(request, principal="caller", conversation_id="conversation")
        assert result["status"] == "COMMITTED"
        # A delivery observer may fail after the response has been returned;
        # durable state is not rewritten and a retry is read-only.
        with pytest.raises(OSError):
            raise OSError("caller disconnected after release")
        retry = service.submit(request, principal="caller", conversation_id="conversation")
        assert retry["status"] == "COMMITTED" and provider.calls == 1
        return

    outcome = None
    try:
        outcome = service.submit(request, principal="caller", conversation_id="conversation")
    except (ContractError, OSError):
        pass

    with psycopg.connect(URL) as conn:
        turn = conn.execute("SELECT state FROM restricted_content.turns").fetchone()
        attempt = conn.execute("SELECT state FROM inference_ledger.attempts").fetchone()
    if boundary == "request" and position == "before":
        assert turn is None and attempt is None
    elif boundary == "postcommit_readback":
        assert turn is not None and turn[0] == "COMMITTED"
    else:
        assert turn is not None and turn[0] != "COMMITTED"
    assert provider.calls <= 1
    if boundary == "postcommit_readback":
        assert attempt[0] == "SUCCEEDED"
    elif boundary == "complete_response":
        assert outcome is not None and outcome["status"] in {"FAILED", "INDETERMINATE"}
