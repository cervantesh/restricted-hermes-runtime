"""PostgreSQL-backed recovery proof for the Mattermost delivery outbox.

The pause between the first ``/turns`` reply and the local READY transition is
intentional: it models an externally killed ingress process.  The replacement
edge must replay the persisted epoch/request pair.  Two UDS HTTP requests are
therefore possible, but the real conversation service must retain one turn and
the only stub in this composition -- the provider -- must dispatch once.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
import uvicorn
from fastapi import FastAPI

from restricted_runtime.auth import LocalSocketAuthenticator
from restricted_runtime.contracts import ProviderResult, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.mattermost_ingress import ConversationUdsClient, Ingress, MattermostEvent
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox, key_fingerprint
from restricted_runtime.mattermost_policy import MattermostPolicy
from restricted_runtime.policy import LOCAL_POLICY_SCHEMA, PolicyBundle
from restricted_runtime.services.restricted_api import create_app as conversation_app
from restricted_runtime.storage import PostgresContentStore, PostgresLedger


DATABASE_URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    os.name == "nt" or not DATABASE_URL,
    reason="requires an isolated PostgreSQL database and POSIX AF_UNIX",
)

SOCKET = Path("/run/restricted-inference/conversation.sock")
TEAM = "team0000000000000000000000"
CHANNEL = "chan0000000000000000000"
USER = "user0000000000000000000000"
BOT = "bot00000000000000000000000"
ROOT = "root0000000000000000000000"
OUTBOX_KEY = b"m" * 32


class _Keys:
    def wrap(self, value: bytes) -> bytes: return value
    def unwrap(self, value: bytes) -> bytes: return value


class _CountingProvider:
    def __init__(self) -> None: self.calls = 0
    def generate_content(self, _messages):
        self.calls += 1
        return ProviderResult("SUCCEEDED", text="synthetic committed response")


class _Rest:
    def __init__(self, source: dict[str, object]) -> None:
        self.source = source
        self.posts = {ROOT: source}
        self.created: list[dict[str, object]] = []

    def get_me(self): return {"id": BOT, "username": "restricted-bot"}
    def get_channel(self, channel_id): return {"id": channel_id, "team_id": TEAM, "type": "P"}
    def get_channel_member(self, channel_id, user_id): return {"channel_id": channel_id, "user_id": user_id}
    def get_post(self, post_id): return self.posts[post_id]
    def create_post(self, body):
        self.created.append(body)
        return {"id": "reply000000000000000000000", **body}


def _runtime_policy() -> PolicyBundle:
    values = {
        "schema_version": LOCAL_POLICY_SCHEMA, "policy_epoch": "inference-e1",
        "system_instruction_version": "restricted-phi-system.v1",
        "system_instruction_sha256": "afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b",
        "authorization_status": "operator-authorization-required", "external_runner_principal": "runner",
        "gateway_invoker_principal": "gateway", "tenant_id": "tenant-one", "classification": "PHI",
        "provider": "local-uds", "socket_path": "/run/restricted-inference/broker.sock",
        "method": "restrictedGenerate", "model": "operator-model", "model_sha256": "a" * 64,
        "response_profile": "restricted-local-text-response.v1", "streaming": False, "fallbacks": [],
        "max_provider_attempts": 1, "allowed_modalities": ["text"], "tools_allowed": False,
        "candidate_count": 1, "max_output_tokens": 4096, "max_canonical_input_utf8_bytes": 131072,
    }
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    return policy


def _edge_policy(runtime: PolicyBundle) -> MattermostPolicy:
    now = datetime.now(UTC).replace(microsecond=0)
    values = {
        "schema_version": "restricted-mattermost-ingress-policy.v1", "policy_epoch": "mattermost-e1",
        "inference_policy_epoch": runtime.epoch, "inference_policy_digest": runtime.digest,
        "tenant_id": "tenant-one", "origin": "https://mattermost.internal.example", "team_id": TEAM,
        "allowed_channel_ids": [CHANNEL], "allowed_user_ids": [USER], "bot_user_id": BOT,
        "bot_username": "restricted-bot", "allowed_modality": "text", "dms_allowed": False,
        "files_allowed": False, "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096,
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "clock_skew_seconds": 30, "websocket_timeout_seconds": 5, "rest_timeout_seconds": 5,
        "uds_timeout_seconds": 5, "conversation_deadline_seconds": 4,
        "outbox_key_fingerprint": key_fingerprint(OUTBOX_KEY), "outbox_payload_retention_seconds": 3600,
        "outbox_payload_capacity": 100, "outbox_tombstone_capacity": 100, "outbox_scan_limit": 20, "outbox_scan_interval_seconds": 5,
    }
    policy = MattermostPolicy(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    return policy


def _source() -> dict[str, object]:
    return {
        "id": ROOT, "root_id": "", "channel_id": CHANNEL, "user_id": USER,
        "message": "@restricted-bot synthetic outbox recovery", "type": "", "file_ids": [],
        "edit_at": 0, "delete_at": 0,
    }


def _event(source: dict[str, object]) -> MattermostEvent:
    return MattermostEvent.parse(jcs_bytes({"event": "posted", "data": {"post": json.dumps(source), "channel_type": "P"}}))


def _start_socket(app: FastAPI):
    if SOCKET.exists():
        pytest.skip("conversation.sock already belongs to another runtime")
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(SOCKET))
    listener.listen()
    config = uvicorn.Config(app, fd=listener.fileno(), lifespan="off", log_level="error", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = __import__("time").monotonic() + 5
    while not server.started and __import__("time").monotonic() < deadline:
        __import__("time").sleep(0.01)
    assert server.started
    return server, thread, listener


@pytest.fixture(autouse=True)
def _isolated_postgres():
    with psycopg.connect(DATABASE_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        connection.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        connection.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")
    yield


def test_real_postgres_recovery_replays_original_epoch_without_second_provider_dispatch(tmp_path):
    runtime_policy = _runtime_policy()
    provider = _CountingProvider()
    gateway_key = LocalHmacKey("gateway", "v1", b"g" * 32)
    service = ConversationService(
        PostgresContentStore(DATABASE_URL),
        Gateway(runtime_policy, gateway_key, PostgresLedger(DATABASE_URL, runtime_policy, gateway_key), provider),
        LocalHmacKey("service", "v1", b"s" * 32), _Keys(), runtime_policy, "tenant-one",
    )
    server = thread = listener = None
    outbox = None
    try:
        server, thread, listener = _start_socket(conversation_app(service, LocalSocketAuthenticator("runner"), gateway_ready=lambda: True))
        policy = _edge_policy(runtime_policy)
        source = _source()
        rest = _Rest(source)
        key_path = tmp_path / "outbox.key"
        key_path.write_bytes(OUTBOX_KEY)
        os.chmod(key_path, 0o600)
        outbox = MattermostOutbox.initialize(tmp_path / "outbox", key_path, expected_fingerprint=policy.values["outbox_key_fingerprint"])
        first = Ingress(policy, rest, ConversationUdsClient(policy), outbox)
        first.preflight()
        root_id = first._authorize_source(source)
        envelope = first._envelope(source, root_id)
        record, created = outbox.reserve(envelope, payload_capacity=100, tombstone_capacity=100)
        assert created and record.state is DeliveryState.WAITING_COMMIT
        # External crash injection boundary: conversation has returned a durable
        # response, while the old process has not written READY locally.
        created_response = first.conversation.create_conversation(conversation_id=envelope["conversation_id"])
        envelope = {**envelope, "conversation_epoch": created_response["conversation_epoch"]}
        record = outbox.update_waiting(record, envelope)
        committed = first.conversation.submit_turn(
            conversation_id=envelope["conversation_id"], conversation_epoch=envelope["conversation_epoch"],
            client_request_id=envelope["client_request_id"], message=envelope["message"],
        )
        assert committed["status"] == "COMMITTED" and provider.calls == 1
        original_epoch = envelope["conversation_epoch"]
        outbox.close()
        outbox = MattermostOutbox.open(tmp_path / "outbox", key_path, expected_fingerprint=policy.values["outbox_key_fingerprint"])
        recovered = Ingress(policy, rest, ConversationUdsClient(policy), outbox)
        recovered.preflight()  # startup drain performs the exact persisted replay and one POST attempt
        result = outbox.candidates(20)
        assert result == []
        durable = outbox.get(record.record_tag)
        assert durable is not None and durable.state is DeliveryState.DELIVERED and durable.envelope is None
        assert provider.calls == 1
        assert len(rest.created) == 1 and rest.created[0]["root_id"] == ROOT
        with psycopg.connect(DATABASE_URL) as connection:
            turns = connection.execute("SELECT conversation_epoch, state FROM restricted_content.turns").fetchall()
        assert turns == [(original_epoch, "COMMITTED")]
        # Replay of the Mattermost source resolves to its tombstone before capacity
        # and cannot create another turn or delivery.
        recovered.mark_authenticated()
        recovered.handle(_event(source))
        assert provider.calls == 1 and len(rest.created) == 1
    finally:
        if outbox is not None:
            outbox.close()
        if server is not None:
            server.should_exit = True
            thread.join(5)
            listener.close()
        SOCKET.unlink(missing_ok=True)
