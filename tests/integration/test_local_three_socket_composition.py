"""Real three-UDS local composition over an isolated PostgreSQL database."""
from __future__ import annotations

import hashlib
import os
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import httpx
import psycopg
import pytest
import uvicorn
from fastapi import FastAPI, Request

from restricted_runtime.auth import LocalSocketAuthenticator
from restricted_runtime.contracts import ProviderResult, TurnRequest, jcs_bytes
from restricted_runtime.conversation import ConversationService
from restricted_runtime.crypto import LocalHmacKey
from restricted_runtime.gateway import Gateway
from restricted_runtime.local_gateway_client import LocalGatewayClient
from restricted_runtime.local_uds import LocalUdsClient
from restricted_runtime.policy import LOCAL_POLICY_SCHEMA, PolicyBundle
from restricted_runtime.services.gateway_api import create_app as gateway_app
from restricted_runtime.services.restricted_api import create_app as conversation_app
from restricted_runtime.conversation_storage import PostgresContentStore
from restricted_runtime.storage import PostgresLedger


DATABASE_URL = os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    os.name != "posix" or not DATABASE_URL,
    reason="requires POSIX AF_UNIX and RESTRICTED_RUNTIME_TEST_DATABASE_URL isolated PostgreSQL",
)

_RUN_DIR = Path("/run/restricted-inference")
_CONVERSATION_SOCKET = _RUN_DIR / "conversation.sock"
_GATEWAY_SOCKET = _RUN_DIR / "gateway.sock"
_BROKER_SOCKET = _RUN_DIR / "broker.sock"


def _policy() -> PolicyBundle:
    values = {
        "schema_version": LOCAL_POLICY_SCHEMA,
        "policy_epoch": "three-socket-e1",
        "system_instruction_version": "restricted-phi-system.v1",
        "system_instruction_sha256": "afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b",
        "authorization_status": "operator-authorization-required",
        "external_runner_principal": "runner",
        "gateway_invoker_principal": "gateway",
        "tenant_id": "tenant",
        "classification": "PHI",
        "provider": "local-uds",
        "socket_path": str(_BROKER_SOCKET),
        "method": "restrictedGenerate",
        "model": "operator-model",
        "model_sha256": "a" * 64,
        "response_profile": "restricted-local-text-response.v1",
        "streaming": False,
        "fallbacks": [],
        "max_provider_attempts": 1,
        "allowed_modalities": ["text"],
        "tools_allowed": False,
        "candidate_count": 1,
        "max_output_tokens": 4096,
        "max_canonical_input_utf8_bytes": 131072,
    }
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    return policy


class _Keys:
    def wrap(self, key: bytes) -> bytes: return key
    def unwrap(self, key: bytes) -> bytes: return key


def _start_uds(app, path: Path, *, server_header: bool = False, date_header: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = path.lstat()
        if stat.S_ISSOCK(existing.st_mode) and existing.st_uid == os.geteuid():
            path.unlink()
        else:
            raise RuntimeError(f"unsafe test socket path: {path}")
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    os.chmod(path, 0o660)
    config = uvicorn.Config(app, fd=sock.fileno(), lifespan="off", log_level="error", access_log=False, server_header=server_header, date_header=date_header)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, f"UDS server did not start: {path}"
    return server, thread, sock


def _stop_uds(server, thread, sock, path: Path):
    server.should_exit = True
    thread.join(5)
    sock.close()
    path.unlink(missing_ok=True)
    assert not thread.is_alive()


def _assert_unrelated_uid_denied(path: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("unrelated-UID UDS ACL proof requires a root POSIX test runner")
    probe = subprocess.run(
        [sys.executable, "-c", "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/restricted-inference/conversation.sock')"],
        user=65534,
        group=65534,
        extra_groups=[],
        capture_output=True,
        text=True,
    )
    assert probe.returncode != 0
    assert not path.exists() or stat.S_IMODE(path.stat().st_mode) == 0o660


@pytest.fixture(autouse=True)
def isolated_database():
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS restricted_content CASCADE; DROP SCHEMA IF EXISTS inference_ledger CASCADE")
        conn.execute(Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8"))
        conn.execute("UPDATE inference_ledger.runtime_controls SET dispatch_enabled=true WHERE control_key=true")
    for path in (_CONVERSATION_SOCKET, _GATEWAY_SOCKET, _BROKER_SOCKET):
        path.unlink(missing_ok=True)
    yield
    for path in (_CONVERSATION_SOCKET, _GATEWAY_SOCKET, _BROKER_SOCKET):
        path.unlink(missing_ok=True)


def test_real_three_socket_composition_commits_and_reads_back_once():
    policy = _policy()
    broker_calls: list[bytes] = []
    broker = FastAPI()

    @broker.post("/v1/restricted/generate")
    async def generate(request: Request):
        broker_calls.append(await request.body())
        return {
            "schema_version": "restricted-local-inference-response.v1",
            "state": "SUCCEEDED",
            "finish_reason": "STOP",
            "text": "synthetic three-socket response",
            "model_sha256": policy.values["model_sha256"],
            "request_id": "broker-request-1",
        }

    broker_server, broker_thread, broker_sock = _start_uds(broker, _BROKER_SOCKET)
    gateway_server = gateway_thread = gateway_sock = None
    conversation_server = conversation_thread = conversation_sock = None
    try:
        provider = LocalUdsClient(policy)
        gateway = Gateway(policy, LocalHmacKey("gateway", "v1", b"g" * 32), PostgresLedger(DATABASE_URL, policy), provider)
        gateway_server, gateway_thread, gateway_sock = _start_uds(
            gateway_app(gateway, LocalSocketAuthenticator("gateway")), _GATEWAY_SOCKET
        )
        service = ConversationService(
            PostgresContentStore(DATABASE_URL),
            LocalGatewayClient(str(_GATEWAY_SOCKET)),
            LocalHmacKey("service", "v1", b"s" * 32),
            _Keys(),
            policy,
            "tenant",
        )
        conversation_server, conversation_thread, conversation_sock = _start_uds(
            conversation_app(service, LocalSocketAuthenticator("runner")), _CONVERSATION_SOCKET
        )
        transport = httpx.HTTPTransport(uds=str(_CONVERSATION_SOCKET), retries=0)
        with httpx.Client(transport=transport, base_url="http://localhost", timeout=10, trust_env=False) as operator:
            created = operator.post("/v1/restricted/conversations/three-socket")
            assert created.status_code == 200, created.text
            epoch = created.json()["conversation_epoch"]
            payload = {
                "schema_version": "restricted-turn.v1",
                "client_request_id": str(uuid.uuid4()),
                "conversation_epoch": epoch,
                "message": "synthetic non-PHI probe",
            }
            first = operator.post("/v1/restricted/conversations/three-socket/turns", json=payload)
            second = operator.post("/v1/restricted/conversations/three-socket/turns", json=payload)
        assert first.status_code == second.status_code == 200, (first.text, second.text)
        assert first.json()["status"] == second.json()["status"] == "COMMITTED"
        assert first.json()["message"] == second.json()["message"] == "synthetic three-socket response"
        assert len(broker_calls) == 1
        with psycopg.connect(DATABASE_URL) as conn:
            row = conn.execute("SELECT state, response_ciphertext, gateway_decision_id FROM restricted_content.turns").fetchone()
            assert row[0] == "COMMITTED" and row[1] and row[2] is not None
            assert b"synthetic" not in bytes(row[1])
        _assert_unrelated_uid_denied(_CONVERSATION_SOCKET)
    finally:
        if conversation_server is not None:
            _stop_uds(conversation_server, conversation_thread, conversation_sock, _CONVERSATION_SOCKET)
        if gateway_server is not None:
            _stop_uds(gateway_server, gateway_thread, gateway_sock, _GATEWAY_SOCKET)
        _stop_uds(broker_server, broker_thread, broker_sock, _BROKER_SOCKET)


def test_real_uvicorn_closed_headers_are_required_by_local_broker_parser():
    policy = _policy()
    broker = FastAPI()

    @broker.post("/v1/restricted/generate")
    async def generate():
        return {
            "schema_version": "restricted-local-inference-response.v1",
            "state": "SUCCEEDED",
            "finish_reason": "STOP",
            "text": "synthetic header probe",
            "model_sha256": policy.values["model_sha256"],
            "request_id": "broker-header-probe",
        }

    server, thread, sock = _start_uds(broker, _BROKER_SOCKET, server_header=True, date_header=True)
    try:
        result = LocalUdsClient(policy).generate_content([{"role": "user", "text": "synthetic"}])
        assert result.state == "INDETERMINATE"
    finally:
        _stop_uds(server, thread, sock, _BROKER_SOCKET)

    server, thread, sock = _start_uds(broker, _BROKER_SOCKET)
    try:
        result = LocalUdsClient(policy).generate_content([{"role": "user", "text": "synthetic"}])
        assert result.state == "SUCCEEDED"
    finally:
        _stop_uds(server, thread, sock, _BROKER_SOCKET)
