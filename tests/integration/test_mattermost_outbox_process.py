"""Process-level RED/GREEN witness for durable Mattermost delivery recovery."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint


pytestmark = pytest.mark.skipif(os.name == "nt", reason="real AF_UNIX ingress process witness")
ROOT = Path(__file__).resolve().parents[2]
SOCKET = Path("/run/restricted-inference/conversation.sock")
OUTBOX_STATE = Path("/var/lib/restricted-mattermost-outbox")
_HELPER_PATH = ROOT / "tests" / "integration" / "test_mattermost_ingress_deadline_process.py"


def _helpers():
    spec = importlib.util.spec_from_file_location("outbox_deadline_helpers", _HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_crash_after_committed_turn_replay_repeats_without_a_durable_outbox(tmp_path):
    """Exact-base RED: a new ingress process forgets a committed source event."""
    if os.geteuid() != 0:
        pytest.skip("isolated conversation.sock process witness requires a writable socket directory")
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists():
        pytest.skip("conversation.sock already belongs to another runtime")
    helper = _helpers()
    state = helper._State("success")
    state.turn_committed = threading.Event()
    state.allow_turn_response = threading.Event()
    key_path, cert_path = helper._certificates(tmp_path)
    peer = helper.ThreadingHTTPServer(("127.0.0.1", 0), helper._MattermostPeer)
    peer.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    class ConversationHandler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline(4096)
            headers = {}
            while True:
                item = self.rfile.readline(4096)
                if item == b"\r\n":
                    break
                key, value = item.decode("ascii").split(":", 1)
                headers[key.lower()] = value.strip()
            body = self.rfile.read(int(headers.get("content-length", "0")))
            method, path, _ = line.decode("ascii").strip().split(" ")
            if method == "GET" and path == "/readyz":
                response = {
                    "schema_version": "restricted-conversation-readiness.v1", "status": "ready",
                    "policy_epoch": "inference-e1", "policy_digest": "a" * 64, "classification": "PHI",
                    "system_instruction_version": "restricted-phi-system.v1", "allowed_modalities": ["text"],
                    "tools_allowed": False, "fallbacks": [], "max_provider_attempts": 1, "streaming": False,
                    "max_output_tokens": 4096, "max_canonical_input_utf8_bytes": 131072,
                    "response_profile": "restricted-local-text-response.v1",
                }
            elif method == "POST" and path.endswith("/turns"):
                request = json.loads(body)
                state.turns += 1
                state.turn_committed.set()
                assert state.allow_turn_response.wait(10)
                response = {
                    "schema_version": "restricted-turn-result.v1", "turn_id": "turn-one",
                    "conversation_epoch": request["conversation_epoch"], "status": "COMMITTED",
                    "message": helper.RESPONSE,
                }
            elif method == "POST" and path.startswith("/v1/restricted/conversations/"):
                response = {
                    "schema_version": "restricted-conversation.v1",
                    "conversation_id": path.rsplit("/", 1)[-1], "conversation_epoch": "epoch-one",
                }
            else:
                raise AssertionError((method, path))
            payload = jcs_bytes(response)
            try:
                self.wfile.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(payload)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + payload
                )
                self.wfile.flush()
            except BrokenPipeError:
                pass

    conversation = socketserver.ThreadingUnixStreamServer(str(SOCKET), ConversationHandler)
    conversation.state = state
    threading.Thread(target=conversation.serve_forever, daemon=True).start()
    policy, signature, public = helper._policy(tmp_path, peer.server_port)
    token = tmp_path / "token"
    token.write_text(helper.TOKEN, encoding="utf-8")
    key = tmp_path / "outbox.key"
    key.write_bytes(b"m" * 32)
    os.chmod(key, 0o600)
    if OUTBOX_STATE.exists():
        pytest.skip("outbox state path already belongs to another runtime")
    MattermostOutbox.initialize(OUTBOX_STATE, key, expected_fingerprint=key_fingerprint(b"m" * 32)).close()
    environment = {
        **os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
        "RESTRICTED_MATTERMOST_POLICY_PATH": str(policy),
        "RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH": str(signature),
        "RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64": public,
        "RESTRICTED_MATTERMOST_TOKEN_PATH": str(token),
        "RESTRICTED_MATTERMOST_CA_PATH": str(cert_path),
        "RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH": str(key),
    }

    def start():
        return subprocess.Popen(
            [sys.executable, "-B", "-m", "restricted_runtime.services.production_mattermost_ingress"],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    first = start()
    try:
        assert state.event_sent.wait(5)
        assert state.turn_committed.wait(5)
        # The fake conversation service has accepted/committed this turn but
        # withholds its response; killing here models the observed loss window.
        first.terminate()
        first.communicate(timeout=10)
        state.allow_turn_response.set()
        state.release.set()
        state.event_sent.clear()
        state.turn_committed.clear()
        second = start()
        try:
            assert state.event_sent.wait(5)
            assert state.turn_committed.wait(5)
            assert state.delivered.wait(5)
        finally:
            state.release.set()
            if second.poll() is None:
                second.terminate()
            second.communicate(timeout=10)
        # A crash after the downstream turn committed but before READY may
        # cause a second *transport* submission.  The contract deliberately
        # reuses the persisted epoch/request so the real conversation service
        # treats it as an idempotent readback.  This constant fake peer is
        # intentionally non-idempotent, so it witnesses the two causal UDS
        # calls only; the PostgreSQL witness proves one durable row/provider
        # dispatch for the same window.
        assert state.turns == 2
    finally:
        state.release.set()
        if first.poll() is None:
            first.terminate()
        first.communicate(timeout=10)
        peer.shutdown()
        peer.server_close()
        conversation.shutdown()
        conversation.server_close()
        SOCKET.unlink(missing_ok=True)
        shutil.rmtree(OUTBOX_STATE, ignore_errors=True)
