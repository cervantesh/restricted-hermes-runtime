"""Causal production-process witness for the signed Mattermost UDS deadline."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from restricted_runtime.contracts import jcs_bytes
from restricted_runtime.mattermost_outbox import MattermostOutbox, key_fingerprint


pytestmark = pytest.mark.skipif(os.name == "nt", reason="real AF_UNIX ingress process witness")
ROOT = Path(__file__).resolve().parents[2]
SOCKET = Path("/run/restricted-inference/conversation.sock")
OUTBOX_STATE = Path("/var/lib/restricted-mattermost-outbox")
TEAM = "team0000000000000000000000"
CHANNEL = "chan0000000000000000000000"
USER = "user0000000000000000000000"
BOT = "bot00000000000000000000000"
ROOT_POST = "root0000000000000000000000"
TOKEN = "TOKEN_CANARY_7c98"
MESSAGE = "@restricted-bot MESSAGE_CANARY_718d"
RESPONSE = "RESPONSE_CANARY_c4a1"
_CAUSAL_DELIVERY_WINDOW_SECONDS = 3
_STARTUP_WINDOW_SECONDS = 10


def _frame(payload: bytes) -> bytes:
    if len(payload) < 126:
        return bytes((0x81, len(payload))) + payload
    return b"\x81\x7e" + len(payload).to_bytes(2, "big") + payload


def _read_frame(stream) -> tuple[int, bytes]:
    first = stream.read(2)
    if len(first) != 2:
        raise EOFError
    length = first[1] & 0x7F
    if length == 126:
        length = int.from_bytes(stream.read(2), "big")
    elif length == 127:
        length = int.from_bytes(stream.read(8), "big")
    mask = stream.read(4) if first[1] & 0x80 else b""
    payload = stream.read(length)
    return first[0] & 0x0F, bytes(value ^ mask[index % 4] for index, value in enumerate(payload)) if mask else payload


class _State:
    def __init__(self, mode: str):
        self.mode = mode
        self.ready = self.creates = self.turns = 0
        self.posts: list[dict] = []
        self.event_sent = threading.Event()
        self.create_received = threading.Event()
        self.turn_received = threading.Event()
        self.delivered = threading.Event()
        self.release = threading.Event()


class _ConversationHandler(socketserver.StreamRequestHandler):
    def handle(self):
        state: _State = self.server.state
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
            state.ready += 1
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
            state.turn_received.set()
            if state.mode == "second_hop":
                time.sleep(1.2)
            response = {
                "schema_version": "restricted-turn-result.v1", "turn_id": "turn-one",
                "conversation_epoch": request["conversation_epoch"], "status": "COMMITTED", "message": RESPONSE,
            }
        elif method == "POST" and path.startswith("/v1/restricted/conversations/"):
            state.creates += 1
            state.create_received.set()
            if state.mode == "first_hop":
                time.sleep(1.2)
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
            # The peer hit its deadline after a valid request was accepted.
            pass


class _MattermostPeer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def _json(self, value, status=200):
        payload = jcs_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        state: _State = self.server.state
        if self.path == "/api/v4/websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            opcode, payload = _read_frame(self.rfile)
            assert opcode == 0x1
            assert json.loads(payload) == {"action": "authentication_challenge", "data": {"token": TOKEN}, "seq": 1}
            self.wfile.write(_frame(jcs_bytes({"seq_reply": 1, "status": "OK"})))
            post = {
                "id": ROOT_POST, "root_id": "", "channel_id": CHANNEL, "user_id": USER,
                "message": MESSAGE, "type": "", "file_ids": [], "edit_at": 0, "delete_at": 0,
            }
            event = {"event": "posted", "data": {"post": json.dumps(post), "channel_type": "P"}}
            self.wfile.write(_frame(jcs_bytes(event)))
            self.wfile.flush()
            state.event_sent.set()
            state.release.wait(10)
            self.close_connection = True
        elif self.path == "/api/v4/users/me":
            self._json({"id": BOT, "username": "restricted-bot"})
        elif self.path == "/api/v4/channels/" + CHANNEL:
            self._json({"id": CHANNEL, "team_id": TEAM, "type": "P"})
        elif self.path in {
            "/api/v4/channels/" + CHANNEL + "/members/" + USER,
            "/api/v4/channels/" + CHANNEL + "/members/" + BOT,
        }:
            self._json({"channel_id": CHANNEL, "user_id": self.path.rsplit("/", 1)[-1]})
        elif self.path == "/api/v4/posts/" + ROOT_POST:
            self._json({
                "id": ROOT_POST, "root_id": "", "channel_id": CHANNEL, "user_id": USER,
                "message": MESSAGE, "type": "", "file_ids": [], "edit_at": 0, "delete_at": 0,
            })
        else:
            self._json({"error": "rejected"}, 404)

    def do_POST(self):
        state: _State = self.server.state
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        assert self.path == "/api/v4/posts"
        state.posts.append(body)
        self._json({"id": "posted-reply", **body}, 201)
        state.delivered.set()


def _certificates(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "tls.key", tmp_path / "tls.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _policy(tmp_path: Path, port: int) -> tuple[Path, Path, str]:
    now = datetime.now(UTC).replace(microsecond=0)
    value = {
        "schema_version": "restricted-mattermost-ingress-policy.v1", "policy_epoch": "mattermost-e1",
        "inference_policy_epoch": "inference-e1", "inference_policy_digest": "a" * 64,
        "tenant_id": "tenant-one", "origin": f"https://127.0.0.1:{port}", "team_id": TEAM,
        "allowed_channel_ids": [CHANNEL], "allowed_user_ids": [USER], "bot_user_id": BOT,
        "bot_username": "restricted-bot", "allowed_modality": "text", "dms_allowed": False,
        "files_allowed": False, "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096,
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "clock_skew_seconds": 30, "websocket_timeout_seconds": 5, "rest_timeout_seconds": 5,
        "uds_timeout_seconds": 2, "conversation_deadline_seconds": 1,
        "outbox_key_fingerprint": hashlib.sha256(b"m" * 32).hexdigest(), "outbox_payload_retention_seconds": 3600,
        "outbox_payload_capacity": 1000, "outbox_tombstone_capacity": 1000,
        "outbox_scan_limit": 64,
    }
    private = ed25519.Ed25519PrivateKey.generate()
    policy, signature = tmp_path / "policy.json", tmp_path / "policy.sig"
    policy.write_bytes(jcs_bytes(value))
    signature.write_text(base64.b64encode(private.sign(jcs_bytes(value))).decode(), encoding="ascii")
    return policy, signature, base64.b64encode(private.public_key().public_bytes_raw()).decode()


def _witness(tmp_path: Path, mode: str, *, expect_delivery: bool) -> tuple[int, int, int, int]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists():
        pytest.skip("conversation.sock already belongs to another runtime")
    if OUTBOX_STATE.exists():
        pytest.skip("outbox state path already belongs to another runtime")
    state = _State(mode)
    key_path, cert_path = _certificates(tmp_path)
    peer = ThreadingHTTPServer(("127.0.0.1", 0), _MattermostPeer)
    peer.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    peer_thread = threading.Thread(target=peer.serve_forever, daemon=True)
    peer_thread.start()
    conversation = socketserver.ThreadingUnixStreamServer(str(SOCKET), _ConversationHandler)
    conversation.state = state
    conversation_thread = threading.Thread(target=conversation.serve_forever, daemon=True)
    conversation_thread.start()
    policy, signature, public = _policy(tmp_path, peer.server_port)
    token = tmp_path / "token"
    token.write_text(TOKEN, encoding="utf-8")
    outbox_key = tmp_path / "outbox.key"
    outbox_key.write_bytes(b"m" * 32)
    os.chmod(outbox_key, 0o600)
    MattermostOutbox.initialize(OUTBOX_STATE, outbox_key, expected_fingerprint=key_fingerprint(b"m" * 32)).close()
    environment = {
        **os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
        "RESTRICTED_MATTERMOST_POLICY_PATH": str(policy),
        "RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH": str(signature),
        "RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64": public,
        "RESTRICTED_MATTERMOST_TOKEN_PATH": str(token),
        "RESTRICTED_MATTERMOST_CA_PATH": str(cert_path),
        "RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH": str(outbox_key),
    }
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "restricted_runtime.services.production_mattermost_ingress"],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        if not state.event_sent.wait(_STARTUP_WINDOW_SECONDS):
            if process.poll() is None:
                process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            pytest.fail(f"production ingress did not authenticate or receive the event; stdout={stdout!r} stderr={stderr!r}")
        if mode == "first_hop":
            assert state.create_received.wait(5)
        elif mode == "second_hop":
            assert state.turn_received.wait(5)
        # The delayed peer has accepted a valid request.  Wait for the full
        # causal window instead of sampling counters immediately afterwards:
        # a product that restores independent request deadlines must be able
        # to complete the next hop and post its reply during this window.
        assert state.delivered.wait(_CAUSAL_DELIVERY_WINDOW_SECONDS) is expect_delivery
        return state.ready, state.creates, state.turns, len(state.posts)
    finally:
        state.release.set()
        try:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=10)
        finally:
            peer.shutdown()
            peer.server_close()
            conversation.shutdown()
            conversation.server_close()
            SOCKET.unlink(missing_ok=True)
            shutil.rmtree(OUTBOX_STATE, ignore_errors=True)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("success", (1, 1, 1, 1)), ("first_hop", (1, 1, 0, 0)), ("second_hop", (1, 1, 1, 0))],
)
def test_authenticated_production_event_path_shares_one_signed_uds_deadline(tmp_path, mode, expected):
    assert _witness(tmp_path, mode, expect_delivery=mode == "success") == expected


def test_deadline_witness_bites_against_the_installed_independent_request_mutation(tmp_path):
    assert _witness(tmp_path / "shared", "first_hop", expect_delivery=False) == (1, 1, 0, 0)
    source_path = ROOT / "src" / "restricted_runtime" / "mattermost_ingress.py"
    original = source_path.read_text(encoding="utf-8")
    mutated = original.replace("deadline=deadline", "deadline=None").replace(
        "if deadline - time.monotonic() <= 0:", "if False:"
    )
    assert mutated != original
    try:
        source_path.write_text(mutated, encoding="utf-8")
        assert "deadline=None" in source_path.read_text(encoding="utf-8")
        assert _witness(tmp_path / "independent", "first_hop", expect_delivery=True) == (1, 1, 1, 1)
    finally:
        source_path.write_text(original, encoding="utf-8")
