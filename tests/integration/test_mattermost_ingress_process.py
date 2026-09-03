"""Real process witness: TLS Mattermost HTTP/WebSocket peer to conversation.sock."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socketserver
import sqlite3
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
RAW_EVENT = "RAW_EVENT_CANARY_36db"


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
    decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload)) if mask else payload
    return first[0] & 0x0F, decoded


class ConversationHandler(socketserver.StreamRequestHandler):
    turns = 0
    mode = "success"

    def handle(self):
        if type(self).mode == "uds_timeout":
            time.sleep(3)
            return
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
                "tools_allowed": False, "fallbacks": [], "max_provider_attempts": 1,
                "streaming": False, "max_output_tokens": 4096,
                "max_canonical_input_utf8_bytes": 131072,
                "response_profile": "restricted-local-text-response.v1",
            }
        elif method == "POST" and path.endswith("/turns"):
            request = json.loads(body)
            type(self).turns += 1
            response = {
                "schema_version": "restricted-turn-result.v1", "turn_id": "turn-one",
                "conversation_epoch": request["conversation_epoch"], "status": "COMMITTED", "message": RESPONSE,
            }
        elif method == "POST" and path.startswith("/v1/restricted/conversations/"):
            response = {
                "schema_version": "restricted-conversation.v1",
                "conversation_id": path.rsplit("/", 1)[-1], "conversation_epoch": "epoch-one",
            }
        else:
            raise AssertionError((method, path))
        payload = jcs_bytes(response)
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(payload)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + payload
        )


class PeerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    posts = []
    delivered = threading.Event()
    mode = "success"
    websocket_connections = 0

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
        if self.path == "/api/v4/websocket":
            type(self).websocket_connections += 1
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            opcode, payload = _read_frame(self.rfile)
            assert opcode == 0x1
            auth = json.loads(payload)
            assert auth == {"action": "authentication_challenge", "data": {"token": TOKEN}, "seq": 1}
            status = "FAIL" if type(self).mode == "auth_failure" else "OK"
            self.wfile.write(_frame(jcs_bytes({"seq_reply": 1, "status": status})))
            self.wfile.flush()
            if status == "OK":
                if type(self).mode == "malformed_websocket":
                    self.wfile.write(_frame(("{\"" + RAW_EVENT).encode()))
                    self.wfile.flush()
                    time.sleep(1)
                    self.close_connection = True
                    return
                post = {
                    "id": ROOT_POST, "root_id": "", "channel_id": CHANNEL, "user_id": USER,
                    "message": MESSAGE, "type": "", "file_ids": [], "edit_at": 0, "delete_at": 0,
                }
                event = {"event": "posted", "data": {"post": json.dumps(post), "channel_type": "P"}}
                self.wfile.write(_frame(jcs_bytes(event)))
                self.wfile.flush()
                type(self).delivered.wait(10)
            self.close_connection = True
        elif self.path == "/api/v4/users/me":
            if type(self).mode == "rest_error":
                self._json({"error": "ERROR_BODY_CANARY_092a"}, 500)
            else:
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
            self._json({"error": "ERROR_BODY_CANARY_092a"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        if self.path != "/api/v4/posts":
            self._json({"error": "ERROR_BODY_CANARY_092a"}, 404)
            return
        type(self).posts.append(body)
        # The pinned Mattermost server can durably accept a create-post while
        # its immediate response disappears.  The edge must treat that as an
        # ambiguous attempt, not as a retryable delivery.
        if type(self).mode == "drop_post_response":
            type(self).delivered.set()
            self.close_connection = True
            return
        self._json({"id": "posted-reply", **body}, 201)
        type(self).delivered.set()


def _certificates(tmp_path: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "tls.key", tmp_path / "tls.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _policy(tmp_path: Path, port: int, *, fast_timeout: bool = False):
    now = datetime.now(UTC).replace(microsecond=0)
    value = {
        "schema_version": "restricted-mattermost-ingress-policy.v1", "policy_epoch": "mattermost-e1",
        "inference_policy_epoch": "inference-e1", "inference_policy_digest": "a" * 64,
        "tenant_id": "tenant-one", "origin": f"https://localhost:{port}", "team_id": TEAM,
        "allowed_channel_ids": [CHANNEL], "allowed_user_ids": [USER], "bot_user_id": BOT,
        "bot_username": "restricted-bot", "allowed_modality": "text", "dms_allowed": False,
        "files_allowed": False, "delivery_mode": "thread-only", "initiation_mode": "explicit-mention",
        "max_message_utf8_bytes": 4096,
        "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "clock_skew_seconds": 30, "websocket_timeout_seconds": 5, "rest_timeout_seconds": 5,
        "uds_timeout_seconds": 2 if fast_timeout else 45,
        "conversation_deadline_seconds": 1 if fast_timeout else 40,
        "outbox_key_fingerprint": hashlib.sha256(b"m" * 32).hexdigest(),
        "outbox_payload_retention_seconds": 3600,
        "outbox_payload_capacity": 1000,
        "outbox_tombstone_capacity": 1000,
        "outbox_scan_limit": 64,
    }
    private = ed25519.Ed25519PrivateKey.generate()
    policy, signature = tmp_path / "policy.json", tmp_path / "policy.sig"
    policy.write_bytes(jcs_bytes(value))
    signature.write_text(base64.b64encode(private.sign(jcs_bytes(value))).decode(), encoding="ascii")
    return policy, signature, base64.b64encode(private.public_key().public_bytes_raw()).decode()


@pytest.mark.parametrize(
    "mode",
    ["success", "malformed_websocket", "auth_failure", "rest_error", "uds_timeout"],
)
def test_production_entrypoint_real_paths_keep_diagnostics_content_free(tmp_path, mode):
    if os.geteuid() != 0:
        pytest.skip("exact conversation.sock process witness requires an isolated root runner")
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists():
        pytest.skip("conversation.sock already belongs to another runtime")
    if OUTBOX_STATE.exists():
        pytest.skip("outbox state path already belongs to another runtime")
    PeerHandler.mode = mode
    PeerHandler.posts = []
    PeerHandler.delivered = threading.Event()
    PeerHandler.websocket_connections = 0
    ConversationHandler.mode = mode
    ConversationHandler.turns = 0
    key_path, cert_path = _certificates(tmp_path)
    peer = ThreadingHTTPServer(("127.0.0.1", 0), PeerHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    peer_thread = threading.Thread(target=peer.serve_forever, daemon=True)
    peer_thread.start()
    conversation = socketserver.ThreadingUnixStreamServer(str(SOCKET), ConversationHandler)
    conversation_thread = threading.Thread(target=conversation.serve_forever, daemon=True)
    conversation_thread.start()
    policy, signature, public = _policy(tmp_path, peer.server_port, fast_timeout=mode == "uds_timeout")
    token = tmp_path / "token"
    token.write_text(TOKEN, encoding="utf-8")
    outbox_key = tmp_path / "outbox.key"
    outbox_key.write_bytes(b"m" * 32)
    os.chmod(outbox_key, 0o600)
    MattermostOutbox.initialize(OUTBOX_STATE, outbox_key, expected_fingerprint=key_fingerprint(b"m" * 32)).close()
    environment = {
        **os.environ, "PYTHONPATH": str(ROOT / "src"),
        "RESTRICTED_MATTERMOST_POLICY_PATH": str(policy),
        "RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH": str(signature),
        "RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64": public,
        "RESTRICTED_MATTERMOST_TOKEN_PATH": str(token),
        "RESTRICTED_MATTERMOST_CA_PATH": str(cert_path),
        "RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH": str(outbox_key),
        "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "restricted_runtime.services.production_mattermost_ingress"],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        if mode == "success":
            assert PeerHandler.delivered.wait(15)
            assert ConversationHandler.turns == 1
            assert len(PeerHandler.posts) == 1
            assert PeerHandler.posts[0]["channel_id"] == CHANNEL
            assert PeerHandler.posts[0]["root_id"] == ROOT_POST
        elif mode == "malformed_websocket":
            time.sleep(3)
            assert ConversationHandler.turns == 0
            assert PeerHandler.posts == []
            assert PeerHandler.websocket_connections >= 2
        else:
            assert process.wait(timeout=10) == 1
    finally:
        if process.poll() is None:
            process.terminate()
        stdout, stderr = process.communicate(timeout=10)
        peer.shutdown()
        peer.server_close()
        conversation.shutdown()
        conversation.server_close()
        SOCKET.unlink(missing_ok=True)
        shutil.rmtree(OUTBOX_STATE, ignore_errors=True)
    logs = stdout + stderr
    for canary in (TOKEN, MESSAGE, RESPONSE, RAW_EVENT, "ERROR_BODY_CANARY_092a", ROOT_POST):
        assert canary not in logs
    if mode == "success":
        assert "mattermost_ingress_outcome=authenticated_ready" in logs


@pytest.fixture(scope="module")
def installed_mattermost_ingress(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build once; every crash witness executes the wheel, never ``src``."""
    root = tmp_path_factory.mktemp("installed-mattermost-ingress")
    wheelhouse = root / "wheelhouse"
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", ".", "--wheel-dir", str(wheelhouse)],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=120,
    )
    wheel = next(wheelhouse.glob("restricted_hermes_runtime-*.whl"))
    site = root / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(wheel)],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=120,
    )
    return site


def _installed_environment(
    site: Path,
    policy: Path,
    signature: Path,
    public: str,
    token: Path,
    certificate: Path,
    outbox_key: Path,
    *,
    wrapper: Path | None = None,
) -> dict[str, str]:
    # ``src`` is deliberately absent.  ``cwd`` may be the repository root,
    # but that root does not contain the package; the child resolves only the
    # wheel target and an optional external crash wrapper.
    import_path = [str(site)] if wrapper is None else [str(wrapper), str(site)]
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(import_path),
        "PYTHONDONTWRITEBYTECODE": "1",
        "RESTRICTED_MATTERMOST_POLICY_PATH": str(policy),
        "RESTRICTED_MATTERMOST_POLICY_SIGNATURE_PATH": str(signature),
        "RESTRICTED_MATTERMOST_POLICY_PUBLIC_KEY_B64": public,
        "RESTRICTED_MATTERMOST_TOKEN_PATH": str(token),
        "RESTRICTED_MATTERMOST_CA_PATH": str(certificate),
        "RESTRICTED_MATTERMOST_OUTBOX_KEY_PATH": str(outbox_key),
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
    }


def _outbox_states() -> list[str]:
    database = OUTBOX_STATE / "mattermost-outbox.sqlite3"
    with sqlite3.connect(database) as connection:
        return [row[0] for row in connection.execute("SELECT state FROM records ORDER BY record_tag")]


def _wait_for(predicate, *, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for process witness state")


def _crash_wrapper(tmp_path: Path, stage: str) -> Path:
    """External installed-artifact crash injection; production remains untouched."""
    wrapper = tmp_path / f"crash-{stage}"
    wrapper.mkdir()
    if stage == "before_delivered_ack":
        source = """\
import os
from restricted_runtime.mattermost_outbox import DeliveryState, MattermostOutbox
_original = MattermostOutbox.terminal
def _stop(self, record, state, *, reason):
    if state is DeliveryState.DELIVERED:
        os._exit(86)
    return _original(self, record, state, reason=reason)
MattermostOutbox.terminal = _stop
"""
    elif stage == "after_inflight_before_http":
        source = """\
import os
from restricted_runtime.mattermost_ingress import MattermostRestClient
def _stop(self, body):
    os._exit(87)
MattermostRestClient.create_post = _stop
"""
    else:
        raise AssertionError(stage)
    (wrapper / "sitecustomize.py").write_text(source, encoding="utf-8")
    return wrapper


def _start_installed(site: Path, environment: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-B", "-m", "restricted_runtime.services.production_mattermost_ingress"],
        cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _stop(process: subprocess.Popen[str]) -> tuple[str, str]:
    if process.poll() is None:
        process.terminate()
    try:
        return process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate(timeout=10)


@pytest.mark.parametrize(
    ("stage", "expected_exit"),
    [("before_delivered_ack", 86), ("after_inflight_before_http", 87)],
)
def test_installed_process_crash_after_inflight_never_reposts_on_replay(
    tmp_path, installed_mattermost_ingress, stage, expected_exit,
):
    """A valid response/claimed dispatch killed externally becomes AMBIGUOUS."""
    if os.geteuid() != 0:
        pytest.skip("exact fixed-path process witness requires an isolated root runner")
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists() or OUTBOX_STATE.exists():
        pytest.skip("fixed process witness paths already belong to another runtime")
    PeerHandler.mode = "success"
    PeerHandler.posts = []
    PeerHandler.delivered = threading.Event()
    PeerHandler.websocket_connections = 0
    ConversationHandler.mode = "success"
    ConversationHandler.turns = 0
    key_path, cert_path = _certificates(tmp_path)
    peer = ThreadingHTTPServer(("127.0.0.1", 0), PeerHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    conversation = socketserver.ThreadingUnixStreamServer(str(SOCKET), ConversationHandler)
    threading.Thread(target=conversation.serve_forever, daemon=True).start()
    policy, signature, public = _policy(tmp_path, peer.server_port)
    token = tmp_path / "token"
    token.write_text(TOKEN, encoding="utf-8")
    outbox_key = tmp_path / "outbox.key"
    outbox_key.write_bytes(b"m" * 32)
    os.chmod(outbox_key, 0o600)
    MattermostOutbox.initialize(OUTBOX_STATE, outbox_key, expected_fingerprint=key_fingerprint(b"m" * 32)).close()
    wrapper = _crash_wrapper(tmp_path, stage)
    crashing = _start_installed(
        installed_mattermost_ingress,
        _installed_environment(installed_mattermost_ingress, policy, signature, public, token, cert_path, outbox_key, wrapper=wrapper),
    )
    restarted: subprocess.Popen[str] | None = None
    try:
        assert crashing.wait(timeout=15) == expected_exit
        if stage == "before_delivered_ack":
            assert len(PeerHandler.posts) == 1
        else:
            assert PeerHandler.posts == []
        assert _outbox_states() == ["IN_FLIGHT"]
        restarted = _start_installed(
            installed_mattermost_ingress,
            _installed_environment(installed_mattermost_ingress, policy, signature, public, token, cert_path, outbox_key),
        )
        _wait_for(lambda: _outbox_states() == ["AMBIGUOUS"])
        _wait_for(lambda: PeerHandler.websocket_connections >= 2)
        time.sleep(0.25)  # allow the replayed event to reach the executor
        assert (len(PeerHandler.posts), ConversationHandler.turns) == ((1, 1) if stage == "before_delivered_ack" else (0, 1))
    finally:
        if restarted is not None:
            _stop(restarted)
        _stop(crashing)
        peer.shutdown()
        peer.server_close()
        conversation.shutdown()
        conversation.server_close()
        SOCKET.unlink(missing_ok=True)
        shutil.rmtree(OUTBOX_STATE, ignore_errors=True)


def test_installed_process_dropped_post_response_is_ambiguous_and_never_reposts(
    tmp_path, installed_mattermost_ingress,
):
    """Mattermost may persist a post while the immediate response is lost."""
    if os.geteuid() != 0:
        pytest.skip("exact fixed-path process witness requires an isolated root runner")
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET.exists() or OUTBOX_STATE.exists():
        pytest.skip("fixed process witness paths already belong to another runtime")
    PeerHandler.mode = "drop_post_response"
    PeerHandler.posts = []
    PeerHandler.delivered = threading.Event()
    PeerHandler.websocket_connections = 0
    ConversationHandler.mode = "success"
    ConversationHandler.turns = 0
    key_path, cert_path = _certificates(tmp_path)
    peer = ThreadingHTTPServer(("127.0.0.1", 0), PeerHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    peer.socket = context.wrap_socket(peer.socket, server_side=True)
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    conversation = socketserver.ThreadingUnixStreamServer(str(SOCKET), ConversationHandler)
    threading.Thread(target=conversation.serve_forever, daemon=True).start()
    policy, signature, public = _policy(tmp_path, peer.server_port)
    token = tmp_path / "token"
    token.write_text(TOKEN, encoding="utf-8")
    outbox_key = tmp_path / "outbox.key"
    outbox_key.write_bytes(b"m" * 32)
    os.chmod(outbox_key, 0o600)
    MattermostOutbox.initialize(OUTBOX_STATE, outbox_key, expected_fingerprint=key_fingerprint(b"m" * 32)).close()
    first = _start_installed(
        installed_mattermost_ingress,
        _installed_environment(installed_mattermost_ingress, policy, signature, public, token, cert_path, outbox_key),
    )
    restarted: subprocess.Popen[str] | None = None
    try:
        assert PeerHandler.delivered.wait(15)
        _wait_for(lambda: _outbox_states() == ["AMBIGUOUS"])
        assert (len(PeerHandler.posts), ConversationHandler.turns) == (1, 1)
        _stop(first)
        restarted = _start_installed(
            installed_mattermost_ingress,
            _installed_environment(installed_mattermost_ingress, policy, signature, public, token, cert_path, outbox_key),
        )
        _wait_for(lambda: PeerHandler.websocket_connections >= 2)
        time.sleep(0.25)
        assert _outbox_states() == ["AMBIGUOUS"]
        assert (len(PeerHandler.posts), ConversationHandler.turns) == (1, 1)
    finally:
        _stop(first)
        if restarted is not None:
            _stop(restarted)
        peer.shutdown()
        peer.server_close()
        conversation.shutdown()
        conversation.server_close()
        SOCKET.unlink(missing_ok=True)
        shutil.rmtree(OUTBOX_STATE, ignore_errors=True)
