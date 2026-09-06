from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import shutil
from pathlib import Path

import pytest

from restricted_runtime.contracts import jcs_bytes


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED"),
    reason="requires Linux AF_UNIX peer credentials",
)

ROOT = Path(__file__).resolve().parents[2]
ACTOR = "actor000000000000000000000"
BODY = {
    "mattermostActorId": ACTOR,
    "patientId": "123e4567-e89b-42d3-a456-426614174000",
    "requestId": "request_123",
    "integrationId": "hrh-mattermost-01",
    "clinicalPolicyId": "clinical-read-v1",
    "policyEpoch": "mattermost-e1",
    "policyDigest": "a" * 64,
}

DEADLINE_STARTUP_SERVER = r"""
import signal,sys
from pathlib import Path
from types import SimpleNamespace
import restricted_runtime.services.production_clinical_adapter as production
marker=Path(sys.argv[1])
mode=sys.argv[2]
production.AdapterConfig.load=lambda _path: SimpleNamespace(api_key_path=Path('/unused'),expected_ingress_uid=10007,expected_clinical_timezone='America/New_York',timeout_seconds=1)
production.load_api_key=lambda *_args,**_kwargs: marker.write_text('secret',encoding='ascii')
production.HrhHttpsClient=lambda *_args,**_kwargs: marker.write_text('client',encoding='ascii')
def bind():
    marker.write_text('bind',encoding='ascii')
    raise RuntimeError('bound')
production.bind_listener=bind
if mode == 'blocked':
    signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGALRM})
    production.main()
    sys.exit(99)
try:
    production.run()
except RuntimeError:
    pass
sys.exit(0)
"""


@pytest.mark.parametrize(("mode", "expected"), [("blocked", None), ("clean", "bind")])
def test_production_adapter_deadline_preflight_handles_inherited_signal_mask_before_side_effects(tmp_path, mode, expected):
    marker = tmp_path / "startup-marker"
    result = subprocess.run(
        [sys.executable, "-c", DEADLINE_STARTUP_SERVER, str(marker), mode], cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")}, capture_output=True, text=True, timeout=5,
    )
    assert (result.returncode != 0) is (mode == "blocked")
    assert (marker.read_text(encoding="ascii") if marker.exists() else None) == expected

SERVER = r"""
import os,socket,sys
from pathlib import Path
from restricted_runtime.clinical_adapter import ClinicalAdapter,peer_uid,receive_one
class Upstream:
    def request(self,path,body):
        Path(sys.argv[3]).write_text(path,encoding='ascii')
        return {'clinicTimezone':'America/New_York','appointment':None,'responseDigest':'b'*64}
path=sys.argv[1]
listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1)
connection,_=listener.accept()
with connection:
    raw=receive_one(connection,timeout_seconds=2)
    connection.sendall(ClinicalAdapter(expected_ingress_uid=int(sys.argv[2]),expected_clinical_timezone='America/New_York',upstream=Upstream()).handle(peer_uid(connection),raw))
listener.close();os.unlink(path)
"""


def invoke(tmp_path: Path, expected_uid: int) -> tuple[bytes, Path]:
    path, marker = tmp_path / "adapter.sock", tmp_path / "upstream-called"
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    process = subprocess.Popen(
        [sys.executable, "-c", SERVER, str(path), str(expected_uid), str(marker)],
        cwd=ROOT,
        env=environment,
    )
    try:
        deadline = time.monotonic() + 5
        while not path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(2)
        client.connect(str(path))
        body = jcs_bytes(BODY)
        client.sendall(
            b"POST /v1/clinical/query HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
        )
        client.shutdown(socket.SHUT_WR)
        response = b"".join(iter(lambda: client.recv(4096), b""))
        client.close()
        assert process.wait(timeout=5) == 0
        return response, marker
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_real_uds_peer_is_accepted_and_only_query_route_is_called(tmp_path):
    response, marker = invoke(tmp_path, os.geteuid())
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert marker.read_text(encoding="ascii") == "/api/restricted-hermes/clinical/next-appointment"


def test_real_uds_wrong_peer_is_denied_before_upstream(tmp_path):
    response, marker = invoke(tmp_path, os.geteuid() + 1)
    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert not marker.exists()


ROOT_SERVER = r"""
import os,socket,sys
from pathlib import Path
from restricted_runtime.clinical_adapter import ClinicalAdapter,_bind_listener_at,peer_uid,receive_one
class Upstream:
    def request(self,path,body):
        Path(sys.argv[2]).write_text(path,encoding='ascii')
        return {'clinicTimezone':'America/New_York','appointment':None,'responseDigest':'b'*64}
listener=_bind_listener_at(sys.argv[1],socket_gid=20006)
connection,_=listener.accept()
with connection:
    raw=receive_one(connection,timeout_seconds=3)
    connection.sendall(ClinicalAdapter(expected_ingress_uid=10007,expected_clinical_timezone='America/New_York',upstream=Upstream()).handle(peer_uid(connection),raw))
listener.close();os.unlink(sys.argv[1])
"""

CLIENT = r"""
import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2);s.connect(sys.argv[1]);s.sendall(bytes.fromhex(sys.argv[2]));s.shutdown(socket.SHUT_WR)
print(b''.join(iter(lambda:s.recv(4096),b'')).hex())
"""


def _identity(uid: int, gid: int, groups: list[int]):
    def apply():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
    return apply


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="requires root to exercise numeric service principals")
def test_linux_socket_group_allows_ingress_principal_and_denies_unrelated_uid():
    directory = Path(tempfile.mkdtemp(prefix="restricted-clinical-", dir="/tmp"))
    socket_path, marker = directory / "query.sock", directory / "called"
    os.chown(directory, 10008, 20006)
    os.chmod(directory, 0o770)
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    server = subprocess.Popen(
        [sys.executable, "-c", ROOT_SERVER, str(socket_path), str(marker)],
        cwd=ROOT, env=environment, preexec_fn=_identity(10008, 20007, [20006]),
    )
    try:
        deadline = time.monotonic() + 5
        while not socket_path.exists() and server.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        request = wire_bytes = (
            b"POST /v1/clinical/query HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(jcs_bytes(BODY))).encode("ascii") + b"\r\n\r\n" + jcs_bytes(BODY)
        )
        denied = subprocess.run(
            [sys.executable, "-c", CLIENT, str(socket_path), request.hex()],
            cwd=ROOT, env=environment, preexec_fn=_identity(10009, 20009, []),
            capture_output=True, timeout=5,
        )
        assert denied.returncode != 0
        assert b"PermissionError" in denied.stderr
        allowed = subprocess.run(
            [sys.executable, "-c", CLIENT, str(socket_path), wire_bytes.hex()],
            cwd=ROOT, env=environment, preexec_fn=_identity(10007, 20005, [20006]),
            capture_output=True, text=True, timeout=5,
        )
        assert bytes.fromhex(allowed.stdout.strip()).startswith(b"HTTP/1.1 200 OK\r\n")
        assert server.wait(timeout=5) == 0
        assert marker.read_text(encoding="ascii") == "/api/restricted-hermes/clinical/next-appointment"
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)
        shutil.rmtree(directory, ignore_errors=True)
