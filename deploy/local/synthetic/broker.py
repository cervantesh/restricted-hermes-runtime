"""SYNTHETIC_NON_PHI_ONLY deterministic AF_UNIX broker for conformance tests."""
from __future__ import annotations

import hashlib
import json
import os
import socket
from pathlib import Path


SOCKET = Path("/run/restricted-inference/broker.sock")
COUNT = Path("/var/lib/restricted-synthetic/broker-count")
MODEL_DIGEST = hashlib.sha256(b"SYNTHETIC_NON_PHI_ONLY_BROKER").hexdigest()


def _response() -> bytes:
    body = json.dumps({
        "schema_version": "restricted-local-inference-response.v1",
        "state": "SUCCEEDED",
        "finish_reason": "STOP",
        "text": "SYNTHETIC_NON_PHI_ONLY response",
        "model_sha256": MODEL_DIGEST,
        "request_id": "synthetic-non-phi-only-request-1",
    }, separators=(",", ":")).encode()
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def main() -> None:
    if SOCKET.exists() or SOCKET.is_symlink():
        metadata = SOCKET.lstat()
        if not SOCKET.is_socket() or metadata.st_uid != os.geteuid():
            raise RuntimeError("synthetic broker refuses unsafe stale path")
        SOCKET.unlink()
    COUNT.parent.mkdir(parents=True, exist_ok=True)
    if not COUNT.exists():
        COUNT.write_text("0", encoding="ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET))
        os.chmod(SOCKET, 0o660)
        server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                raw = b""
                while b"\r\n\r\n" not in raw:
                    part = connection.recv(65536)
                    if not part:
                        break
                    raw += part
                # Readiness and ACL probes intentionally open and close the UDS
                # without issuing inference. They must not count or kill the broker.
                if not raw:
                    continue
                head, _, body = raw.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                while len(body) < length:
                    body += connection.recv(length - len(body))
                value = json.loads(body)
                if value.get("declared_model_sha256") != MODEL_DIGEST:
                    raise RuntimeError("synthetic model digest mismatch")
                count = int(COUNT.read_text(encoding="ascii")) + 1
                COUNT.write_text(str(count), encoding="ascii")
                connection.sendall(_response())


if __name__ == "__main__":
    main()
