"""Synthetic-only external caller used by the real Ollama Compose witness."""
from __future__ import annotations

import json
import socket
import time
import uuid


SOCKET = "/run/restricted-inference/conversation.sock"


def request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    wire = method.encode() + b" " + path.encode() + b" HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(40); client.connect(SOCKET); client.sendall(wire); reply = b""
        while True:
            part = client.recv(65536)
            if not part: break
            reply += part
    head, payload = reply.split(b"\r\n\r\n", 1)
    return int(head.split(b" ", 2)[1]), json.loads(payload)


def main() -> None:
    conversation = "synthetic-non-phi-only-ollama"
    status, created = request("POST", f"/v1/restricted/conversations/{conversation}")
    assert status == 200, (status, created)
    started = time.monotonic()
    status, result = request("POST", f"/v1/restricted/conversations/{conversation}/turns", {
        "schema_version": "restricted-turn.v1", "client_request_id": str(uuid.uuid4()),
        "conversation_epoch": created["conversation_epoch"],
        "message": "SYNTHETIC_NON_PHI_ONLY: reply with one short greeting.",
    })
    elapsed = time.monotonic() - started
    assert status == 200 and result.get("status") == "COMMITTED" and isinstance(result.get("message"), str) and result["message"], (round(elapsed, 3), status, result)
    print(json.dumps({"result": result, "model_attested": False, "deployment_conformant": False, "phi_authorized": False}, separators=(",", ":")))


if __name__ == "__main__":
    main()
