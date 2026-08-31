"""SYNTHETIC_NON_PHI_ONLY external caller for the Compose conformance test."""
from __future__ import annotations

import json
import os
import socket
import uuid
from pathlib import Path


SOCKET = "/run/restricted-inference/conversation.sock"
STATE = Path("/var/lib/restricted-synthetic/probe-state.json")


def _request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    wire = method.encode() + b" " + path.encode() + b" HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(SOCKET)
        client.sendall(wire)
        reply = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            reply += chunk
    head, payload = reply.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(payload)


def main() -> None:
    mode = os.environ.get("SYNTHETIC_NON_PHI_ONLY_MODE", "create")
    STATE.parent.mkdir(parents=True, exist_ok=True)
    if mode in {"create", "disabled"}:
        conversation = "synthetic-non-phi-only" if mode == "create" else "synthetic-non-phi-only-disabled-control"
        status, created = _request("POST", f"/v1/restricted/conversations/{conversation}")
        assert status == 200, (status, created)
        request = {
            "schema_version": "restricted-turn.v1",
            "client_request_id": str(uuid.uuid4()),
            "conversation_epoch": created["conversation_epoch"],
            "message": "SYNTHETIC_NON_PHI_ONLY deployment probe",
        }
        if mode == "create":
            STATE.write_text(json.dumps(request, separators=(",", ":")), encoding="utf-8")
    else:
        request = json.loads(STATE.read_text(encoding="utf-8"))
    conversation = "synthetic-non-phi-only-disabled-control" if mode == "disabled" else "synthetic-non-phi-only"
    status, result = _request("POST", f"/v1/restricted/conversations/{conversation}/turns", request)
    if mode == "disabled":
        assert status == 200 and result["status"] != "COMMITTED", (status, result)
    else:
        assert status == 200, (status, result)
        assert result.get("schema_version") == "restricted-turn-result.v1", result
        assert result.get("status") == "COMMITTED", result
        assert result.get("message") == "SYNTHETIC_NON_PHI_ONLY response", result
        assert result.get("turn_id"), result
        assert result.get("conversation_epoch") == request["conversation_epoch"], result
    print(json.dumps({"mode": mode, "result": result}, separators=(",", ":")))


if __name__ == "__main__":
    main()
