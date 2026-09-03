"""Synthetic non-PHI conversation.sock witness for Mattermost ESR staging."""
from __future__ import annotations

import json
import os
import socketserver
import threading
from pathlib import Path


SOCKET = Path("/run/restricted-inference/conversation.sock")
COUNTERS = Path("/state/counters.json")
LOCK = threading.Lock()
STATE = {"turns": 0, "conversation_ids": [], "client_request_ids": [], "turn_shapes": []}


def write_state() -> None:
    temporary = COUNTERS.with_suffix(".tmp")
    temporary.write_text(json.dumps(STATE, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, COUNTERS)


def response(handler: socketserver.StreamRequestHandler, value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":")).encode()
    handler.wfile.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(raw)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + raw
    )


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline(4096).decode("ascii").strip().split(" ")
        if len(request_line) != 3:
            return
        headers: dict[str, str] = {}
        while True:
            line = self.rfile.readline(4096)
            if line == b"\r\n":
                break
            key, value = line.decode("ascii").split(":", 1)
            headers[key.lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        method, path = request_line[:2]
        if method == "GET" and path == "/readyz":
            value = {
                "schema_version": "restricted-conversation-readiness.v1",
                "status": "ready",
                "policy_epoch": "esr-e1",
                "policy_digest": "a" * 64,
                "classification": "PHI",
                "system_instruction_version": "restricted-phi-system.v1",
                "allowed_modalities": ["text"],
                "tools_allowed": False,
                "fallbacks": [],
                "max_provider_attempts": 1,
                "streaming": False,
                "max_output_tokens": 4096,
                "max_canonical_input_utf8_bytes": 131072,
                "response_profile": "restricted-local-text-response.v1",
            }
        elif method == "POST" and path.endswith("/turns"):
            incoming = json.loads(body)
            conversation_id = path.split("/")[-2]
            with LOCK:
                STATE["turns"] += 1
                STATE["conversation_ids"].append(conversation_id)
                STATE["client_request_ids"].append(incoming["client_request_id"])
                STATE["turn_shapes"].append({key: type(item).__name__ for key, item in sorted(incoming.items())})
                write_state()
            value = {
                "schema_version": "restricted-turn-result.v1",
                "turn_id": "synthetic",
                "conversation_epoch": incoming["conversation_epoch"],
                "status": "COMMITTED",
                "message": "synthetic response",
            }
        elif method == "POST" and path.startswith("/v1/restricted/conversations/"):
            value = {
                "schema_version": "restricted-conversation.v1",
                "conversation_id": path.rsplit("/", 1)[-1],
                "conversation_epoch": "esr",
            }
        else:
            return
        response(self, value)


SOCKET.parent.mkdir(parents=True, exist_ok=True)
SOCKET.unlink(missing_ok=True)
COUNTERS.parent.mkdir(parents=True, exist_ok=True)
write_state()
with socketserver.ThreadingUnixStreamServer(str(SOCKET), Handler) as server:
    os.chown(SOCKET, 0, 20001)
    os.chmod(SOCKET, 0o660)
    server.serve_forever()
