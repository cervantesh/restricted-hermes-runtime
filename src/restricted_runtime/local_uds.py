"""One-attempt closed HTTP/1.1 framing over an AF_UNIX broker socket."""
from __future__ import annotations

import socket
import stat
import time
from pathlib import Path
from typing import Any

from .contracts import ContractError, ProviderResult, jcs_bytes, load_closed_json
from .messages import validate_internal_messages
from .policy import LOCAL_POLICY_SCHEMA, PolicyBundle, SYSTEM_INSTRUCTION

_MAX_RESPONSE_BYTES = 1_048_576
_REQUEST_SCHEMA = "restricted-local-inference-request.v1"
_RESPONSE_SCHEMA = "restricted-local-inference-response.v1"


def _indeterminate(kind: str) -> ProviderResult:
    return ProviderResult("INDETERMINATE", failure_class=kind)


def _socket_path(path: str) -> str:
    candidate = Path(path)
    try:
        mode = candidate.lstat().st_mode
    except OSError as exc:
        raise ContractError("local broker socket is unavailable") from exc
    if candidate.is_symlink() or not stat.S_ISSOCK(mode):
        raise ContractError("local broker path is not a socket")
    return path


def _request(policy: PolicyBundle, messages: list[dict[str, str]]) -> bytes:
    validate_internal_messages(messages)
    return jcs_bytes({
        "schema_version": _REQUEST_SCHEMA,
        "system_instruction": SYSTEM_INSTRUCTION,
        "messages": messages,
        "generation_config": {"candidate_count": 1, "max_output_tokens": 4096},
        "declared_model_sha256": policy.values["model_sha256"],
    })


def parse_local_response(raw: bytes, declared_model_sha256: str) -> ProviderResult:
    if len(raw) > _MAX_RESPONSE_BYTES:
        return _indeterminate("RESPONSE_TOO_LARGE")
    try:
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        if not lines or lines[0] != b"HTTP/1.1 200 OK":
            if lines and lines[0].startswith(b"HTTP/1.1 "):
                return ProviderResult("FAILED", failure_class="LOCAL_HTTP_NON_200")
            raise ValueError("status")
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            key, value = line.split(b":", 1)
            key = key.lower()
            if key in headers or key not in {b"content-length", b"content-type"}:
                raise ValueError("header")
            headers[key] = value.strip()
        if set(headers) != {b"content-length", b"content-type"} or headers[b"content-type"] != b"application/json":
            raise ValueError("headers")
        length = int(headers[b"content-length"])
        if length < 0 or length != len(body):
            raise ValueError("length")
        value = load_closed_json(body)
        expected = {"schema_version", "state", "finish_reason", "text", "model_sha256", "request_id"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("schema")
        if value["schema_version"] != _RESPONSE_SCHEMA or value["state"] != "SUCCEEDED" or value["finish_reason"] != "STOP":
            raise ValueError("terminal")
        if not isinstance(value["text"], str) or not value["text"] or not isinstance(value["request_id"], str) or not value["request_id"]:
            raise ValueError("values")
        if not isinstance(value["model_sha256"], str) or len(value["model_sha256"]) != 64 or any(char not in "0123456789abcdef" for char in value["model_sha256"]):
            raise ValueError("model digest")
        if value["model_sha256"] != declared_model_sha256:
            return _indeterminate("MODEL_DIGEST_MISMATCH")
        return ProviderResult("SUCCEEDED", text=value["text"], provider_request_id=value["request_id"], broker_declared_model_sha256=value["model_sha256"])
    except Exception:
        return _indeterminate("MALFORMED_RESPONSE")


class LocalUdsClient:
    """The sole local provider dispatch path; it never constructs an INET socket."""
    def __init__(self, policy: PolicyBundle, *, timeout_seconds: float = 40.0):
        policy.validate()
        if policy.values["schema_version"] != LOCAL_POLICY_SCHEMA:
            raise ContractError("local client requires the local policy schema")
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0 or timeout_seconds > 40:
            raise ContractError("local provider deadline is invalid")
        self.policy, self.timeout_seconds = policy, float(timeout_seconds)
        _socket_path(str(policy.values["socket_path"]))

    def generate_content(self, messages: list[dict[str, str]]) -> ProviderResult:
        payload = _request(self.policy, messages)
        path = _socket_path(str(self.policy.values["socket_path"]))
        started = time.monotonic()
        def phase_timeout() -> float:
            remaining = self.timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise socket.timeout()
            return min(5.0, remaining)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(phase_timeout())
                client.connect(path)
                wire = b"POST /v1/restricted/generate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + payload
                client.settimeout(phase_timeout())
                client.sendall(wire)
                chunks: list[bytes] = []
                total = 0
                while True:
                    client.settimeout(phase_timeout())
                    chunk = client.recv(min(65536, _MAX_RESPONSE_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk); total += len(chunk)
                    if total > _MAX_RESPONSE_BYTES:
                        return _indeterminate("RESPONSE_TOO_LARGE")
        except socket.timeout:
            if time.monotonic() - started >= self.timeout_seconds:
                return _indeterminate("TOTAL_DEADLINE")
            return _indeterminate("TRANSPORT_AFTER_DISPATCH")
        except OSError:
            return _indeterminate("TRANSPORT_AFTER_DISPATCH")
        return parse_local_response(b"".join(chunks), str(self.policy.values["model_sha256"]))
