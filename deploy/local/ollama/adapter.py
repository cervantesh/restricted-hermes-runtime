"""Synthetic-only, one-attempt Ollama to restricted-local-UDS adapter.

This file deliberately has no dependency on the product composition roots. It
is an optional local deployment edge and refuses every input outside its closed
contract.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import stat
import time
import uuid
from pathlib import Path
from typing import Any


MAX_HTTP = 1_048_576
OLLAMA_DEADLINE = 35.0
STARTUP_DEADLINE = 180.0
MODEL_TAG = "qwen2.5:7b"
MANIFEST_SHA256 = "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
MAIN_BLOB_SHA256 = "2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730"
SOCKET = Path("/run/restricted-inference/broker.sock")
STORE = Path("/models")
MANIFEST_RELATIVE = Path("manifests/registry.ollama.ai/library/qwen2.5/7b")


class ClosedError(ValueError):
    pass


class GuardDrift(ClosedError):
    pass


class Baseline:
    def __init__(self, files: dict[str, tuple[int, tuple[int, ...]]], directories: dict[str, tuple[int, ...]]):
        self.files, self.directories = files, directories

    def close(self) -> None:
        for descriptor in self.files.values():
            os.close(descriptor[0])


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ClosedError("duplicate JSON key")
        value[key] = item
    return value


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ClosedError) as exc:
        raise ClosedError("invalid JSON") from exc


def _remaining(deadline: float | None, phase: str) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ClosedError(f"{phase} exceeded deadline")
    return remaining


def _read_regular(path: Path, *, maximum: int | None = None, deadline: float | None = None) -> tuple[bytes, str, tuple[int, int, int, int]]:
    """Read one non-symlink regular file while proving its identity stayed fixed."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ClosedError("bundle path is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != identity:
            raise ClosedError("bundle file changed during open")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            chunks: list[bytes] = []
            while True:
                _remaining(deadline, "bundle metadata read")
                chunk = source.read(65_536)
                if not chunk:
                    break
                chunks.append(chunk)
                if maximum is not None and sum(map(len, chunks)) > maximum:
                    raise ClosedError("bundle metadata exceeds limit")
            raw = b"".join(chunks)
        if maximum is not None and len(raw) > maximum:
            raise ClosedError("bundle metadata exceeds limit")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
        raise ClosedError("bundle file changed during read")
    return raw, hashlib.sha256(raw).hexdigest(), identity


def _sha256_regular(path: Path, *, deadline: float | None = None) -> tuple[str, int, tuple[int, int, int, int]]:
    """Stream-hash a regular nofollow file and recheck its identity."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ClosedError("bundle path is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != identity:
            raise ClosedError("bundle file changed during open")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            hasher = hashlib.sha256()
            while chunk := source.read(1_048_576):
                _remaining(deadline, "bundle blob hash")
                hasher.update(chunk)
            digest = hasher.hexdigest()
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
        raise ClosedError("bundle file changed during read")
    return digest, identity[2], identity


def _under_store(relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ClosedError("bundle path traversal")
    root = STORE.resolve(strict=True)
    target = root / relative
    try:
        target.parent.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError) as exc:
        raise ClosedError("bundle path escapes model store") from exc
    return target


def _descriptor(value: Any) -> tuple[str, int]:
    if not isinstance(value, dict) or set(value) != {"mediaType", "digest", "size"}:
        raise ClosedError("descriptor shape rejected")
    digest, size = value["digest"], value["size"]
    if not isinstance(value["mediaType"], str) or not isinstance(digest, str) or not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ClosedError("descriptor value rejected")
    if not digest.startswith("sha256:") or len(digest) != 71 or any(ch not in "0123456789abcdef" for ch in digest[7:]):
        raise ClosedError("descriptor digest rejected")
    return digest[7:], size


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _allowlist() -> set[str]:
    raw, digest, _ = _read_regular(_under_store(MANIFEST_RELATIVE), maximum=MAX_HTTP)
    if digest != MANIFEST_SHA256:
        raise GuardDrift("manifest guard mismatch")
    value = _json(raw)
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "mediaType", "config", "layers"}:
        raise GuardDrift("manifest guard shape")
    return {str(MANIFEST_RELATIVE), *(str(Path("blobs") / f"sha256-{digest}") for digest, _ in [_descriptor(item) for item in [value["config"], *value["layers"]]])}


def _namespace() -> tuple[dict[str, os.stat_result], dict[str, os.stat_result]]:
    root = STORE.resolve(strict=True); directories: dict[str, os.stat_result] = {".": root.lstat()}; files: dict[str, os.stat_result] = {}
    for current, names, entries in os.walk(root, followlinks=False):
        base = Path(current)
        for name in names:
            path = base / name; metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode): raise GuardDrift("namespace directory rejected")
            directories[str(path.relative_to(root))] = metadata
        for name in entries:
            path = base / name; metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode): raise GuardDrift("namespace file rejected")
            files[str(path.relative_to(root))] = metadata
    return files, directories


def capture_baseline() -> Baseline:
    allow = _allowlist(); files, directories = _namespace()
    if set(files) != allow: raise GuardDrift("namespace allowlist mismatch")
    retained: dict[str, tuple[int, tuple[int, int, int, int, int, int, int, int]]] = {}
    try:
        for relative, before in files.items():
            descriptor = os.open(_under_store(Path(relative)), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)); opened = os.fstat(descriptor)
            if _identity(before) != _identity(opened): os.close(descriptor); raise GuardDrift("file changed during baseline")
            retained[relative] = (descriptor, _identity(opened))
        return Baseline(retained, {relative: _identity(value) for relative, value in directories.items()})
    except Exception:
        for descriptor, _ in retained.values(): os.close(descriptor)
        raise


def guard(baseline: Baseline) -> None:
    try: files, directories = _namespace()
    except OSError as exc: raise GuardDrift("namespace unavailable") from exc
    if set(files) != set(baseline.files) or set(directories) != set(baseline.directories): raise GuardDrift("namespace changed")
    if any(_identity(value) != baseline.directories[key] for key, value in directories.items()): raise GuardDrift("directory identity changed")
    for relative, metadata in files.items():
        descriptor, expected = baseline.files[relative]
        if _identity(metadata) != expected or _identity(os.fstat(descriptor)) != expected: raise GuardDrift("file identity changed")


def verify_bundle(*, deadline: float | None = None) -> str:
    """Verify the exact raw manifest and each referenced immutable blob."""
    manifest = _under_store(MANIFEST_RELATIVE)
    raw_manifest, manifest_digest, manifest_identity = _read_regular(manifest, maximum=MAX_HTTP, deadline=deadline)
    if manifest_digest != MANIFEST_SHA256:
        raise ClosedError("manifest digest mismatch")
    value = _json(raw_manifest)
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "mediaType", "config", "layers"}:
        raise ClosedError("manifest shape rejected")
    if value["schemaVersion"] != 2 or value["mediaType"] != "application/vnd.docker.distribution.manifest.v2+json" or not isinstance(value["layers"], list):
        raise ClosedError("manifest value rejected")
    descriptors = [value["config"], *value["layers"]]
    declared = [_descriptor(item) for item in descriptors]
    if MAIN_BLOB_SHA256 not in {digest for digest, _ in declared}:
        raise ClosedError("required model blob is absent")
    for digest, expected_size in declared:
        actual_digest, actual_size, _ = _sha256_regular(_under_store(Path("blobs") / f"sha256-{digest}"), deadline=deadline)
        if actual_digest != digest or actual_size != expected_size:
            raise ClosedError("bundle blob verification failed")
    _, final_digest, final_identity = _read_regular(manifest, maximum=MAX_HTTP, deadline=deadline)
    if final_digest != MANIFEST_SHA256 or final_identity != manifest_identity:
        raise ClosedError("manifest changed during bundle verification")
    return final_digest


def _closed_request(value: Any) -> dict[str, Any]:
    expected = {"schema_version", "system_instruction", "messages", "generation_config", "declared_model_sha256"}
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != "restricted-local-inference-request.v1":
        raise ClosedError("restricted request rejected")
    if value["declared_model_sha256"] != MANIFEST_SHA256 or not isinstance(value["system_instruction"], str) or not value["system_instruction"]:
        raise ClosedError("restricted request model or system rejected")
    if value["generation_config"] != {"candidate_count": 1, "max_output_tokens": 4096} or not isinstance(value["messages"], list) or not value["messages"]:
        raise ClosedError("restricted request generation rejected")
    messages = [{"role": "system", "content": value["system_instruction"]}]
    for item in value["messages"]:
        if not isinstance(item, dict) or set(item) != {"role", "text"} or item["role"] not in {"user", "model"} or not isinstance(item["text"], str) or not item["text"]:
            raise ClosedError("restricted message rejected")
        messages.append({"role": "assistant" if item["role"] == "model" else "user", "content": item["text"]})
    return {"model": MODEL_TAG, "messages": messages, "stream": False, "options": {"num_predict": 4096}}


def _ollama(path: str, payload: dict[str, Any] | None = None, *, deadline: float | None = None) -> dict[str, Any]:
    """Make one request; a pre-bind caller supplies its absolute startup deadline."""
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", 11434, timeout=1)
    started = time.monotonic()
    request_deadline = deadline if deadline is not None else started + OLLAMA_DEADLINE
    try:
        connection.request("GET" if payload is None else "POST", path, body=body if payload is not None else None, headers={"Content-Type": "application/json"} if payload is not None else {})
        remaining = _remaining(request_deadline, "Ollama request")
        if remaining <= 0 or connection.sock is None:
            raise ClosedError("Ollama deadline exceeded")
        # The constructor's one-second timeout applies only while connecting;
        # once connected, the single request receives the closed total budget.
        connection.sock.settimeout(remaining)
        response = connection.getresponse()
        remaining = _remaining(request_deadline, "Ollama request")
        if remaining <= 0 or connection.sock is None:
            raise ClosedError("Ollama deadline exceeded")
        connection.sock.settimeout(remaining)
        raw = response.read(MAX_HTTP + 1)
        if response.status < 200 or response.status >= 300 or len(raw) > MAX_HTTP or time.monotonic() > request_deadline:
            raise ClosedError("Ollama response rejected")
        return _json(raw)
    except (OSError, http.client.HTTPException) as exc:
        raise ClosedError("Ollama unavailable") from exc
    finally:
        connection.close()


def _validated_response(value: Any) -> tuple[str, str]:
    expected = {"model", "created_at", "message", "done", "done_reason", "total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration"}
    if not isinstance(value, dict) or set(value) != expected or value["model"] != MODEL_TAG or not isinstance(value["created_at"], str) or not value["created_at"] or value["done"] is not True or value["done_reason"] != "stop":
        raise ClosedError("Ollama response contract rejected")
    message = value["message"]
    if not isinstance(message, dict) or set(message) != {"role", "content"} or message["role"] != "assistant" or not isinstance(message["content"], str) or not message["content"]:
        raise ClosedError("Ollama message contract rejected")
    if any(not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0 for key in ("total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration")):
        raise ClosedError("Ollama metrics rejected")
    return message["content"], value["created_at"]


def _warm(*, deadline: float | None = None) -> None:
    tags = _ollama("/api/tags", deadline=deadline)
    if not isinstance(tags, dict) or set(tags) != {"models"} or not isinstance(tags["models"], list):
        raise ClosedError("Ollama readiness rejected")
    warm = _ollama("/api/chat", {"model": MODEL_TAG, "messages": [{"role": "system", "content": "SYNTHETIC_NON_PHI_ONLY"}, {"role": "user", "content": "SYNTHETIC_NON_PHI_ONLY: reply with ready."}], "stream": False, "options": {"num_predict": 4096}}, deadline=deadline)
    _validated_response(warm)


def _reply(connection: socket.socket, status: int, value: dict[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    reason = b"OK" if status == 200 else b"Bad Request"
    try:
        connection.sendall(b"HTTP/1.1 " + str(status).encode() + b" " + reason + b"\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    except OSError:
        # Readiness probes may deliberately connect and close without a request.
        # Their departed peer must not terminate the long-lived broker listener.
        return


def _read_request(connection: socket.socket) -> dict[str, Any]:
    deadline = time.monotonic() + 5
    def receive(limit: int) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise ClosedError("request read exceeded deadline")
        connection.settimeout(remaining)
        part = connection.recv(limit)
        if not part: raise ClosedError("truncated request")
        return part
    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) <= MAX_HTTP:
        raw += receive(65536)
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if not lines or lines[0] != b"POST /v1/restricted/generate HTTP/1.0":
        raise ClosedError("HTTP request rejected")
    lengths = [line.split(b":", 1)[1].strip() for line in lines[1:] if line.lower().startswith(b"content-length:")]
    if len(lengths) != 1:
        raise ClosedError("content length rejected")
    length = int(lengths[0])
    while len(body) < length and len(body) <= MAX_HTTP:
        body += receive(min(65536, length - len(body)))
    if len(body) != length or length > MAX_HTTP:
        raise ClosedError("request body rejected")
    return _json(body)


def _bind(*, deadline: float | None = None) -> socket.socket:
    _remaining(deadline, "broker bind")
    if SOCKET.exists() or SOCKET.is_symlink():
        metadata = SOCKET.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ClosedError("unsafe broker socket path")
        SOCKET.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET))
    os.chmod(SOCKET, 0o660)
    metadata = SOCKET.stat()
    if metadata.st_uid != 10003 or metadata.st_gid != 20003 or stat.S_IMODE(metadata.st_mode) != 0o660:
        raise ClosedError("broker socket identity rejected")
    server.listen(4)
    return server


def _startup() -> tuple[socket.socket, Baseline]:
    deadline = time.monotonic() + STARTUP_DEADLINE
    verify_bundle(deadline=deadline)
    _remaining(deadline, "VERIFY_1")
    _warm(deadline=deadline)
    _remaining(deadline, "WARMUP_ONCE")
    verify_bundle(deadline=deadline)
    _remaining(deadline, "VERIFY_2")
    baseline = capture_baseline()
    try:
        return _bind(deadline=deadline), baseline
    except Exception:
        baseline.close()
        raise


def main() -> None:
    server, baseline = _startup()
    try:
        with server:
            while True:
                connection, _ = server.accept()
                with connection:
                    try:
                        guard(baseline)  # also covers empty readiness connections.
                        payload = _closed_request(_read_request(connection))
                        response = _ollama("/api/chat", payload)
                        guard(baseline)
                        text, created_at = _validated_response(response)
                        _reply(connection, 200, {"schema_version": "restricted-local-inference-response.v1", "state": "SUCCEEDED", "finish_reason": "STOP", "text": text, "model_sha256": MANIFEST_SHA256, "request_id": created_at + ":" + str(uuid.uuid4())})
                    except GuardDrift:
                        # A changed staged namespace is fatal: withhold text, remove
                        # the endpoint, and never continue serving a new identity.
                        if SOCKET.exists() and not SOCKET.is_symlink(): SOCKET.unlink()
                        return
                    except Exception:
                        _reply(connection, 400, {"error": "restricted request rejected", "request_id": str(uuid.uuid4())})
    finally:
        baseline.close()


if __name__ == "__main__":
    main()
