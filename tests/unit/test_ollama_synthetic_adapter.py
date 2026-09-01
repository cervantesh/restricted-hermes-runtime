"""Closed-contract tests for the optional synthetic Ollama adapter."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ollama_adapter", ROOT / "deploy" / "local" / "ollama" / "adapter.py")
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(adapter)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "models"; manifest = store / "manifests/registry.ollama.ai/library/qwen2.5/7b"; blobs = store / "blobs"
    config, main = b"config", b"main"
    descriptors = [
        {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:" + _digest(config), "size": len(config)},
        {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:" + _digest(main), "size": len(main)},
    ]
    for raw in (config, main):
        target = blobs / ("sha256-" + _digest(raw)); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
    raw_manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": descriptors[0], "layers": descriptors[1:]}, separators=(",", ":")).encode()
    manifest.parent.mkdir(parents=True, exist_ok=True); manifest.write_bytes(raw_manifest)
    monkeypatch.setattr(adapter, "STORE", store)
    monkeypatch.setattr(adapter, "MANIFEST_SHA256", _digest(raw_manifest))
    monkeypatch.setattr(adapter, "MAIN_BLOB_SHA256", _digest(main))
    return manifest


def test_bundle_verifier_accepts_exact_regular_manifest_and_blobs(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    assert adapter.verify_bundle() == adapter.MANIFEST_SHA256


def test_post_ready_guard_accepts_retained_exact_namespace_and_rejects_drift(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    baseline = adapter.capture_baseline()
    try:
        adapter.guard(baseline)
        extra = tmp_path / "models" / "unexpected"; extra.write_bytes(b"x")
        with pytest.raises(adapter.GuardDrift):
            adapter.guard(baseline)
    finally:
        baseline.close()


def test_post_ready_guard_rejects_replaced_referenced_blob(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    baseline = adapter.capture_baseline()
    try:
        target = next((tmp_path / "models" / "blobs").glob("sha256-*"))
        os.utime(target, None)
        with pytest.raises(adapter.GuardDrift):
            adapter.guard(baseline)
    finally:
        baseline.close()


@pytest.mark.parametrize("mutation", ["manifest", "blob", "size", "main"])
def test_bundle_verifier_rejects_identity_mutations(tmp_path, monkeypatch, mutation):
    manifest = _bundle(tmp_path, monkeypatch)
    if mutation == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif mutation == "blob":
        next((tmp_path / "models/blobs").glob("sha256-*")).write_bytes(b"changed")
    elif mutation == "size":
        value = json.loads(manifest.read_text()); value["layers"][0]["size"] += 1; manifest.write_text(json.dumps(value))
        monkeypatch.setattr(adapter, "MANIFEST_SHA256", _digest(manifest.read_bytes()))
    else:
        monkeypatch.setattr(adapter, "MAIN_BLOB_SHA256", "0" * 64)
    with pytest.raises(adapter.ClosedError):
        adapter.verify_bundle()


def test_bundle_verifier_rejects_symlinked_manifest(tmp_path, monkeypatch):
    manifest = _bundle(tmp_path, monkeypatch)
    replacement = manifest.with_name("replacement")
    replacement.write_bytes(manifest.read_bytes())
    manifest.unlink()
    try:
        manifest.symlink_to(replacement)
    except OSError as exc:
        pytest.skip(f"symlink creation is not available on this host: {exc}")
    with pytest.raises(adapter.ClosedError):
        adapter.verify_bundle()


def test_bundle_verifier_rejects_manifest_target_traversal(tmp_path, monkeypatch):
    _bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter, "MANIFEST_RELATIVE", Path("../outside"))
    with pytest.raises(adapter.ClosedError):
        adapter.verify_bundle()


def test_closed_translation_rejects_tools_images_thinking_and_wrong_model():
    request = {"schema_version": "restricted-local-inference-request.v1", "system_instruction": "system", "messages": [{"role": "user", "text": "hello"}, {"role": "model", "text": "hi"}], "generation_config": {"candidate_count": 1, "max_output_tokens": 4096}, "declared_model_sha256": adapter.MANIFEST_SHA256}
    assert adapter._closed_request(request) == {"model": "qwen2.5:7b", "messages": [{"role": "system", "content": "system"}, {"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}], "stream": False, "options": {"num_predict": 4096}}
    for key, value in (("tools", []), ("images", []), ("thinking", True), ("declared_model_sha256", "0" * 64)):
        mutated = {**request, key: value}
        with pytest.raises(adapter.ClosedError):
            adapter._closed_request(mutated)


def test_closed_response_rejects_missing_done_wrong_model_and_partial_message():
    valid = {"model": "qwen2.5:7b", "created_at": "2026-01-01T00:00:00Z", "message": {"role": "assistant", "content": "ok"}, "done": True, "done_reason": "stop", "total_duration": 1, "load_duration": 0, "prompt_eval_count": 1, "prompt_eval_duration": 1, "eval_count": 1, "eval_duration": 1}
    assert adapter._validated_response(valid) == ("ok", "2026-01-01T00:00:00Z")
    for mutation in ({"done": False}, {"model": "other"}, {"message": {"role": "assistant"}}):
        with pytest.raises(adapter.ClosedError):
            adapter._validated_response({**valid, **mutation})


class _Response:
    def __init__(self, status: int, raw: bytes):
        self.status = status
        self._raw = raw

    def read(self, _limit: int) -> bytes:
        return self._raw


class _Socket:
    def __init__(self):
        self.timeouts: list[float] = []

    def settimeout(self, _timeout: float) -> None:
        self.timeouts.append(_timeout)


class _Connection:
    def __init__(self, response: _Response):
        self.response = response
        self.sock = _Socket()

    def request(self, *_args, **_kwargs) -> None:
        return None

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        return None


@pytest.mark.parametrize("case", ["non_success", "oversize"])
def test_ollama_fail_closed_for_non_success_or_oversize_payload(monkeypatch, case):
    status = 503 if case == "non_success" else 200
    raw = b"{}" if case == "non_success" else b"x" * (adapter.MAX_HTTP + 1)
    monkeypatch.setattr(adapter.http.client, "HTTPConnection", lambda *_args, **_kwargs: _Connection(_Response(status, raw)))
    with pytest.raises(adapter.ClosedError):
        adapter._ollama("/api/tags")


def test_ollama_fail_closed_for_malformed_partial_payload_with_one_attempt(monkeypatch):
    attempts = []

    def factory(*_args, **_kwargs):
        attempts.append(1)
        return _Connection(_Response(200, b'{"models":'))

    monkeypatch.setattr(adapter.http.client, "HTTPConnection", factory)
    with pytest.raises(adapter.ClosedError):
        adapter._ollama("/api/tags")
    assert attempts == [1]


def test_ollama_fail_closed_when_connection_dies(monkeypatch):
    class DeadConnection(_Connection):
        def request(self, *_args, **_kwargs) -> None:
            raise OSError("connection reset")

    monkeypatch.setattr(adapter.http.client, "HTTPConnection", lambda *_args, **_kwargs: DeadConnection(_Response(200, b"{}")))
    with pytest.raises(adapter.ClosedError):
        adapter._ollama("/api/tags")


def test_serving_keeps_connect_one_second_and_never_uses_startup_budget(monkeypatch):
    connection = _Connection(_Response(200, b'{"models":[]}'))
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        return connection

    monkeypatch.setattr(adapter.http.client, "HTTPConnection", factory)
    assert adapter._ollama("/api/tags") == {"models": []}
    assert calls == [(('127.0.0.1', 11434), {"timeout": 1})]
    assert connection.sock.timeouts and max(connection.sock.timeouts) <= adapter.OLLAMA_DEADLINE
    assert adapter.STARTUP_DEADLINE not in connection.sock.timeouts


def test_prebind_warmup_can_use_remaining_absolute_startup_budget(monkeypatch):
    connection = _Connection(_Response(200, b'{"models":[]}'))
    ticks = iter((0.0, 0.0, 36.0, 36.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(adapter.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)
    assert adapter._ollama("/api/tags", deadline=179.0) == {"models": []}
    assert connection.sock.timeouts == [179.0, 143.0]


def test_serving_over_35_seconds_fails_closed(monkeypatch):
    connection = _Connection(_Response(200, b'{"models":[]}'))
    ticks = iter((0.0, 0.0, 36.0))
    monkeypatch.setattr(adapter.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(adapter.http.client, "HTTPConnection", lambda *_args, **_kwargs: connection)
    with pytest.raises(adapter.ClosedError):
        adapter._ollama("/api/tags")
    assert connection.sock.timeouts == [adapter.OLLAMA_DEADLINE]


@pytest.mark.parametrize("expired_phase", ["verify_1", "warmup", "verify_2"])
def test_startup_phase_timeout_never_calls_bind(monkeypatch, expired_phase):
    now = [0.0]
    verify_calls = [0]
    bound = []
    monkeypatch.setattr(adapter.time, "monotonic", lambda: now[0])

    def verify(*, deadline):
        verify_calls[0] += 1
        if expired_phase == f"verify_{verify_calls[0]}":
            now[0] = adapter.STARTUP_DEADLINE + 1

    def warm(*, deadline):
        if expired_phase == "warmup":
            now[0] = adapter.STARTUP_DEADLINE + 1

    monkeypatch.setattr(adapter, "verify_bundle", verify)
    monkeypatch.setattr(adapter, "_warm", warm)
    monkeypatch.setattr(adapter, "_bind", lambda **_kwargs: bound.append(True))
    with pytest.raises(adapter.ClosedError):
        adapter._startup()
    assert bound == []


def test_startup_keeps_socket_absent_while_warmup_is_pending(monkeypatch, tmp_path):
    bound = []
    monkeypatch.setattr(adapter, "SOCKET", tmp_path / "broker.sock")
    monkeypatch.setattr(adapter, "verify_bundle", lambda **_kwargs: adapter.MANIFEST_SHA256)

    def warm(**_kwargs):
        assert not adapter.SOCKET.exists()

    monkeypatch.setattr(adapter, "_warm", warm)
    baseline = type("Baseline", (), {"close": lambda self: None})()
    monkeypatch.setattr(adapter, "capture_baseline", lambda: baseline)
    monkeypatch.setattr(adapter, "_bind", lambda **_kwargs: bound.append(True) or "server")
    assert adapter._startup() == ("server", baseline)
    assert bound == [True]


def test_expired_prebind_request_has_no_retry_and_never_binds(monkeypatch):
    attempts = []
    bound = []
    monkeypatch.setattr(adapter.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(adapter, "verify_bundle", lambda **_kwargs: adapter.MANIFEST_SHA256)

    def expired(path, payload=None, *, deadline=None):
        attempts.append((path, payload, deadline))
        raise adapter.ClosedError("Ollama request exceeded deadline")

    monkeypatch.setattr(adapter, "_ollama", expired)
    monkeypatch.setattr(adapter, "_bind", lambda **_kwargs: bound.append(True))
    with pytest.raises(adapter.ClosedError):
        adapter._startup()
    assert attempts == [("/api/tags", None, adapter.STARTUP_DEADLINE)]
    assert bound == []


@pytest.mark.parametrize("durations,allowed", [((50, 50, 50), True), ((60, 60, 61), False)])
def test_startup_uses_one_absolute_budget_across_all_phases(monkeypatch, durations, allowed):
    now = [0.0]
    verify_calls = [0]
    bound = []
    monkeypatch.setattr(adapter.time, "monotonic", lambda: now[0])

    def verify(**_kwargs):
        now[0] += durations[0 if verify_calls[0] == 0 else 2]
        verify_calls[0] += 1

    def warm(**_kwargs):
        now[0] += durations[1]

    monkeypatch.setattr(adapter, "verify_bundle", verify)
    monkeypatch.setattr(adapter, "_warm", warm)
    baseline = type("Baseline", (), {"close": lambda self: None})()
    monkeypatch.setattr(adapter, "capture_baseline", lambda: baseline)
    monkeypatch.setattr(adapter, "_bind", lambda **_kwargs: bound.append(True) or "server")
    if allowed:
        assert adapter._startup() == ("server", baseline)
        assert bound == [True]
    else:
        with pytest.raises(adapter.ClosedError):
            adapter._startup()
        assert bound == []


def test_warmup_is_one_synthetic_chat_attempt(monkeypatch):
    calls = []
    valid = {"model": "qwen2.5:7b", "created_at": "2026-01-01T00:00:00Z", "message": {"role": "assistant", "content": "ready"}, "done": True, "done_reason": "stop", "total_duration": 1, "load_duration": 0, "prompt_eval_count": 1, "prompt_eval_duration": 1, "eval_count": 1, "eval_duration": 1}

    def ollama(path, payload=None, *, deadline=None):
        calls.append((path, payload, deadline))
        return {"models": []} if path == "/api/tags" else valid

    monkeypatch.setattr(adapter, "_ollama", ollama)
    adapter._warm(deadline=123.0)
    chats = [call for call in calls if call[0] == "/api/chat"]
    assert len(chats) == 1
    assert all(call[2] == 123.0 for call in calls)
    assert chats[0][1]["messages"] == [{"role": "system", "content": "SYNTHETIC_NON_PHI_ONLY"}, {"role": "user", "content": "SYNTHETIC_NON_PHI_ONLY: reply with ready."}]


def test_departed_readiness_peer_cannot_kill_broker_response_path():
    class DepartedPeer:
        def sendall(self, _payload):
            raise BrokenPipeError("peer closed")

    adapter._reply(DepartedPeer(), 400, {"error": "restricted request rejected"})


def test_request_reader_rejects_half_closed_body_and_uses_one_deadline(monkeypatch):
    class HalfClosed:
        def __init__(self): self.calls = 0; self.timeouts = []
        def settimeout(self, value): self.timeouts.append(value)
        def recv(self, _limit):
            self.calls += 1
            return b"POST /v1/restricted/generate HTTP/1.0\r\nContent-Length: 2\r\n\r\n" if self.calls == 1 else b""
    peer = HalfClosed()
    with pytest.raises(adapter.ClosedError, match="truncated"):
        adapter._read_request(peer)
    assert peer.timeouts and max(peer.timeouts) <= 5


def test_guard_oserror_is_fatal_drift(monkeypatch):
    baseline = type("Baseline", (), {"files": {}, "directories": {}})()
    monkeypatch.setattr(adapter, "_namespace", lambda: (_ for _ in ()).throw(OSError("race")))
    with pytest.raises(adapter.GuardDrift): adapter.guard(baseline)
