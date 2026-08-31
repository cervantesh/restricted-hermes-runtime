"""Closed self-hosted profile guards; no broker or model is started here."""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.contracts import ContractError, jcs_bytes
from restricted_runtime.policy import LOCAL_POLICY_SCHEMA, PolicyBundle


def local_values() -> dict[str, object]:
    return {
        "schema_version": LOCAL_POLICY_SCHEMA,
        "policy_epoch": "local-e1",
        "system_instruction_version": "restricted-phi-system.v1",
        "system_instruction_sha256": "afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b",
        "authorization_status": "operator-authorization-required",
        "external_runner_principal": "runner",
        "gateway_invoker_principal": "conversation",
        "tenant_id": "tenant",
        "classification": "PHI",
        "provider": "local-uds",
        "socket_path": "/run/restricted-inference/broker.sock",
        "method": "restrictedGenerate",
        "model": "operator-display-name",
        "model_sha256": "a" * 64,
        "response_profile": "restricted-local-text-response.v1",
        "streaming": False,
        "fallbacks": [],
        "max_provider_attempts": 1,
        "allowed_modalities": ["text"],
        "tools_allowed": False,
        "candidate_count": 1,
        "max_output_tokens": 4096,
        "max_canonical_input_utf8_bytes": 131072,
    }


def test_local_policy_is_closed_and_has_distinct_sink_tuple():
    values = local_values()
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    assert policy.sink_tuple() == {
        "schema_version": LOCAL_POLICY_SCHEMA,
        "provider": "local-uds",
        "socket_path": "/run/restricted-inference/broker.sock",
        "method": "restrictedGenerate",
        "model": "operator-display-name",
        "model_sha256": "a" * 64,
        "response_profile": "restricted-local-text-response.v1",
    }
    for mutation in (
        {**values, "hostname": "localhost"},
        {**values, "socket_path": "/tmp/broker.sock"},
        {**values, "model_sha256": "A" * 64},
    ):
        with pytest.raises(ContractError):
            PolicyBundle(mutation, "digest").validate()


def test_vertex_policy_cannot_acquire_a_local_field():
    import json
    from pathlib import Path

    values = json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(policy_epoch="e", tenant_id="tenant", vertex_project_id="project", vertex_project_number="123", model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash", generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent", socket_path="/run/restricted-inference/broker.sock")
    with pytest.raises(ContractError):
        PolicyBundle(values, "digest").validate()


def test_operator_authorization_binds_policy_and_expiry():
    from restricted_runtime.operator_authorization import load_operator_authorization

    values = local_values()
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    private = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    authorization = {
        "schema_version": "restricted-operator-authorization.v1",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "tenant_id": "tenant",
        "provider": "local-uds",
        "model_sha256": "a" * 64,
        "permitted_use_id": "approved-synthetic-probe",
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    }
    signature = private.sign(jcs_bytes(authorization))
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    loaded = load_operator_authorization(authorization, base64.b64encode(signature).decode("ascii"), public, policy, now=now)
    assert loaded.permitted_use_id == "approved-synthetic-probe"
    authorization["tenant_id"] = "other"
    with pytest.raises(ContractError):
        load_operator_authorization(authorization, base64.b64encode(private.sign(jcs_bytes(authorization))).decode("ascii"), public, policy, now=now)


def test_local_response_parser_is_closed_and_never_surfaces_mismatched_text():
    from restricted_runtime.local_uds import parse_local_response

    body = {
        "schema_version": "restricted-local-inference-response.v1",
        "state": "SUCCEEDED",
        "finish_reason": "STOP",
        "text": "synthetic reply",
        "model_sha256": "a" * 64,
        "request_id": "broker-request",
    }
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(jcs_bytes(body))).encode() + b"\r\n\r\n" + jcs_bytes(body)
    result = parse_local_response(raw, "a" * 64)
    assert result.state == "SUCCEEDED" and result.text == "synthetic reply"
    body["model_sha256"] = "b" * 64
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(jcs_bytes(body))).encode() + b"\r\n\r\n" + jcs_bytes(body)
    result = parse_local_response(raw, "a" * 64)
    assert result.state == "INDETERMINATE" and result.text is None


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}trailing",
])
def test_local_response_framing_faults_fail_closed(raw):
    from restricted_runtime.local_uds import parse_local_response

    result = parse_local_response(raw, "a" * 64)
    assert result.state == "INDETERMINATE" and result.text is None


@pytest.mark.skipif(os.name != "posix" or not hasattr(socket, "AF_UNIX"), reason="requires POSIX AF_UNIX /run socket namespace")
def test_local_client_uses_one_closed_unix_socket_request(tmp_path):
    from restricted_runtime.local_uds import LocalUdsClient

    socket_dir = tmp_path / "run" / "restricted-inference"
    socket_dir.mkdir(parents=True)
    socket_path = socket_dir / "broker.sock"
    values = local_values()
    # Test composition supplies a real AF_UNIX endpoint; production policy
    # validation remains restricted to the operator-owned /run namespace.
    values["socket_path"] = "/run/restricted-inference/broker.sock"
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    captured: list[bytes] = []
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # On POSIX use the closed path exactly; on native Windows AF_UNIX does
        # not mount /run, so the test remains an explicit environment skip.
        try:
            Path("/run/restricted-inference").mkdir(parents=True, exist_ok=True)
            live_path = Path("/run/restricted-inference/broker.sock")
            live_path.unlink(missing_ok=True)
            server.bind(str(live_path))
        except OSError:
            pytest.skip("operator /run socket namespace unavailable")
        server.listen(1)
        def serve() -> None:
            conn, _ = server.accept()
            with conn:
                captured.append(conn.recv(65536))
                body = {"schema_version":"restricted-local-inference-response.v1","state":"SUCCEEDED","finish_reason":"STOP","text":"synthetic","model_sha256":"a" * 64,"request_id":"broker-1"}
                payload = jcs_bytes(body)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
        thread = threading.Thread(target=serve); thread.start()
        result = LocalUdsClient(policy, timeout_seconds=2).generate_content([{"role":"user","text":"synthetic"}])
        thread.join(timeout=2)
        assert result.state == "SUCCEEDED" and result.provider_request_id == "broker-1"
        assert len(captured) == 1
        assert captured[0].startswith(b"POST /v1/restricted/generate HTTP/1.1\r\n")
        assert b"declared_model_sha256" in captured[0]
    finally:
        server.close()
        Path("/run/restricted-inference/broker.sock").unlink(missing_ok=True)


def test_local_probe_receipt_has_immutable_external_false_claims():
    from restricted_runtime.contracts import ProviderResult
    from restricted_runtime.local_probe_receipt import protocol_probe_receipt

    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    receipt = protocol_probe_receipt(policy, ProviderResult("SUCCEEDED", provider_request_id="broker", broker_declared_model_sha256="a" * 64), source_revision_claim="unverified-build")
    assert {key: receipt[key] for key in ("external_controls_verified", "deployment_conformant", "model_attested", "phi_authorized")} == {key: False for key in ("external_controls_verified", "deployment_conformant", "model_attested", "phi_authorized")}
    assert receipt["broker_request_id_sha256"] != "broker"
    assert receipt["broker_request_id_sha256"] == hashlib.sha256(b"broker").hexdigest()
