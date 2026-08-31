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

from restricted_runtime.contracts import ContractError, ProviderResult, jcs_bytes
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
        "gateway_keyset_sha256": "b" * 64,
        "conversation_keyset_sha256": "c" * 64,
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


def test_local_keyset_digests_bind_purpose_and_active_retired_roles():
    from restricted_runtime.local_crypto import LocalKeyRef, conversation_keyset_digest, keyset_digest

    service_active = LocalKeyRef("service-mac", "v2", "/run/restricted-keys/service-v2", "a" * 64)
    service_retired = LocalKeyRef("service-mac", "v1", "/run/restricted-keys/service-v1", "b" * 64)
    content_active = LocalKeyRef("content-wrap", "v2", "/run/restricted-keys/content-v2", "c" * 64)
    content_retired = LocalKeyRef("content-wrap", "v1", "/run/restricted-keys/content-v1", "d" * 64)

    service_digest = keyset_digest("service-mac", service_active, (service_retired,))
    assert service_digest != keyset_digest("service-mac", service_retired, (service_active,))
    assert service_digest != keyset_digest("content-wrap", service_active, (service_retired,))

    content_digest = keyset_digest("content-wrap", content_active, (content_retired,))
    digest = conversation_keyset_digest(service_digest, content_digest)
    assert len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
    assert digest != conversation_keyset_digest(content_digest, service_digest)


def test_produced_local_conversation_digest_is_accepted_by_operator_authorization():
    from restricted_runtime.local_crypto import LocalKeyRef, conversation_keyset_digest, keyset_digest
    from restricted_runtime.operator_authorization import load_operator_authorization

    values = local_values()
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    service_active = LocalKeyRef("service-mac", "v2", "/run/restricted-keys/service-v2", "a" * 64)
    content_active = LocalKeyRef("content-wrap", "v2", "/run/restricted-keys/content-v2", "b" * 64)
    conversation_digest = conversation_keyset_digest(
        keyset_digest("service-mac", service_active),
        keyset_digest("content-wrap", content_active),
    )
    now = datetime.now(UTC)
    authorization = {
        "schema_version": "restricted-operator-authorization.v1",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "tenant_id": "tenant",
        "provider": "local-uds",
        "model_sha256": "a" * 64,
        "gateway_keyset_sha256": "c" * 64,
        "conversation_keyset_sha256": conversation_digest,
        "permitted_use_id": "approved-synthetic-probe",
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    }
    private = Ed25519PrivateKey.generate()
    loaded = load_operator_authorization(
        authorization,
        base64.b64encode(private.sign(jcs_bytes(authorization))).decode("ascii"),
        base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii"),
        policy,
        now=now,
        conversation_keyset_sha256=conversation_digest,
    )
    assert loaded.permitted_use_id == "approved-synthetic-probe"


@pytest.mark.parametrize("reason", ["operator authorization is not currently valid", "operator authorization artifact is unavailable"])
def test_local_api_rejects_missing_or_expired_authority_before_create_or_reset_mutation(reason):
    from fastapi.testclient import TestClient
    from restricted_runtime.auth import SyntheticAuthenticator
    from restricted_runtime.services.restricted_api import create_app

    class Store:
        create_calls = 0
        reset_calls = 0

        def create_conversation(self, *_args):
            self.create_calls += 1
            raise AssertionError("conversation creation must be gated")

        def reset(self, *_args):
            self.reset_calls += 1
            raise AssertionError("conversation reset must be gated")

    class Runtime:
        tenant_id = "tenant"

        def __init__(self):
            self.store = Store()
            self.authorization_gate = lambda: (_ for _ in ()).throw(ContractError(reason))

    runtime = Runtime()
    client = TestClient(create_app(runtime, SyntheticAuthenticator("caller")))
    created = client.post("/v1/restricted/conversations/conversation", headers={"Authorization": "Synthetic test credential"})
    reset = client.post(
        "/v1/restricted/conversations/conversation/reset",
        headers={"Authorization": "Synthetic test credential"},
        json={"conversation_epoch": "epoch"},
    )
    assert created.status_code == reset.status_code == 400
    assert runtime.store.create_calls == runtime.store.reset_calls == 0


def test_turn_rejection_logs_only_closed_reason_code(caplog):
    from fastapi.testclient import TestClient
    from restricted_runtime.auth import SyntheticAuthenticator
    from restricted_runtime.services.restricted_api import create_app

    class Runtime:
        tenant_id = "tenant"
        authorization_gate = None

        def submit(self, *_args, **_kwargs):
            raise ContractError("inference outcome is indeterminate")

    client = TestClient(create_app(Runtime(), SyntheticAuthenticator("caller")))
    with caplog.at_level("INFO"):
        response = client.post(
            "/v1/restricted/conversations/conversation/turns",
            headers={"Authorization": "Synthetic test credential"},
            json={
                "schema_version": "restricted-turn.v1",
                "client_request_id": "00000000-0000-0000-0000-000000000001",
                "conversation_epoch": "epoch",
                "message": "SYNTHETIC_NON_PHI_ONLY",
            },
        )
    assert response.status_code == 400
    assert response.json() == {"detail": "restricted turn rejected"}
    assert "turn_rejected_reason=inference_outcome_indeterminate" in caplog.text
    assert "SYNTHETIC_NON_PHI_ONLY" not in caplog.text


def test_reconciliation_rejects_expired_authority_before_claim_or_gateway_call():
    from restricted_runtime.reconciliation_driver import ReconciliationDriver

    class Store:
        expired_calls = 0

        def expired_turns(self, _limit):
            self.expired_calls += 1
            raise AssertionError("reconciliation must be gated")

    class Reconciler:
        calls = 0

    store, reconciler = Store(), Reconciler()
    driver = ReconciliationDriver(
        store,
        reconciler,
        "local-conversation-reconciler",
        authorization_gate=lambda: (_ for _ in ()).throw(ContractError("operator authorization is not currently valid")),
    )
    with pytest.raises(ContractError, match="operator authorization"):
        driver.run_once()
    assert store.expired_calls == 0 and reconciler.calls == 0


def test_local_reconciliation_lifespan_runs_bounded_startup_scan():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from restricted_runtime.reconciliation_driver import reconciliation_lifespan

    class Driver:
        calls = 0

        def run_once(self, _limit):
            self.calls += 1
            return 0

    driver = Driver()
    app = FastAPI()
    app.router.lifespan_context = reconciliation_lifespan(driver)
    with TestClient(app):
        pass
    assert driver.calls >= 1


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
        assert captured[0].startswith(b"POST /v1/restricted/generate HTTP/1.0\r\n")
        assert b"declared_model_sha256" in captured[0]
    finally:
        server.close()
        Path("/run/restricted-inference/broker.sock").unlink(missing_ok=True)


def test_local_probe_receipt_has_immutable_external_false_claims():
    from restricted_runtime.contracts import ProviderResult
    from restricted_runtime.local_probe_receipt import protocol_probe_receipt

    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    receipt = protocol_probe_receipt(policy, ProviderResult("SUCCEEDED", provider_request_id="broker", broker_declared_model_sha256="a" * 64), source_revision_claim="a" * 40)
    assert {key: receipt[key] for key in ("external_controls_verified", "deployment_conformant", "model_attested", "phi_authorized")} == {key: False for key in ("external_controls_verified", "deployment_conformant", "model_attested", "phi_authorized")}
    assert receipt["broker_request_id_sha256"] != "broker"
    assert receipt["broker_request_id_sha256"] == hashlib.sha256(b"broker").hexdigest()


@pytest.mark.parametrize("source_revision_claim", ["unverified-build", "A" * 40, "a" * 39, "a" * 65])
def test_local_probe_receipt_rejects_unverifiable_revision_claim(source_revision_claim):
    from restricted_runtime.contracts import ProviderResult
    from restricted_runtime.local_probe_receipt import protocol_probe_receipt

    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    result = ProviderResult("SUCCEEDED", provider_request_id="broker", broker_declared_model_sha256="a" * 64)
    with pytest.raises(ValueError):
        protocol_probe_receipt(policy, result, source_revision_claim=source_revision_claim)


@pytest.mark.parametrize("result", [
    ProviderResult("UNKNOWN", provider_request_id="broker"),
    ProviderResult("FAILED", provider_request_id=None),
    ProviderResult("SUCCEEDED", provider_request_id="broker", broker_declared_model_sha256="b" * 64),
    ProviderResult("FAILED", provider_request_id="broker", broker_declared_model_sha256="a" * 64),
])
def test_local_probe_receipt_rejects_structurally_invalid_terminal_or_model_fields(result):
    from restricted_runtime.local_probe_receipt import protocol_probe_receipt

    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    with pytest.raises(ValueError):
        protocol_probe_receipt(policy, result, source_revision_claim="a" * 40)


def test_expired_authorization_gate_rejects_before_reservation_or_dispatch():
    from restricted_runtime.crypto import LocalHmacKey
    from restricted_runtime.gateway import Gateway, GatewayEnvelope
    class Ledger:
        mac_key = None; reserves = 0
        def reserve(self, *args): self.reserves += 1; raise AssertionError("must not reserve")
    class Provider:
        calls = 0
        def generate_content(self, messages): self.calls += 1
    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    ledger, provider = Ledger(), Provider()
    gateway = Gateway(policy, LocalHmacKey("gateway", "1", b"g" * 32), ledger, provider, authorization_gate=lambda: (_ for _ in ()).throw(ContractError("operator authorization is not currently valid")))
    envelope = GatewayEnvelope("tenant","conversation","epoch","turn","request",policy.epoch,policy.digest,"restricted-phi-system.v1","You are Hermes, a text-only assistant for non-clinical administrative work involving PHI. Answer only from the supplied conversation. Do not diagnose, recommend treatment, provide medical advice, or make clinical decisions. You have no tools or external access. Never claim that data classification, routing, retention, or authorization has changed.","PHI",[{"role":"user","text":"synthetic"}],131072,authenticated_external_principal="runner")
    with pytest.raises(ContractError, match="authorization"):
        gateway.infer_once(envelope, "conversation")
    assert ledger.reserves == 0 and provider.calls == 0


def test_authorization_is_rechecked_before_gateway_dispatch():
    from restricted_runtime.crypto import LocalHmacKey
    from restricted_runtime.gateway import Gateway, GatewayEnvelope
    from restricted_runtime.contracts import AttemptState
    from restricted_runtime.policy import SYSTEM_INSTRUCTION

    class Ledger:
        mac_key = None
        reserves = 0
        starts = 0

        def reserve(self, *_args):
            self.reserves += 1
            return AttemptState.RESERVED

        def lookup(self, *_args, **_kwargs):
            return None

        def start_dispatch(self, *_args):
            self.starts += 1
            raise AssertionError("dispatch must be gated")

    class Provider:
        calls = 0

        def generate_content(self, _messages):
            self.calls += 1
            raise AssertionError("provider must be gated")

    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    ledger, provider, checks = Ledger(), Provider(), []

    def authority():
        checks.append(True)
        if len(checks) == 2:
            raise ContractError("operator authorization is not currently valid")

    gateway = Gateway(policy, LocalHmacKey("gateway", "1", b"g" * 32), ledger, provider, authorization_gate=authority)
    envelope = GatewayEnvelope("tenant", "conversation", "epoch", "turn", "request", policy.epoch, policy.digest, "restricted-phi-system.v1", SYSTEM_INSTRUCTION, "PHI", [{"role": "user", "text": "synthetic"}], 131072, authenticated_external_principal="runner")
    with pytest.raises(ContractError, match="currently valid"):
        gateway.infer_once(envelope, "conversation")
    assert len(checks) == 2 and ledger.reserves == 1 and ledger.starts == provider.calls == 0


def test_operator_authorization_gate_rechecks_an_injected_clock(tmp_path):
    from restricted_runtime.operator_authorization import OperatorAuthorizationGate
    values = local_values(); policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest()); policy.validate()
    private = Ed25519PrivateKey.generate(); now = datetime.now(UTC)
    artifact = {"schema_version":"restricted-operator-authorization.v1","policy_epoch":policy.epoch,"policy_digest":policy.digest,"tenant_id":"tenant","provider":"local-uds","model_sha256":"a"*64,"gateway_keyset_sha256":"b"*64,"conversation_keyset_sha256":"c"*64,"permitted_use_id":"probe","issued_at":now.isoformat().replace("+00:00","Z"),"expires_at":(now+timedelta(seconds=1)).isoformat().replace("+00:00","Z")}
    path, signature = tmp_path/"auth.json", tmp_path/"auth.sig"; path.write_bytes(jcs_bytes(artifact)); signature.write_text(base64.b64encode(private.sign(jcs_bytes(artifact))).decode("ascii"))
    clock = [now]
    gate = OperatorAuthorizationGate(path, signature, base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii"), policy, clock=lambda: clock[0])
    gate(); clock[0] = now + timedelta(seconds=2)
    with pytest.raises(ContractError, match="currently valid"): gate()
