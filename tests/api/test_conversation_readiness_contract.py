"""The conversation readiness document is a closed policy-derived contract."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from restricted_runtime.auth import SyntheticAuthenticator
from restricted_runtime.contracts import ContractError, jcs_bytes
from restricted_runtime.local_deployment_preflight import _read_conversation_readiness, validate_conversation_readiness
from restricted_runtime.policy import PolicyBundle
from restricted_runtime.services.restricted_api import create_app, readiness_document


def _policy() -> PolicyBundle:
    values = json.loads(Path("policy/local.policy.template.json").read_text(encoding="utf-8"))
    values.update(
        policy_epoch="2026-08-31.1",
        external_runner_principal="local-runner",
        gateway_invoker_principal="local-gateway",
        tenant_id="tenant",
        model="qwen2.5:7b",
        model_sha256="a" * 64,
    )
    policy = PolicyBundle(values, hashlib.sha256(jcs_bytes(values)).hexdigest())
    policy.validate()
    return policy


def test_readyz_is_the_exact_policy_derived_capability_document():
    policy = _policy()
    response = TestClient(create_app(SimpleNamespace(policy=policy), SyntheticAuthenticator("caller"), lambda: True)).get("/readyz")
    expected = {
        "schema_version": "restricted-conversation-readiness.v1",
        "status": "ready",
        "policy_epoch": policy.epoch,
        "policy_digest": policy.digest,
        "classification": policy.values["classification"],
        "system_instruction_version": policy.values["system_instruction_version"],
        "allowed_modalities": policy.values["allowed_modalities"],
        "tools_allowed": policy.values["tools_allowed"],
        "fallbacks": policy.values["fallbacks"],
        "max_provider_attempts": policy.values["max_provider_attempts"],
        "streaming": policy.values["streaming"],
        "max_output_tokens": policy.values["max_output_tokens"],
        "max_canonical_input_utf8_bytes": policy.values["max_canonical_input_utf8_bytes"],
        "response_profile": policy.values["response_profile"],
    }
    assert response.status_code == 200
    assert response.json() == expected
    assert readiness_document(policy) == expected


@pytest.mark.parametrize("mutation", [
    lambda values: values.__setitem__("unknown", "value"),
    lambda values: values.__setitem__("allowed_modalities", ["text", "image"]),
])
def test_readyz_fails_closed_when_its_policy_cannot_prove_the_closed_contract(mutation):
    policy = _policy()
    mutation(policy.values)
    response = TestClient(create_app(SimpleNamespace(policy=policy), SyntheticAuthenticator("caller"), lambda: True)).get("/readyz")
    assert response.status_code == 503


def test_preflight_rejects_unknown_or_mismatched_readiness_fields():
    policy = _policy()
    exact = readiness_document(policy)
    validate_conversation_readiness(json.dumps(exact).encode("utf-8"), policy)
    for mutation in (
        lambda value: value.__setitem__("unknown", True),
        lambda value: value.__setitem__("policy_digest", "0" * 64),
        lambda value: value.__setitem__("tools_allowed", True),
    ):
        candidate = dict(exact)
        mutation(candidate)
        with pytest.raises(ContractError, match="readiness"):
            validate_conversation_readiness(json.dumps(candidate).encode("utf-8"), policy)


def test_preflight_rejects_duplicate_json_keys():
    with pytest.raises(ContractError, match="readiness"):
        validate_conversation_readiness(b'{"status":"ready","status":"ready"}', _policy())


def test_preflight_rejects_invalid_http_framing_before_binding_readiness():
    policy = _policy()
    body = json.dumps(readiness_document(policy), separators=(",", ":")).encode("utf-8")
    _read_conversation_readiness(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body, policy)
    for response in (
        b"HTTP/1.1 200 OK\r\n\r\n" + body,
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n" + body,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n" + body,
    ):
        with pytest.raises(ContractError, match="readiness"):
            _read_conversation_readiness(response, policy)
