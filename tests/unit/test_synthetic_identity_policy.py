"""The two authenticated hops and synthetic posture are distinct policy facts."""
import hashlib
import json
from pathlib import Path

import pytest

from restricted_runtime.contracts import ContractError, jcs_bytes
from restricted_runtime.gateway import GatewayEnvelope
from restricted_runtime.policy import PolicyBundle, SYSTEM_INSTRUCTION


def synthetic_policy() -> PolicyBundle:
    values=json.loads(Path("policy/policy.template.json").read_text(encoding="utf-8"))
    values.update(
        policy_epoch="diagnostic-1", tenant_id="tenant",
        authorization_status="synthetic-non-phi-only",
        external_runner_principal="runner@example.com",
        gateway_invoker_principal="conversation@example.com",
        vertex_project_id="project", vertex_project_number="123",
        model_resource="projects/123/locations/us/publishers/google/models/gemini-3.5-flash",
        generate_content_path="/v1/projects/123/locations/us/publishers/google/models/gemini-3.5-flash:generateContent",
    )
    return PolicyBundle(values,hashlib.sha256(jcs_bytes(values)).hexdigest())


def test_truthful_synthetic_policy_requires_two_distinct_principals_and_unverified_posture():
    policy=synthetic_policy();policy.validate()
    for field in ("provider_request_logging","provider_response_logging","vertex_data_access_payload_logging","vertex_in_memory_cache","training_use","retention_profile"):
        values=dict(policy.values);values[field]="disabled"
        with pytest.raises(ContractError):PolicyBundle(values,policy.digest).validate()
    values=dict(policy.values);values["gateway_invoker_principal"]=values["external_runner_principal"]
    with pytest.raises(ContractError):PolicyBundle(values,policy.digest).validate()


def test_gateway_envelope_canonical_binds_server_set_external_runner_not_internal_oidc_principal():
    policy=synthetic_policy()
    envelope=GatewayEnvelope("tenant","conversation","epoch","turn","request",policy.epoch,policy.digest,"restricted-phi-system.v1",SYSTEM_INSTRUCTION,"PHI",[{"role":"user","text":"synthetic"}],131072,authenticated_external_principal="runner@example.com")
    assert b"runner@example.com" in envelope.canonical()
    assert b"conversation@example.com" not in envelope.canonical()
