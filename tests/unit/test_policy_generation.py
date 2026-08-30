import base64
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from restricted_runtime.policy import load_signed_policy
from tools.generate_synthetic_policy import generate


def test_external_private_key_generates_verifiable_truthful_synthetic_bundle(tmp_path):
    private=Ed25519PrivateKey.generate();raw=private.private_bytes_raw();key=tmp_path/"external-key.txt";key.write_text(base64.b64encode(raw).decode("ascii"),encoding="ascii")
    policy,sig,digest=generate(template=Path("policy/policy.template.json"),output_dir=tmp_path/"generated",private_key_b64_file=key,project_id="project",project_number="123",epoch="e1",tenant_id="tenant",runner_principal="runner@example.com",conversation_principal="conversation@example.com")
    public=base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
    loaded=load_signed_policy(policy,sig,public)
    assert loaded.digest==digest and loaded.values["authorization_status"]=="synthetic-non-phi-only"


def test_policy_generator_rejects_private_key_inside_repository_build_context(tmp_path):
    private=Ed25519PrivateKey.generate(); key=Path("policy")/"do-not-use-private-key.txt"
    key.write_text(base64.b64encode(private.private_bytes_raw()).decode("ascii"),encoding="ascii")
    try:
        with pytest.raises(ValueError,match="outside the repository"):
            generate(template=Path("policy/policy.template.json"),output_dir=tmp_path/"generated",private_key_b64_file=key,project_id="project",project_number="123",epoch="e1",tenant_id="tenant",runner_principal="runner@example.com",conversation_principal="conversation@example.com")
    finally:
        key.unlink()
