"""Static contract for the operator-owned local Linux deployment profile."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "local"


def _compose(name: str = "compose.yaml") -> dict:
    return yaml.safe_load((DEPLOY / name).read_text(encoding="utf-8"))


def test_default_runtime_has_no_network_ports_or_forbidden_environment():
    document = _compose()
    services = document["services"]
    forbidden = {
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "GOOGLE_APPLICATION_CREDENTIALS", "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "MODEL", "MODEL_ID",
    }
    for name in ("conversation", "gateway"):
        service = services[name]
        assert service["network_mode"] == "none"
        assert "ports" not in service and "expose" not in service
        environment = service.get("environment", {})
        assert forbidden.isdisjoint(environment)
    assert "networks" not in document


def test_fixed_identities_and_distinct_postgres_peer_roles_are_declared():
    document = _compose()
    services = document["services"]
    assert services["conversation"]["user"] == "10006:20001"
    assert services["gateway"]["user"] == "10005:20002"
    assert services["conversation"]["group_add"] == ["20000", "20002", "20004"]
    assert services["gateway"]["group_add"] == ["20000", "20003", "20004"]
    conversation_url = services["conversation"]["environment"]["DATABASE_URL"]
    gateway_url = services["gateway"]["environment"]["DATABASE_URL"]
    assert "host=/run/restricted-postgres" in conversation_url
    assert "user=restricted_local_conversation" in conversation_url
    assert "user=restricted_local_gateway" in gateway_url
    assert "password" not in conversation_url.lower() + gateway_url.lower()


def test_operator_artifacts_are_external_and_runtime_mounts_are_read_only():
    document = _compose()
    volumes = document["volumes"]
    for name in ("inference_sockets", "conversation_authorization", "gateway_authorization", "conversation_keys", "gateway_keys"):
        assert volumes[name]["external"] is True
    for role in ("conversation", "gateway"):
        mounts = document["services"][role]["volumes"]
        protected = [mount for mount in mounts if mount["target"] in {"/run/restricted-operator", "/run/restricted-keys"}]
        assert len(protected) == 2
        assert all(mount["read_only"] is True for mount in protected)


def test_default_profile_does_not_contain_a_broker_or_authority_generator():
    services = _compose()["services"]
    assert "broker" not in services
    assert all("synthetic" not in name for name in services)
    assert "operator-authorization" not in " ".join(str(services).lower().split()) or "generate" not in str(services).lower()


def test_synthetic_overlay_is_explicitly_non_phi_and_opt_in():
    overlay = _compose("compose.synthetic-non-phi-only.yaml")
    services = overlay["services"]
    assert set(services) >= {"synthetic-non-phi-only-broker", "synthetic-non-phi-only-probe"}
    for name, service in services.items():
        assert "synthetic-non-phi-only" in name
        assert service["profiles"] == ["synthetic-non-phi-only"]
        assert service["network_mode"] == "none"


def test_local_database_bootstrap_is_separate_from_cloud_sql_runner():
    compose_text = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    bootstrap = (DEPLOY / "postgres" / "020-local-bootstrap.sql").read_text(encoding="utf-8")
    assert "Dockerfile.migration" not in compose_text
    assert "restricted_local_conversation" in bootstrap
    assert "restricted_local_gateway" in bootstrap
    assert "BYPASSRLS" in bootstrap and "CREATEROLE" in bootstrap
    assert "restricted_content_runtime" in bootstrap and "restricted_ledger_runtime" in bootstrap


def test_operator_runbook_and_evidence_template_state_nonclaims():
    combined = "\n".join(
        (DEPLOY / name).read_text(encoding="utf-8")
        for name in ("README.md", "EVIDENCE.template.md")
    ).lower()
    for phrase in ("not hipaa", "not phi authorization", "model_attested=false", "deployment_conformant=false", "phi_authorized=false"):
        assert phrase in combined
