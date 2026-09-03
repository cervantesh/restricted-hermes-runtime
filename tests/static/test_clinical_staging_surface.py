from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
STAGING = ROOT / "deploy" / "clinical-staging"


def test_staging_overlay_publishes_only_hardened_loopback_passthrough():
    compose = yaml.safe_load((STAGING / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    proxy = services["operator-proxy"]
    assert "ports" not in services["mattermost"]
    assert proxy["image"] == "nginx:1.28.0-alpine@sha256:30f1c0d78e0ad60901648be663a710bdadf19e4c10ac6782c235200619158284"
    assert proxy["ports"] == ["127.0.0.1:${CLINICAL_STAGING_PORT:?required}:18444"]
    assert all("ports" not in value for name, value in services.items() if name != "operator-proxy")
    assert proxy["user"] == "101:101"
    assert proxy["read_only"] is True
    assert proxy["cap_drop"] == ["ALL"]
    assert proxy["security_opt"] == ["no-new-privileges:true"]
    assert proxy["networks"] == ["operator_access", "mattermost_edge"]
    assert set(proxy.get("volumes", [])) == {
        "../../../deploy/clinical-staging/nginx-stream.conf:/etc/nginx/nginx.conf:ro"
    }
    assert compose["networks"]["operator_access"]["internal"] is False
    for network in ("mattermost_edge", "mattermost_backend", "hrh_backend", "clinical_upstream"):
        assert compose["networks"][network]["internal"] is True
    assert services["controller"]["profiles"] == ["provision"]
    assert services["controller"]["restart"] == "no"
    assert services["hrh"]["build"]["args"]["BUILD_SHA"] == "${CLINICAL_HRH_BUILD_SHA:?required}"


def test_passthrough_configuration_is_fixed_secretless_l4():
    config = (STAGING / "nginx-stream.conf").read_text(encoding="ascii")
    assert "stream {" in config
    assert "listen 18444;" in config
    assert "proxy_pass mattermost:8065;" in config
    assert "ssl_certificate" not in config
    assert "http {" not in config


def test_staging_volumes_are_external_exactly_named_and_label_verified_by_wrapper():
    compose = yaml.safe_load((STAGING / "compose.yaml").read_text(encoding="utf-8"))
    assert len(compose["volumes"]) == 11
    for logical, value in compose["volumes"].items():
        assert value == {
            "external": True,
            "name": "${CLINICAL_VOLUME_" + logical.upper() + ":?required}",
        }


def test_operator_surface_is_bounded_and_runbook_preserves_nonclaims():
    script = (STAGING / "clinical_staging.py").read_text(encoding="utf-8")
    runbook = (STAGING / "README.md").read_text(encoding="utf-8")
    for command in ("init", "up", "status", "refresh-policy", "stop", "reset", "destroy"):
        assert command in script
    assert "docker system prune" not in script
    assert '"--remove-orphans"' not in script
    assert "verify_effective_env" in script
    assert "verify_destructive_resources" in script
    assert "expected_images" in script
    assert "fsync_directory" in script
    assert "synthetic-only" in runbook
    assert "not HIPAA" in runbook
    assert "not production" in runbook
    assert "privileged provisioner" in runbook
