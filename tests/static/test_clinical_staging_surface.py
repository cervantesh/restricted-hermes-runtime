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
    for command in ("init", "up", "status", "refresh-policy", "stop", "backup", "restore", "reset", "destroy"):
        assert command in script
    assert "docker system prune" not in script
    assert '"--remove-orphans"' not in script
    assert "verify_effective_env" in script
    assert "verify_destructive_resources" in script
    assert "expected_images" in script
    assert "fsync_directory" in script
    assert "validate_backup_bundle" in script
    assert "expected_manifest_sha256" in script
    assert "EXCLUDED_RECOVERY_VOLUME" in script
    assert "ownership_sha256" in script
    assert "synthetic-only" in runbook
    assert "not HIPAA" in runbook
    assert "not production" in runbook
    assert "privileged provisioner" in runbook
    assert "dropped capabilities" in runbook
    assert "no-new-privileges" in runbook
    assert 'RUNTIME_BASE_SHA = "41464aee8748f857153ba2b47377515d4847d210"' in script
    assert 'REQUIRED_HRH_SHA = "e30a4f968de6727519f49c08369f561fdf269ec5"' in script
    assert 'REQUIRED_HRH_TREE = "7fb2543a2ceb1649f05c467b38708d1404106659"' in script
    assert "Dockerfile.web.clinical-candidate" in script
    assert "Dockerfile.migrate.clinical-candidate" in script
    assert "verify_hrh_candidate_build_inputs(self.hrh)" in script
    assert "Cold backup and restore" in runbook
    assert "not a scheduled backup" in runbook


def test_egress_failure_packet_is_content_safe_and_outside_disposable_state():
    harness = (ROOT / "tests" / "deployment" / "test_representative_clinical_egress.sh").read_text(encoding="utf-8")

    assert 'diagnostic_dir="$receipt.diagnostic"' in harness
    assert 'mkdir -m 0700 "$diagnostic_dir"' in harness
    assert 'chmod 0600 "$temporary"' in harness
    assert 'rm -f "$receipt"; rm -rf "$evidence_dir"' in harness
    assert "write_diagnostic" in harness
    assert "collector_class_from" in harness
    assert "receipt-policy/service-observation" in harness
    assert "collector-generic" in harness
    assert "receipt-policy/verification-ingress-networks" in harness
    assert "receipt-policy/verification-clinical-adapter-proxy" in harness
    assert "receipt-policy/verification-unknown" in harness
    assert "exact_name_absent" in harness
    assert "docker network ls --format '{{.Name}}'" in harness
    assert "docker container ls --all --format '{{.Names}}'" in harness
    assert "docker network inspect" not in harness
    assert "docker container inspect" not in harness
    packet = next(line for line in harness.splitlines() if '"schema":"restricted-runtime-representative-clinical-egress-diagnostic.v1"' in line)
    for forbidden in ("$network", "$sink", "$state", "$project", "$controlled_"):
        assert forbidden not in packet
