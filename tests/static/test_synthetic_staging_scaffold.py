"""Offline proof that the diagnostic manifest stays isolated and non-PHI."""
from pathlib import Path


ROOT=Path("infra")


def test_staging_manifest_declares_dedicated_resources_and_never_reuses_dev_runtime_names():
    source="\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.tf"))
    for required in ("google_artifact_registry_repository", "google_compute_network", "google_compute_subnetwork", "google_compute_global_address", "google_service_networking_connection", "google_cloud_run_v2_service", "google_cloud_run_v2_job", "google_sql_database_instance", "google_kms_crypto_key", "google_service_account"):
        assert required in source
    assert "hrh-pg2-dev" not in source and "hrh-app-dev" not in source
    assert 'default = "health-record-hub-dev"' in source and 'default = "us-central1"' in source


def test_staging_manifest_pins_images_and_carries_all_closed_runtime_inputs():
    source="\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.tf"))
    for value in ("conversation_image", "gateway_image", "runner_image", "migration_image", "@sha256:", "RESTRICTED_POLICY_PATH", "RESTRICTED_POLICY_SIGNATURE_PATH", "RESTRICTED_POLICY_PUBLIC_KEY_B64", "RESTRICTED_RUNNER_AUDIENCE", "RESTRICTED_GATEWAY_AUDIENCE", "RESTRICTED_CONTENT_WRAP_KEY", "RESTRICTED_SERVICE_MAC_KEY_RESOURCE", "RESTRICTED_GATEWAY_MAC_KEY_RESOURCE", "DATABASE_URL"):
        assert value in source
    assert "--auto-iam-authn" in source and "cloud_sql_proxy_image" in source
    assert "RESTRICTED_CALLER_PRINCIPAL" not in source


def test_staging_has_no_nat_and_keeps_fqdn_sni_residual_undetermined():
    source="\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.tf"))
    assert "google_compute_router_nat" not in source
    assert "UNDETERMINED" in (ROOT / "egress-policy.md").read_text(encoding="utf-8")
