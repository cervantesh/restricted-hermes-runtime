"""Offline proof that the diagnostic manifest stays isolated and non-PHI."""
from pathlib import Path
import re
import yaml


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
    assert 'dest_range       = "199.36.153.4/30"' in source
    assert "restricted.googleapis.com." in source
    assert 'dns_name   = "run.app."' in source and 'name         = "*.run.app."' in source
    assert "google_compute_firewall" in source and 'protocol = "all"' in source
    assert "UNDETERMINED" in (ROOT / "egress-policy.md").read_text(encoding="utf-8")


def test_staging_uses_iam_database_auth_key_scoped_kms_and_fail_closed_jobs():
    source="\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.tf"))
    assert len(re.findall(r'role\s*=\s*"roles/cloudsql\.instanceUser"',source)) == 3
    assert "google_kms_crypto_key_iam_member" in source
    assert "roles/cloudkms.cryptoKeyEncrypterDecrypter" in source
    assert len(re.findall(r'role\s*=\s*"roles/cloudkms\.signerVerifier"',source)) == 2
    assert "migration_bootstrap_secret_id" in source and "MIGRATION_ADMIN_DSN" in source
    assert "--auto-iam-authn" in source and "RESTRICTED_SYNTHETIC_PAYLOAD" in source
    assert 'default = false' in source and "RESTRICTED_ADMISSION_ENABLED" in source
    assert "jsonencode(var.retired_service_mac_versions)" in source


def test_kms_algorithms_image_provenance_and_policy_build_context_are_closed():
    source="\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.tf"))
    assert source.count('version_template { algorithm = "HMAC_SHA256" }') == 4
    assert 'algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"' in source
    assert 'algorithm = "EC_SIGN_ED25519"' in source
    assert 'cryptoKeyVersions/1' not in source
    assert "runtime_images_are_project_owned" in source
    assert 'artifact_registry_prefix = "${var.region}-docker.pkg.dev/${var.project_id}/restricted-synthetic-runtime/"' in source
    dockerignore=Path(".dockerignore").read_text(encoding="utf-8")
    assert "!policy/generated/policy.json" in dockerignore and "!policy/generated/policy.sig" in dockerignore
    for name in ("Dockerfile.conversation","Dockerfile.gateway"):
        recipe=Path(name).read_text(encoding="utf-8")
        assert "COPY policy ./policy" not in recipe
        assert "policy/generated/policy.json" in recipe and "policy/generated/policy.sig" in recipe


def test_cloud_build_source_context_includes_only_public_policy_artifacts():
    ignore=Path(".gcloudignore").read_text(encoding="utf-8")
    for excluded in (".git", ".serena/", ".env", "*.pem", "*.key", "*.p8", "*private*", "*.tfstate", "*.tfvars", "policy/generated/*"):
        assert excluded in ignore
    assert "!policy/generated/policy.json" in ignore
    assert "!policy/generated/policy.sig" in ignore
    assert "!policy/generated/public_key.b64" not in ignore


def test_migration_uses_password_admin_socket_while_runtime_sidecars_use_iam_auth():
    source=(ROOT/"runtime.tf").read_text(encoding="utf-8")
    assert len(re.findall(r'args\s*=\s*\["--private-ip",\s*"--auto-iam-authn"',source))==2
    assert "RESTRICTED_EXPECTED_MIGRATION_SOCKET" in source
    assert 'args = ["--private-ip", "--unix-socket=/cloudsql"' in source
    assert "MIGRATION_ADMIN_DSN" in source


def test_connectors_fit_the_official_weighted_name_limit_and_sql_users_are_trimmed():
    main=(ROOT/"main.tf").read_text(encoding="utf-8")
    names=re.findall(r'resource "google_vpc_access_connector" "\w+" \{\s+name\s*=\s*"([^"]+)"',main)
    assert len(names)==4 and all(len(name)+name.count("-") < 21 for name in names)
    assert "trimsuffix(google_service_account.conversation.email, \".gserviceaccount.com\")" in main
    assert "trimsuffix(google_service_account.gateway.email, \".gserviceaccount.com\")" in main
    runtime=(ROOT/"runtime.tf").read_text(encoding="utf-8")
    assert "local.conversation_db_user" in runtime and "local.gateway_db_user" in runtime


def test_connectors_have_explicit_supported_capacity_and_psc_uses_the_reserved_address_uri():
    main=(ROOT/"main.tf").read_text(encoding="utf-8")
    assert main.count("min_instances = 2") == 4
    assert main.count("max_instances = 3") == 4
    assert 'resource "google_compute_address" "vertex_psc"' in main
    endpoint=main.split('resource "google_network_connectivity_regional_endpoint" "vertex_us" {',1)[1].split("}",1)[0]
    assert "address           = google_compute_address.vertex_psc.id" in endpoint
    assert 'rrdatas      = [google_compute_address.vertex_psc.address]' in main
    assert 'destination_ranges = ["${google_compute_address.vertex_psc.address}/32"]' in main


def test_durable_dispatch_control_starts_disabled_and_is_not_mutable_by_gateway_role():
    migration=Path("migrations/001_restricted_runtime.sql").read_text(encoding="utf-8")
    storage=Path("src/restricted_runtime/storage.py").read_text(encoding="utf-8")
    assert "CREATE TABLE inference_ledger.runtime_controls" in migration
    assert "dispatch_enabled boolean NOT NULL DEFAULT false" in migration
    assert "REVOKE INSERT, UPDATE, DELETE ON inference_ledger.runtime_controls FROM restricted_ledger_runtime" in migration
    assert "FOR SHARE" in storage and "attempt[\"state\"] != \"RESERVED\"" in storage


def test_vertex_us_sink_uses_its_own_psc_dns_and_not_the_restricted_vip():
    policy=Path("policy/policy.template.json").read_text(encoding="utf-8")
    egress=(ROOT/"egress-policy.md").read_text(encoding="utf-8")
    main=(ROOT/"main.tf").read_text(encoding="utf-8")
    assert '"hostname": "aiplatform.us.rep.googleapis.com"' in policy
    assert '"location": "us"' in policy
    assert 'resource "google_network_connectivity_regional_endpoint" "vertex_us"' in main
    assert 'target_google_api = "aiplatform.us.rep.googleapis.com"' in main
    assert 'dns_name   = "aiplatform.us.rep.googleapis.com."' in main
    assert 'name         = "aiplatform.us.rep.googleapis.com."' in main
    assert 'destination_ranges = ["${google_compute_address.vertex_psc.address}/32"]' in main
    assert 'target_tags        = [local.gateway_connector_tag]' in main
    assert "It is **not** sent to the restricted VIP" in egress


def test_release_recipe_has_no_fake_digest_or_private_key_and_imports_manual_registry():
    pipeline_path=ROOT/"cloudbuild.images.yaml"
    pipeline=pipeline_path.read_text(encoding="utf-8")
    parsed=yaml.safe_load(pipeline_path.read_text(encoding="utf-8"))
    bootstrap=(ROOT/"BOOTSTRAP.md").read_text(encoding="utf-8")
    assert "restricted-synthetic-runtime" in pipeline and "$PROJECT_ID" in pipeline
    assert "private-key" not in pipeline.lower()
    assert len(parsed["steps"]) == 4 and len(parsed["images"]) == 4
    assert all(isinstance(step["args"],list) and step["args"][-2].startswith("${_REGION}-docker.pkg.dev/$PROJECT_ID/") for step in parsed["steps"])
    assert "gcloud artifacts repositories create" in bootstrap
    assert "terraform -chdir=infra import -var-file=../operator.synthetic.tfvars google_artifact_registry_repository.runtime" in bootstrap
    assert "sha256:000" not in bootstrap.lower()
