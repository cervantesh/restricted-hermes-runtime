terraform {
  required_version = ">= 1.7"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

variable "project_id" {
  type    = string
  default = "health-record-hub-dev"
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "tenant_id" { type = string }
variable "policy_epoch" { type = string }
variable "policy_digest" { type = string }
variable "policy_public_key_b64" { type = string }
variable "ttl" { type = string }
variable "admission_enabled" {
  type    = bool
  default = false
}
variable "migration_bootstrap_secret_id" {
  type        = string
  description = "Operator-created Secret Manager secret ID containing only the one-time admin DSN."
  validation {
    condition     = length(trimspace(var.migration_bootstrap_secret_id)) > 0
    error_message = "migration bootstrap secret reference is mandatory; Terraform never creates its value."
  }
}
variable "conversation_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.conversation_image))
    error_message = "conversation image must be pinned by digest"
  }
}
variable "gateway_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.gateway_image))
    error_message = "gateway image must be pinned by digest"
  }
}
variable "runner_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.runner_image))
    error_message = "runner image must be pinned by digest"
  }
}
variable "migration_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.migration_image))
    error_message = "migration image must be pinned by digest"
  }
}
variable "cloud_sql_proxy_image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.cloud_sql_proxy_image))
    error_message = "proxy image must be pinned by digest"
  }
}
variable "retired_service_mac_versions" {
  type    = list(object({ key_resource = string, key_version = string, verify_version = string }))
  default = []
}
variable "retired_gateway_mac_versions" {
  type    = list(object({ key_resource = string, key_version = string, verify_version = string }))
  default = []
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  labels                   = { restricted_runtime = "synthetic-only", ttl = var.ttl, phi = "forbidden" }
  runner_audience          = "https://restricted-synthetic-conversation-${var.project_id}.run.app"
  gateway_audience         = "https://restricted-synthetic-gateway-${var.project_id}.run.app"
  artifact_registry_prefix = "${var.region}-docker.pkg.dev/${var.project_id}/restricted-synthetic-runtime/"
}

check "runtime_images_are_project_owned" {
  assert {
    condition = alltrue([
      for image in [var.conversation_image, var.gateway_image, var.runner_image, var.migration_image] :
      startswith(image, local.artifact_registry_prefix) && can(regex("@sha256:[0-9a-f]{64}$", image))
    ]) && startswith(var.cloud_sql_proxy_image, "gcr.io/cloud-sql-connectors/cloud-sql-proxy@sha256:")
    error_message = "runtime images must be digests from this project's restricted Artifact Registry; only the official digest-pinned Cloud SQL proxy is external."
  }
}

resource "google_artifact_registry_repository" "runtime" {
  location      = var.region
  repository_id = "restricted-synthetic-runtime"
  format        = "DOCKER"
  labels        = local.labels
}

resource "google_compute_network" "restricted" {
  name                            = "restricted-synthetic-vpc"
  auto_create_subnetworks         = false
  delete_default_routes_on_create = true
}
resource "google_compute_subnetwork" "restricted" {
  name                     = "restricted-synthetic-subnet"
  region                   = var.region
  network                  = google_compute_network.restricted.id
  ip_cidr_range            = "10.77.0.0/24"
  private_ip_google_access = true
}
resource "google_compute_global_address" "private_services" {
  name          = "restricted-synthetic-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.restricted.id
}
resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.restricted.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}
resource "google_vpc_access_connector" "conversation" {
  name          = "rr-conv-eg"
  region        = var.region
  network       = google_compute_network.restricted.name
  ip_cidr_range = "10.77.1.0/28"
}
resource "google_vpc_access_connector" "gateway" {
  name          = "rr-gw-eg"
  region        = var.region
  network       = google_compute_network.restricted.name
  ip_cidr_range = "10.77.2.0/28"
}
resource "google_vpc_access_connector" "runner" {
  name          = "rr-run-eg"
  region        = var.region
  network       = google_compute_network.restricted.name
  ip_cidr_range = "10.77.3.0/28"
}
resource "google_vpc_access_connector" "migration" {
  name          = "rr-mig-eg"
  region        = var.region
  network       = google_compute_network.restricted.name
  ip_cidr_range = "10.77.4.0/28"
}

locals {
  connector_tags = [
    "vpc-connector-${var.region}-${google_vpc_access_connector.conversation.name}",
    "vpc-connector-${var.region}-${google_vpc_access_connector.gateway.name}",
    "vpc-connector-${var.region}-${google_vpc_access_connector.runner.name}",
    "vpc-connector-${var.region}-${google_vpc_access_connector.migration.name}",
  ]
}

# The official restricted.googleapis.com baseline permits only the restricted
# VIP before deny-all. FQDN/SNI verification remains an external HOLD gate.
resource "google_dns_managed_zone" "googleapis" {
  name       = "restricted-synthetic-googleapis"
  dns_name   = "googleapis.com."
  visibility = "private"
  private_visibility_config {
    networks {
      network_url = google_compute_network.restricted.id
    }
  }
}
resource "google_dns_record_set" "restricted_googleapis" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}
resource "google_dns_record_set" "all_googleapis" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}
# Internal Cloud Run URLs remain on run.app even when default routes are
# removed. Resolve their wildcard only to the same restricted VIP; the
# firewall's exact TCP/443 allow remains the sole network path.
resource "google_dns_managed_zone" "runapp" {
  name       = "restricted-synthetic-runapp"
  dns_name   = "run.app."
  visibility = "private"
  private_visibility_config {
    networks {
      network_url = google_compute_network.restricted.id
    }
  }
}
resource "google_dns_record_set" "all_runapp" {
  managed_zone = google_dns_managed_zone.runapp.name
  name         = "*.run.app."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}
resource "google_compute_route" "restricted_google_apis" {
  name             = "restricted-synthetic-google-apis"
  network          = google_compute_network.restricted.id
  dest_range       = "199.36.153.4/30"
  next_hop_gateway = "default-internet-gateway"
}
resource "google_compute_firewall" "allow_restricted_google_apis" {
  name               = "restricted-synthetic-allow-google-apis"
  network            = google_compute_network.restricted.name
  direction          = "EGRESS"
  priority           = 1000
  target_tags        = local.connector_tags
  destination_ranges = ["199.36.153.4/30"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
resource "google_compute_firewall" "allow_private_sql" {
  name               = "restricted-synthetic-allow-private-sql"
  network            = google_compute_network.restricted.name
  direction          = "EGRESS"
  priority           = 1010
  target_tags        = local.connector_tags
  destination_ranges = ["${google_compute_global_address.private_services.address}/${google_compute_global_address.private_services.prefix_length}"]
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}
resource "google_compute_firewall" "deny_other_egress" {
  name               = "restricted-synthetic-deny-other-egress"
  network            = google_compute_network.restricted.name
  direction          = "EGRESS"
  priority           = 65534
  target_tags        = local.connector_tags
  destination_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
}

resource "google_service_account" "runner" {
  account_id   = "restricted-synthetic-runner"
  display_name = "Synthetic-only runner"
}
resource "google_service_account" "conversation" {
  account_id   = "restricted-synth-conversation"
  display_name = "Restricted synthetic conversation"
}
resource "google_service_account" "gateway" {
  account_id   = "restricted-synthetic-gateway"
  display_name = "Restricted synthetic gateway"
}
resource "google_service_account" "migration" {
  account_id   = "restricted-synthetic-migration"
  display_name = "Restricted synthetic migration"
}

resource "google_kms_key_ring" "restricted" {
  name     = "restricted-synthetic"
  location = var.region
}
resource "google_kms_crypto_key" "content_wrap" {
  name                          = "content-wrap"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "ENCRYPT_DECRYPT"
  skip_initial_version_creation = true
  version_template { algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION" }
}
resource "google_kms_crypto_key" "service_mac_active" {
  name                          = "service-idempotency-active"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "MAC"
  skip_initial_version_creation = true
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "service_mac_retired" {
  name                          = "service-idempotency-retired"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "MAC"
  skip_initial_version_creation = true
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "gateway_mac_active" {
  name                          = "gateway-envelope-active"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "MAC"
  skip_initial_version_creation = true
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "gateway_mac_retired" {
  name                          = "gateway-envelope-retired"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "MAC"
  skip_initial_version_creation = true
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "policy_signing" {
  name                          = "policy-ed25519"
  key_ring                      = google_kms_key_ring.restricted.id
  purpose                       = "ASYMMETRIC_SIGN"
  skip_initial_version_creation = true
  version_template { algorithm = "EC_SIGN_ED25519" }
}
resource "google_kms_crypto_key_version" "content_wrap_active" {
  crypto_key = google_kms_crypto_key.content_wrap.id
}
resource "google_kms_crypto_key_version" "service_mac_active" {
  crypto_key = google_kms_crypto_key.service_mac_active.id
}
resource "google_kms_crypto_key_version" "service_mac_retired" {
  crypto_key = google_kms_crypto_key.service_mac_retired.id
}
resource "google_kms_crypto_key_version" "gateway_mac_active" {
  crypto_key = google_kms_crypto_key.gateway_mac_active.id
}
resource "google_kms_crypto_key_version" "gateway_mac_retired" {
  crypto_key = google_kms_crypto_key.gateway_mac_retired.id
}
resource "google_kms_crypto_key_version" "policy_signing_active" {
  crypto_key = google_kms_crypto_key.policy_signing.id
}
resource "google_project_iam_custom_role" "mac_verify_only" {
  role_id     = "restrictedSyntheticMacVerify"
  title       = "Restricted synthetic KMS MAC verify only"
  permissions = ["cloudkms.cryptoKeyVersions.useToVerify"]
}

resource "google_sql_database_instance" "restricted" {
  name                = "restricted-synthetic-postgres"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = false
  depends_on          = [google_service_networking_connection.private_services]
  settings {
    tier              = "db-custom-1-3840"
    availability_type = "ZONAL"
    user_labels       = local.labels
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.restricted.id
      enable_private_path_for_google_cloud_services = true
    }
  }
}
resource "google_sql_database" "runtime" {
  name     = "restricted_runtime"
  instance = google_sql_database_instance.restricted.name
}
locals {
  # Cloud SQL IAM database usernames omit this service-account domain suffix.
  # OIDC and Google IAM bindings deliberately retain the full email identity.
  conversation_db_user = trimsuffix(google_service_account.conversation.email, ".gserviceaccount.com")
  gateway_db_user      = trimsuffix(google_service_account.gateway.email, ".gserviceaccount.com")
  migration_db_user    = trimsuffix(google_service_account.migration.email, ".gserviceaccount.com")
}
resource "google_sql_user" "conversation" {
  name     = local.conversation_db_user
  instance = google_sql_database_instance.restricted.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
resource "google_sql_user" "gateway" {
  name     = local.gateway_db_user
  instance = google_sql_database_instance.restricted.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
resource "google_sql_user" "migration" {
  name     = local.migration_db_user
  instance = google_sql_database_instance.restricted.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_project_iam_member" "gateway_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_project_iam_member" "conversation_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_project_iam_member" "gateway_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_project_iam_member" "migration_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.migration.email}"
}
resource "google_project_iam_member" "conversation_sql_iam" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_project_iam_member" "gateway_sql_iam" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_project_iam_member" "migration_sql_iam" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.migration.email}"
}

resource "google_kms_crypto_key_iam_member" "conversation_wrap" {
  crypto_key_id = google_kms_crypto_key.content_wrap.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_kms_crypto_key_iam_member" "conversation_mac_active" {
  crypto_key_id = google_kms_crypto_key.service_mac_active.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_kms_crypto_key_iam_member" "conversation_mac_retired" {
  crypto_key_id = google_kms_crypto_key.service_mac_retired.id
  role          = google_project_iam_custom_role.mac_verify_only.name
  member        = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_kms_crypto_key_iam_member" "gateway_mac_active" {
  crypto_key_id = google_kms_crypto_key.gateway_mac_active.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_kms_crypto_key_iam_member" "gateway_mac_retired" {
  crypto_key_id = google_kms_crypto_key.gateway_mac_retired.id
  role          = google_project_iam_custom_role.mac_verify_only.name
  member        = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_secret_manager_secret_iam_member" "migration_bootstrap" {
  project   = var.project_id
  secret_id = var.migration_bootstrap_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.migration.email}"
}
