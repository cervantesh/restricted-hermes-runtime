terraform {
  required_version = ">= 1.7"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

variable "project_id" {
  type = string
  default = "health-record-hub-dev"
}
variable "region" {
  type = string
  default = "us-central1"
}
variable "tenant_id" { type = string }
variable "policy_epoch" { type = string }
variable "policy_digest" { type = string }
variable "policy_public_key_b64" { type = string }
variable "ttl" { type = string }
variable "conversation_image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.conversation_image))
    error_message = "conversation image must be pinned by digest"
  }
}
variable "gateway_image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.gateway_image))
    error_message = "gateway image must be pinned by digest"
  }
}
variable "runner_image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.runner_image))
    error_message = "runner image must be pinned by digest"
  }
}
variable "migration_image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.migration_image))
    error_message = "migration image must be pinned by digest"
  }
}
variable "cloud_sql_proxy_image" {
  type = string
  validation {
    condition = can(regex("@sha256:[0-9a-f]{64}$", var.cloud_sql_proxy_image))
    error_message = "proxy image must be pinned by digest"
  }
}
variable "retired_service_mac_versions" {
  type = map(string)
  default = {}
}
variable "retired_gateway_mac_versions" {
  type = map(string)
  default = {}
}

provider "google" {
  project = var.project_id
  region = var.region
}

locals {
  labels = { restricted_runtime = "synthetic-only", ttl = var.ttl, phi = "forbidden" }
  runner_audience = "https://restricted-synthetic-conversation-${var.project_id}.run.app"
  gateway_audience = "https://restricted-synthetic-gateway-${var.project_id}.run.app"
}

resource "google_artifact_registry_repository" "runtime" {
  location = var.region
  repository_id = "restricted-synthetic-runtime"
  format = "DOCKER"
  labels = local.labels
}

resource "google_compute_network" "restricted" {
  name = "restricted-synthetic-vpc"
  auto_create_subnetworks = false
}
resource "google_compute_subnetwork" "restricted" {
  name = "restricted-synthetic-subnet"
  region = var.region
  network = google_compute_network.restricted.id
  ip_cidr_range = "10.77.0.0/24"
  private_ip_google_access = true
}
resource "google_compute_global_address" "private_services" {
  name = "restricted-synthetic-psa"
  purpose = "VPC_PEERING"
  address_type = "INTERNAL"
  prefix_length = 16
  network = google_compute_network.restricted.id
}
resource "google_service_networking_connection" "private_services" {
  network = google_compute_network.restricted.id
  service = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}
resource "google_vpc_access_connector" "restricted" {
  name = "restricted-synthetic-egress"
  region = var.region
  network = google_compute_network.restricted.name
  ip_cidr_range = "10.77.1.0/28"
}

resource "google_service_account" "runner" {
  account_id = "restricted-synthetic-runner"
  display_name = "Synthetic-only runner"
}
resource "google_service_account" "conversation" {
  account_id = "restricted-synth-conversation"
  display_name = "Restricted synthetic conversation"
}
resource "google_service_account" "gateway" {
  account_id = "restricted-synthetic-gateway"
  display_name = "Restricted synthetic gateway"
}
resource "google_service_account" "migration" {
  account_id = "restricted-synthetic-migration"
  display_name = "Restricted synthetic migration"
}

resource "google_kms_key_ring" "restricted" {
  name = "restricted-synthetic"
  location = var.region
}
resource "google_kms_crypto_key" "content_wrap" {
  name = "content-wrap"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "ENCRYPT_DECRYPT"
}
resource "google_kms_crypto_key" "service_mac_active" {
  name = "service-idempotency-active"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "MAC"
}
resource "google_kms_crypto_key" "service_mac_retired" {
  name = "service-idempotency-retired"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "MAC"
}
resource "google_kms_crypto_key" "gateway_mac_active" {
  name = "gateway-envelope-active"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "MAC"
}
resource "google_kms_crypto_key" "gateway_mac_retired" {
  name = "gateway-envelope-retired"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "MAC"
}
resource "google_kms_crypto_key" "policy_signing" {
  name = "policy-ed25519"
  key_ring = google_kms_key_ring.restricted.id
  purpose = "ASYMMETRIC_SIGN"
}

resource "google_sql_database_instance" "restricted" {
  name = "restricted-synthetic-postgres"
  region = var.region
  database_version = "POSTGRES_16"
  deletion_protection = false
  depends_on = [google_service_networking_connection.private_services]
  settings {
    tier = "db-custom-1-3840"
    availability_type = "ZONAL"
    user_labels = local.labels
    database_flags {
      name = "cloudsql.iam_authentication"
      value = "on"
    }
    ip_configuration {
      ipv4_enabled = false
      private_network = google_compute_network.restricted.id
      enable_private_path_for_google_cloud_services = true
    }
  }
}
resource "google_sql_database" "runtime" {
  name = "restricted_runtime"
  instance = google_sql_database_instance.restricted.name
}
resource "google_sql_user" "conversation" {
  name = google_service_account.conversation.email
  instance = google_sql_database_instance.restricted.name
  type = "CLOUD_IAM_SERVICE_ACCOUNT"
}
resource "google_sql_user" "gateway" {
  name = google_service_account.gateway.email
  instance = google_sql_database_instance.restricted.name
  type = "CLOUD_IAM_SERVICE_ACCOUNT"
}
resource "google_sql_user" "migration" {
  name = google_service_account.migration.email
  instance = google_sql_database_instance.restricted.name
  type = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_project_iam_member" "gateway_vertex" {
  project = var.project_id
  role = "roles/aiplatform.user"
  member = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_project_iam_member" "conversation_sql" {
  project = var.project_id
  role = "roles/cloudsql.client"
  member = "serviceAccount:${google_service_account.conversation.email}"
}
resource "google_project_iam_member" "gateway_sql" {
  project = var.project_id
  role = "roles/cloudsql.client"
  member = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_project_iam_member" "migration_sql" {
  project = var.project_id
  role = "roles/cloudsql.client"
  member = "serviceAccount:${google_service_account.migration.email}"
}
resource "google_secret_manager_secret" "migration_admin" {
  secret_id = "restricted-synthetic-migration-admin"
  replication {
    auto {}
  }
}
