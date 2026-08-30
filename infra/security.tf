variable "network_self_link" { type = string }
variable "sql_tier" {
  type    = string
  default = "db-custom-2-7680"
}
resource "google_kms_key_ring" "restricted" {
  name     = "restricted-phi"
  location = var.region
}
resource "google_kms_crypto_key" "content_wrap" {
  name     = "content-wrap"
  key_ring = google_kms_key_ring.restricted.id
  purpose  = "ENCRYPT_DECRYPT"
}
resource "google_kms_crypto_key" "service_mac_active" {
  name     = "service-idempotency-active"
  key_ring = google_kms_key_ring.restricted.id
  purpose  = "MAC"
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "service_mac_retired" {
  name     = "service-idempotency-retired"
  key_ring = google_kms_key_ring.restricted.id
  purpose  = "MAC"
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "gateway_mac_active" {
  name     = "gateway-envelope-active"
  key_ring = google_kms_key_ring.restricted.id
  purpose  = "MAC"
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_kms_crypto_key" "gateway_mac_retired" {
  name     = "gateway-envelope-retired"
  key_ring = google_kms_key_ring.restricted.id
  purpose  = "MAC"
  version_template { algorithm = "HMAC_SHA256" }
}
resource "google_project_iam_custom_role" "mac_verify_only" {
  role_id     = "restrictedMacVerifyOnly"
  title       = "Restricted KMS MAC verify only"
  permissions = ["cloudkms.cryptoKeyVersions.useToVerify"]
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
resource "google_sql_database_instance" "restricted" {
  name                = "restricted-phi-postgres"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true
  settings {
    tier              = var.sql_tier
    availability_type = "REGIONAL"
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.network_self_link
      enable_private_path_for_google_cloud_services = true
    }
  }
}
resource "google_sql_database" "runtime" {
  name     = "restricted_runtime"
  instance = google_sql_database_instance.restricted.name
}
resource "google_vpc_access_connector" "restricted" {
  name          = "restricted-phi-egress"
  region        = var.region
  network       = var.network_self_link
  ip_cidr_range = "10.8.0.0/28"
}
