terraform {
  required_version = ">= 1.7"
  required_providers { google = { source = "hashicorp/google", version = "~> 6.0" } }
}
variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "tenant_id" { type = string }
variable "caller_principal" { type = string }
variable "conversation_image" { type = string }
variable "gateway_image" { type = string }
variable "policy_digest" { type = string }
variable "policy_epoch" { type = string }
provider "google" {
  project = var.project_id
  region  = var.region
}
resource "google_service_account" "conversation" {
  account_id   = "restricted-conversation"
  display_name = "Restricted conversation service"
}
resource "google_service_account" "gateway" {
  account_id   = "restricted-gateway"
  display_name = "Restricted inference gateway"
}
resource "google_project_iam_member" "gateway_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.gateway.email}"
}
resource "google_cloud_run_v2_service" "gateway" {
  name     = "restricted-inference-gateway"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  template {
    service_account = google_service_account.gateway.email
    vpc_access {
      connector = google_vpc_access_connector.restricted.id
      egress    = "ALL_TRAFFIC"
    }
    containers {
      image = var.gateway_image
      env {
        name  = "RESTRICTED_POLICY_DIGEST"
        value = var.policy_digest
      }
      env {
        name  = "RESTRICTED_POLICY_EPOCH"
        value = var.policy_epoch
      }
    }
  }
}
resource "google_cloud_run_v2_service" "conversation" {
  name     = "restricted-conversation"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  template {
    service_account = google_service_account.conversation.email
    vpc_access {
      connector = google_vpc_access_connector.restricted.id
      egress    = "ALL_TRAFFIC"
    }
    containers {
      image = var.conversation_image
      env {
        name  = "RESTRICTED_TENANT_ID"
        value = var.tenant_id
      }
      env {
        name  = "RESTRICTED_CALLER_PRINCIPAL"
        value = var.caller_principal
      }
      env {
        name  = "RESTRICTED_POLICY_DIGEST"
        value = var.policy_digest
      }
      env {
        name  = "RESTRICTED_POLICY_EPOCH"
        value = var.policy_epoch
      }
    }
  }
}
