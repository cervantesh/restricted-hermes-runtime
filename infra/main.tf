terraform {
  required_version = ">= 1.7"
  required_providers { google = { source = "hashicorp/google", version = "~> 6.0" } }
}

variable "project_id" { type = string }
variable "region" { type = string; default = "us-central1" }
variable "tenant_id" { type = string }
variable "caller_principal" { type = string }
variable "conversation_image" { type = string }
variable "gateway_image" { type = string }
variable "policy_digest" { type = string }
variable "policy_epoch" { type = string }

provider "google" { project = var.project_id; region = var.region }

resource "google_service_account" "conversation" { account_id = "restricted-conversation"; display_name = "Restricted conversation service" }
resource "google_service_account" "gateway" { account_id = "restricted-gateway"; display_name = "Restricted inference gateway" }

# This intentionally grants Vertex User only to the gateway. KMS/SQL resource
# bindings are deployment inputs and must name exact separately-owned keys/DB roles.
resource "google_project_iam_member" "gateway_vertex" { project = var.project_id; role = "roles/aiplatform.user"; member = "serviceAccount:${google_service_account.gateway.email}" }

resource "google_cloud_run_v2_service" "gateway" {
  name = "restricted-inference-gateway"; location = var.region; ingress = "INGRESS_INTERNAL_ONLY"
  template { service_account = google_service_account.gateway.email; containers { image = var.gateway_image; env { name="RESTRICTED_POLICY_DIGEST"; value=var.policy_digest }; env { name="RESTRICTED_POLICY_EPOCH"; value=var.policy_epoch } } }
}
resource "google_cloud_run_v2_service" "conversation" {
  name = "restricted-conversation"; location = var.region; ingress = "INGRESS_INTERNAL_ONLY"
  template { service_account = google_service_account.conversation.email; containers { image = var.conversation_image; env { name="RESTRICTED_TENANT_ID"; value=var.tenant_id }; env { name="RESTRICTED_CALLER_PRINCIPAL"; value=var.caller_principal }; env { name="RESTRICTED_POLICY_DIGEST"; value=var.policy_digest }; env { name="RESTRICTED_POLICY_EPOCH"; value=var.policy_epoch } } }
}

resource "google_cloud_run_v2_service_iam_member" "caller_invokes_conversation" { name=google_cloud_run_v2_service.conversation.name; location=var.region; role="roles/run.invoker"; member="serviceAccount:${var.caller_principal}" }
resource "google_cloud_run_v2_service_iam_member" "conversation_invokes_gateway" { name=google_cloud_run_v2_service.gateway.name; location=var.region; role="roles/run.invoker"; member="serviceAccount:${google_service_account.conversation.email}" }

# Deliberate deployment blocker: no Cloud SQL/KMS, VPC egress, BAA, cache, or
# retention resources are synthesized from defaults. Their exact named inputs
# and proof are mandatory before any apply that processes PHI.
