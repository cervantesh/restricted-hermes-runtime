locals {
  sql_socket = "/cloudsql/${google_sql_database_instance.restricted.connection_name}"
  gateway_runtime_env = {
    RESTRICTED_POLICY_PATH = "/app/policy/generated/policy.json"
    RESTRICTED_POLICY_SIGNATURE_PATH = "/app/policy/generated/policy.sig"
    RESTRICTED_POLICY_PUBLIC_KEY_B64 = var.policy_public_key_b64
    RESTRICTED_POLICY_EPOCH = var.policy_epoch
    RESTRICTED_POLICY_DIGEST = var.policy_digest
    RESTRICTED_GATEWAY_AUDIENCE = local.gateway_audience
    RESTRICTED_GATEWAY_MAC_KEY_RESOURCE = google_kms_crypto_key.gateway_mac_active.id
    RESTRICTED_GATEWAY_MAC_KEY_VERSION = "${google_kms_crypto_key.gateway_mac_active.id}/cryptoKeyVersions/1"
    RESTRICTED_GATEWAY_RETIRED_MAC_KEYS_JSON = jsonencode(var.retired_gateway_mac_versions)
    DATABASE_URL = "host=${local.sql_socket} dbname=${google_sql_database.runtime.name} user=${google_service_account.gateway.email}"
  }
  conversation_runtime_env = {
    RESTRICTED_POLICY_PATH = "/app/policy/generated/policy.json"
    RESTRICTED_POLICY_SIGNATURE_PATH = "/app/policy/generated/policy.sig"
    RESTRICTED_POLICY_PUBLIC_KEY_B64 = var.policy_public_key_b64
    RESTRICTED_POLICY_EPOCH = var.policy_epoch
    RESTRICTED_POLICY_DIGEST = var.policy_digest
    RESTRICTED_TENANT_ID = var.tenant_id
    RESTRICTED_RUNNER_AUDIENCE = local.runner_audience
    RESTRICTED_GATEWAY_URL = google_cloud_run_v2_service.gateway.uri
    RESTRICTED_GATEWAY_AUDIENCE = local.gateway_audience
    RESTRICTED_CONTENT_WRAP_KEY = google_kms_crypto_key.content_wrap.id
    RESTRICTED_SERVICE_MAC_KEY_RESOURCE = google_kms_crypto_key.service_mac_active.id
    RESTRICTED_SERVICE_MAC_KEY_VERSION = "${google_kms_crypto_key.service_mac_active.id}/cryptoKeyVersions/1"
    RESTRICTED_SERVICE_RETIRED_MAC_KEYS_JSON = jsonencode(var.retired_service_mac_versions)
    DATABASE_URL = "host=${local.sql_socket} dbname=${google_sql_database.runtime.name} user=${google_service_account.conversation.email}"
  }
}

resource "google_cloud_run_v2_service" "gateway" {
  name = "restricted-synthetic-gateway"
  location = var.region
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  custom_audiences = [local.gateway_audience]
  template {
    service_account = google_service_account.gateway.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      connector = google_vpc_access_connector.restricted.id
      egress = "ALL_TRAFFIC"
    }
    volumes {
      name = "cloudsql"
      empty_dir {}
    }
    containers {
      image = var.gateway_image
      volume_mounts {
        name = "cloudsql"
        mount_path = "/cloudsql"
      }
      dynamic "env" {
        for_each = local.gateway_runtime_env
        content {
          name = env.key
          value = env.value
        }
      }
    }
    containers {
      image = var.cloud_sql_proxy_image
      args = ["--auto-iam-authn", "--unix-socket=/cloudsql", google_sql_database_instance.restricted.connection_name]
      volume_mounts {
        name = "cloudsql"
        mount_path = "/cloudsql"
      }
    }
  }
}

resource "google_cloud_run_v2_service" "conversation" {
  name = "restricted-synthetic-conversation"
  location = var.region
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  custom_audiences = [local.runner_audience]
  template {
    service_account = google_service_account.conversation.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      connector = google_vpc_access_connector.restricted.id
      egress = "ALL_TRAFFIC"
    }
    volumes {
      name = "cloudsql"
      empty_dir {}
    }
    containers {
      image = var.conversation_image
      volume_mounts {
        name = "cloudsql"
        mount_path = "/cloudsql"
      }
      dynamic "env" {
        for_each = local.conversation_runtime_env
        content {
          name = env.key
          value = env.value
        }
      }
    }
    containers {
      image = var.cloud_sql_proxy_image
      args = ["--auto-iam-authn", "--unix-socket=/cloudsql", google_sql_database_instance.restricted.connection_name]
      volume_mounts {
        name = "cloudsql"
        mount_path = "/cloudsql"
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "runner_to_conversation" {
  location = var.region
  service = google_cloud_run_v2_service.conversation.name
  role = "roles/run.invoker"
  member = "serviceAccount:${google_service_account.runner.email}"
}
resource "google_cloud_run_service_iam_member" "conversation_to_gateway" {
  location = var.region
  service = google_cloud_run_v2_service.gateway.name
  role = "roles/run.invoker"
  member = "serviceAccount:${google_service_account.conversation.email}"
}

# Non-product jobs are wired to digest-pinned images by the release pipeline.
resource "google_cloud_run_v2_job" "runner" {
  name = "restricted-synthetic-runner"
  location = var.region
  template {
    template {
      service_account = google_service_account.runner.email
      max_retries = 0
      containers { image = var.runner_image }
    }
  }
}
resource "google_cloud_run_v2_job" "migration" {
  name = "restricted-synthetic-migration"
  location = var.region
  template {
    template {
      service_account = google_service_account.migration.email
      max_retries = 0
      containers { image = var.migration_image }
    }
  }
}
