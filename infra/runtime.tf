locals {
  sql_socket = "/cloudsql/${google_sql_database_instance.restricted.connection_name}"
  gateway_runtime_env = {
    RESTRICTED_POLICY_PATH                   = "/app/policy/generated/policy.json"
    RESTRICTED_POLICY_SIGNATURE_PATH         = "/app/policy/generated/policy.sig"
    RESTRICTED_POLICY_PUBLIC_KEY_B64         = var.policy_public_key_b64
    RESTRICTED_POLICY_EPOCH                  = var.policy_epoch
    RESTRICTED_POLICY_DIGEST                 = var.policy_digest
    RESTRICTED_GATEWAY_AUDIENCE              = local.gateway_audience
    RESTRICTED_GATEWAY_MAC_KEY_RESOURCE      = google_kms_crypto_key.gateway_mac_active.id
    RESTRICTED_GATEWAY_MAC_KEY_VERSION       = google_kms_crypto_key_version.gateway_mac_active.id
    RESTRICTED_ADMISSION_ENABLED             = var.admission_enabled ? "true" : "false"
    RESTRICTED_GATEWAY_RETIRED_MAC_KEYS_JSON = jsonencode(var.retired_gateway_mac_versions)
    DATABASE_URL                             = "host=${local.sql_socket} dbname=${google_sql_database.runtime.name} user=${local.gateway_db_user}"
  }
  conversation_runtime_env = {
    RESTRICTED_POLICY_PATH                   = "/app/policy/generated/policy.json"
    RESTRICTED_POLICY_SIGNATURE_PATH         = "/app/policy/generated/policy.sig"
    RESTRICTED_POLICY_PUBLIC_KEY_B64         = var.policy_public_key_b64
    RESTRICTED_POLICY_EPOCH                  = var.policy_epoch
    RESTRICTED_POLICY_DIGEST                 = var.policy_digest
    RESTRICTED_TENANT_ID                     = var.tenant_id
    RESTRICTED_ADMISSION_ENABLED             = var.admission_enabled ? "true" : "false"
    RESTRICTED_RUNNER_AUDIENCE               = local.runner_audience
    RESTRICTED_GATEWAY_URL                   = google_cloud_run_v2_service.gateway.uri
    RESTRICTED_GATEWAY_AUDIENCE              = local.gateway_audience
    RESTRICTED_CONTENT_WRAP_KEY              = google_kms_crypto_key.content_wrap.id
    RESTRICTED_SERVICE_MAC_KEY_RESOURCE      = google_kms_crypto_key.service_mac_active.id
    RESTRICTED_SERVICE_MAC_KEY_VERSION       = google_kms_crypto_key_version.service_mac_active.id
    RESTRICTED_SERVICE_RETIRED_MAC_KEYS_JSON = jsonencode(var.retired_service_mac_versions)
    DATABASE_URL                             = "host=${local.sql_socket} dbname=${google_sql_database.runtime.name} user=${local.conversation_db_user}"
  }
  runner_job_env = {
    RESTRICTED_RUNNER_AUDIENCE   = local.runner_audience
    RESTRICTED_CONVERSATION_URL  = google_cloud_run_v2_service.conversation.uri
    RESTRICTED_SYNTHETIC_PAYLOAD = "HRH_RESTRICTED_RUNTIME_OK"
  }
  migration_job_env = {
    RESTRICTED_MIGRATIONS_DIR            = "/app/migrations"
    RESTRICTED_EXPECTED_MIGRATION_SOCKET = local.sql_socket
    CONVERSATION_IAM_DB_USER             = local.conversation_db_user
    GATEWAY_IAM_DB_USER                  = local.gateway_db_user
  }
}

resource "google_cloud_run_v2_service" "gateway" {
  name                = "restricted-synthetic-gateway"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = false
  custom_audiences    = [local.gateway_audience]
  template {
    service_account = google_service_account.gateway.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      connector = google_vpc_access_connector.gateway.id
      egress    = "ALL_TRAFFIC"
    }
    volumes {
      name = "sql-socket"
      empty_dir {}
    }
    containers {
      name       = "gateway"
      depends_on = ["cloud-sql-proxy"]
      image      = var.gateway_image
      ports { container_port = 8080 }
      volume_mounts {
        name       = "sql-socket"
        mount_path = "/cloudsql"
      }
      dynamic "env" {
        for_each = local.gateway_runtime_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
    containers {
      name  = "cloud-sql-proxy"
      image = var.cloud_sql_proxy_image
      args  = ["--private-ip", "--auto-iam-authn", "--unix-socket=/cloudsql", "--health-check", "--http-address=0.0.0.0", "--http-port=9090", "--quitquitquit", "--exit-zero-on-sigterm", google_sql_database_instance.restricted.connection_name]
      startup_probe {
        http_get {
          path = "/readiness"
          port = 9090
        }
        initial_delay_seconds = 0
        period_seconds        = 5
        timeout_seconds       = 3
        failure_threshold     = 12
      }
      volume_mounts {
        name       = "sql-socket"
        mount_path = "/cloudsql"
      }
    }
  }
}

resource "google_cloud_run_v2_service" "conversation" {
  name                = "restricted-synthetic-conversation"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = false
  custom_audiences    = [local.runner_audience]
  template {
    service_account = google_service_account.conversation.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    vpc_access {
      connector = google_vpc_access_connector.conversation.id
      egress    = "ALL_TRAFFIC"
    }
    volumes {
      name = "sql-socket"
      empty_dir {}
    }
    containers {
      name       = "conversation"
      depends_on = ["cloud-sql-proxy"]
      image      = var.conversation_image
      ports { container_port = 8080 }
      volume_mounts {
        name       = "sql-socket"
        mount_path = "/cloudsql"
      }
      dynamic "env" {
        for_each = local.conversation_runtime_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
    containers {
      name  = "cloud-sql-proxy"
      image = var.cloud_sql_proxy_image
      args  = ["--private-ip", "--auto-iam-authn", "--unix-socket=/cloudsql", "--health-check", "--http-address=0.0.0.0", "--http-port=9090", "--quitquitquit", "--exit-zero-on-sigterm", google_sql_database_instance.restricted.connection_name]
      startup_probe {
        http_get {
          path = "/readiness"
          port = 9090
        }
        initial_delay_seconds = 0
        period_seconds        = 5
        timeout_seconds       = 3
        failure_threshold     = 12
      }
      volume_mounts {
        name       = "sql-socket"
        mount_path = "/cloudsql"
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "runner_to_conversation" {
  location = var.region
  service  = google_cloud_run_v2_service.conversation.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.runner.email}"
}
resource "google_cloud_run_service_iam_member" "conversation_to_gateway" {
  location = var.region
  service  = google_cloud_run_v2_service.gateway.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.conversation.email}"
}

# Non-product jobs are wired to digest-pinned images by the release pipeline.
resource "google_cloud_run_v2_job" "runner" {
  name                = "restricted-synthetic-runner"
  location            = var.region
  deletion_protection = false
  template {
    template {
      service_account = google_service_account.runner.email
      max_retries     = 0
      vpc_access {
        connector = google_vpc_access_connector.runner.id
        egress    = "ALL_TRAFFIC"
      }
      containers {
        name  = "synthetic-runner"
        image = var.runner_image
        dynamic "env" {
          for_each = local.runner_job_env
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }
}
resource "google_cloud_run_v2_job" "migration" {
  name                = "restricted-synthetic-migration"
  location            = var.region
  deletion_protection = false
  depends_on          = [google_secret_manager_secret_iam_member.migration_bootstrap]
  template {
    template {
      service_account = google_service_account.migration.email
      max_retries     = 0
      vpc_access {
        connector = google_vpc_access_connector.migration.id
        egress    = "ALL_TRAFFIC"
      }
      volumes {
        name = "sql-socket"
        empty_dir {}
      }
      containers {
        name       = "migration-runner"
        depends_on = ["cloud-sql-proxy"]
        image      = var.migration_image
        command    = ["python", "-m", "restricted_runtime.migration_runner"]
        volume_mounts {
          name       = "sql-socket"
          mount_path = "/cloudsql"
        }
        dynamic "env" {
          for_each = local.migration_job_env
          content {
            name  = env.key
            value = env.value
          }
        }
        env {
          name = "MIGRATION_ADMIN_DSN"
          value_source {
            secret_key_ref {
              secret  = var.migration_bootstrap_secret_id
              version = "1"
            }
          }
        }
      }
      containers {
        name  = "cloud-sql-proxy"
        image = var.cloud_sql_proxy_image
        # One-shot operator-admin DSN uses PostgreSQL password authentication.
        # Runtime services alone use --auto-iam-authn.
        args = ["--private-ip", "--unix-socket=/cloudsql", "--health-check", "--http-address=0.0.0.0", "--http-port=9090", "--quitquitquit", "--exit-zero-on-sigterm", google_sql_database_instance.restricted.connection_name]
        startup_probe {
          http_get {
            path = "/readiness"
            port = 9090
          }
          initial_delay_seconds = 0
          period_seconds        = 5
          timeout_seconds       = 3
          failure_threshold     = 12
        }
        volume_mounts {
          name       = "sql-socket"
          mount_path = "/cloudsql"
        }
      }
    }
  }
}
