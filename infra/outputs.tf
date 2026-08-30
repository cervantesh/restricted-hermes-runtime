output "artifact_repository" { value = google_artifact_registry_repository.runtime.id }
output "conversation_url" { value = google_cloud_run_v2_service.conversation.uri }
output "gateway_url" { value = google_cloud_run_v2_service.gateway.uri }
output "runner_audience" { value = local.runner_audience }
output "gateway_audience" { value = local.gateway_audience }
output "cloud_sql_connection_name" { value = google_sql_database_instance.restricted.connection_name }
output "policy_signing_key" { value = google_kms_crypto_key.policy_signing.id }
output "staging_destroy_after" { value = var.ttl }
