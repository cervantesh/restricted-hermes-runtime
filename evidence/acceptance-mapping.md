# Executable acceptance mapping — synthetic v0

| Matrix | Executable path | Current class |
|---|---|---|
| AC1 | `tests/static/test_forbidden_imports.py`, `tests/static/test_matrix_local.py::test_ac1_closed_import_graph`, `tests/container/test_runtime_image.py` | local/static and Docker recipe scan green; 2 Docker build/runtime tests skipped because daemon unavailable |
| AC2–3 | `tests/unit/test_contracts.py`, `tests/unit/test_conversation_execution.py` | local |
| AC4–5 | `tests/exact/` deployment receipt | exact-staging blocked |
| AC6 | `tests/integration/test_real_composition.py::test_real_composition_admits_dispatches_commits_reads_once_and_duplicate_is_read_only`, `tests/integration/test_http_composed_path.py::test_real_http_composition_commits_encrypted_readback_and_duplicate_dispatches_once` | PostgreSQL/real HTTP composition green |
| AC7 | `tests/integration/test_runtime_postgres.py::test_different_key_active_turn_and_reset_are_serialized` | PostgreSQL green |
| AC8–9 | `tests/integration/test_runtime_postgres.py::test_reserve_and_not_found_fence_interleave_on_one_durable_guard`, `tests/integration/test_runtime_postgres.py::test_db_time_lease_heartbeat_scanner_and_stale_handler_cas`, `tests/integration/test_fault_matrix.py::test_crash_matrix` | PostgreSQL green |
| AC11–13 | `tests/integration/test_fault_matrix.py::test_crash_matrix`, `tests/integration/test_real_composition.py` | PostgreSQL green |
| AC15 | `tests/integration/test_runtime_wave.py::test_conversation_readiness_requires_matching_gateway_policy_and_no_last_known_good`, `tests/integration/test_runtime_wave.py::test_gateway_policy_rollout_mismatch_creates_no_ledger_reservation_or_provider_dispatch`, `tests/unit/test_gateway_readiness.py::test_ready_requires_exact_live_gateway_pair`, `tests/api/test_readiness_wave.py` | PostgreSQL/unit/API green; epoch, digest, instruction-pair, gateway-down, malformed, and no-last-known-good checks covered |
| AC19 | `tests/integration/test_idempotency_association.py::test_identity_dimensions_reject_replay_before_plaintext_read_or_dispatch` | PostgreSQL green |
| AC20 | `tests/integration/test_content_crypto.py::test_aad_binds_ciphertext_nonce_wrapped_key_direction_and_row_identity`, `tests/integration/test_content_crypto.py::test_nonce_uniqueness_is_enforced_per_turn_key_even_if_entropy_repeats` | PostgreSQL green |
| AC10 | `tests/static/test_matrix_local.py::test_ac10_ac16_no_partial_response_profile`, `tests/api/test_turn_schema.py::test_association_conflict_is_409_and_never_returns_partial_text` | local/API green |
| AC16 | `tests/unit/test_vertex_response_profile.py::test_response_profile_classifies_all_recorded_fixtures`, `tests/unit/test_vertex_response_profile.py::test_response_profile_rejects_non_json_raw_bytes`, `tests/fixtures/vertex/ac16/` | 33 local cases green; raw optional metadata, refusal, truncation, malformed, duplicate, encoding, trailing, multiplicity, non-text, and unknown-field coverage |
| AC14,17–18, exact AC21 | `evidence/PHI_BLOCKERS.md` plus exact collectors | exact-staging blocked |
| AC21 local | `tests/unit/test_fingerprint_rotation.py` | local green |
| SQL separation | `tests/integration/test_sql_privileges.py::test_sql_roles_cannot_read_or_write_the_other_schema` | PostgreSQL green |
| API schema/409 | `tests/api/test_turn_schema.py` | PostgreSQL green |
| AC15 readiness adapter | `tests/api/test_readiness_wave.py`, `tests/unit/test_gateway_readiness.py` | pair/down/malformed/exception response checks green |
| Reconciliation startup/periodic | `tests/integration/test_runtime_wave.py::test_reconciliation_driver_scans_expired_rows_without_inference`, `tests/static/test_production_wiring_wave.py::test_conversation_root_starts_bounded_reconciliation_without_provider_import` | PostgreSQL/static green |
| Lease heartbeat/stale generation | `tests/integration/test_runtime_wave.py::test_slow_provider_requires_multiple_lease_heartbeats`, `tests/integration/test_runtime_wave.py::test_lost_lease_generation_cannot_commit_or_release_provider_output` | PostgreSQL green at recorded head |
| KMS retired-key config | `tests/unit/test_kms_rotation_wave.py`, `tests/unit/test_fingerprint_rotation.py` | config parser, active signing, retired verification, and verify-only behavior green |
| Two-service production wiring | `tests/static/test_production_wiring_wave.py` | static green; exact Cloud Run wiring remains blocked |

The failure-injection, concurrency, and cryptographic association rows are
implemented as PostgreSQL-only test targets. They never downgrade to SQLite or
mocks; an unavailable local database is reported as unavailable infrastructure.

## Execution snapshot

Exact code/test head: `2282e4a4fcc8a71411e9747111a1d70c13137936`.

`RESTRICTED_RUNTIME_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:57288/restricted_runtime_test python -m pytest tests/unit tests/static tests/integration tests/container tests/api -q` — **118 passed, 2 skipped** (both Docker daemon gates), 3 warnings. The run includes the real HTTP composition test
`tests/integration/test_http_composed_path.py::test_real_http_composition_commits_encrypted_readback_and_duplicate_dispatches_once`.

The two skipped tests are the image build/runtime proof only; the Docker recipe
scan itself ran. PostgreSQL-backed tests ran against the isolated test database.
