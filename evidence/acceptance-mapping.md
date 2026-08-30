# Executable acceptance mapping — synthetic v0

| Matrix | Executable path | Current class |
|---|---|---|
| AC1 | `tests/static/test_forbidden_imports.py`, `tests/static/test_matrix_local.py::test_ac1_closed_import_graph`, `tests/container/test_runtime_image.py` | local/image recipe; image build pending daemon |
| AC2–3 | `tests/unit/test_contracts.py`, `tests/unit/test_conversation_execution.py` | local |
| AC4–5 | `tests/exact/` deployment receipt | exact-staging blocked |
| AC6 | `tests/integration/test_real_composition.py::test_real_composition_admits_dispatches_commits_reads_once_and_duplicate_is_read_only` | PostgreSQL green |
| AC7 | `tests/integration/test_runtime_postgres.py::test_different_key_active_turn_and_reset_are_serialized` | PostgreSQL green |
| AC8–9 | `tests/integration/test_runtime_postgres.py::test_reserve_and_not_found_fence_interleave_on_one_durable_guard`, `tests/integration/test_runtime_postgres.py::test_db_time_lease_heartbeat_scanner_and_stale_handler_cas`, `tests/integration/test_fault_matrix.py::test_crash_matrix` | PostgreSQL green |
| AC11–13 | `tests/integration/test_fault_matrix.py::test_crash_matrix`, `tests/integration/test_real_composition.py` | PostgreSQL green |
| AC15 | `tests/integration/test_runtime_postgres.py` | PostgreSQL partial; policy readiness mutation coverage remains pending |
| AC19 | `tests/integration/test_idempotency_association.py::test_identity_dimensions_reject_replay_before_plaintext_read_or_dispatch` | PostgreSQL green |
| AC20 | `tests/integration/test_content_crypto.py::test_aad_binds_ciphertext_nonce_wrapped_key_direction_and_row_identity`, `tests/integration/test_content_crypto.py::test_nonce_uniqueness_is_enforced_per_turn_key_even_if_entropy_repeats` | PostgreSQL green |
| AC10,16 | `tests/unit/test_vertex_response_profile.py`, `tests/static/test_matrix_local.py::test_ac10_ac16_no_partial_response_profile` | local |
| AC14,17–18, exact AC21 | `evidence/PHI_BLOCKERS.md` plus exact collectors | exact-staging blocked |
| AC21 local | `tests/unit/test_fingerprint_rotation.py` | local green |
| SQL separation | `tests/integration/test_sql_privileges.py::test_sql_roles_cannot_read_or_write_the_other_schema` | PostgreSQL green |
| API schema/409 | `tests/api/test_turn_schema.py` | PostgreSQL green |

The failure-injection, concurrency, and cryptographic association rows are
implemented as PostgreSQL-only test targets. They never downgrade to SQLite or
mocks; an unavailable local database is reported as unavailable infrastructure.
