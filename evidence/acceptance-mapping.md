# Executable acceptance mapping — synthetic v0

| Matrix | Executable path | Current class |
|---|---|---|
| AC1 | `tests/static/test_forbidden_imports.py`, `tests/static/test_matrix_local.py::test_ac1_closed_import_graph`, `tests/container/test_runtime_image.py` | image isolation **GREEN**: local immutable conversation image (UID 10001) excludes Vertex/opposite roots; gateway image (UID 10002) excludes conversation roots; imported-package and tar-readable OCI lower-layer/site-packages leak mutations are zero |
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

Exact base: `1128fddfc83abd5ecba5989583243693a98e9750`; contract head:
`5961788e08c9414e78f3dc26dc6d7b53ec56cca2`; code/test head:
`09cca80a3dd0dda20e5484a67b1693939ef0fb5b`.

Root-independent full run using WSL Docker and real ephemeral PostgreSQL at
localhost `127.0.0.1:57288` (credentials omitted): **127 passed, 0 skipped, 3
warnings in 27.45s**. The run includes the real HTTP composition test
`tests/integration/test_http_composed_path.py::test_real_http_composition_commits_encrypted_readback_and_duplicate_dispatches_once`.

Local immutable image IDs (not registry-pushed deployment digests):

- conversation: `sha256:0bf4d5c5b5bf640e45157a1e4d0b66cb2dcc9f11378ea6f17f85479adcd78301`, UID `10001`;
- gateway: `sha256:62acf9d31fa4716267e67281674cd8a55acd31cc878f679453b6a33890da4361`, UID `10002`.

OCI layer scans inspected imported packages and tar-readable `docker save`
blobs; forbidden lower-layer/site-packages modules were zero, and the
conversation/gateway root exclusions held. No registry push or deployed image
digest is claimed.

Final synthetic non-PHI provider smoke: exact sink
`projects/350094423396/locations/us/publishers/google/models/gemini-3.5-flash`
at `aiplatform.us.rep.googleapis.com`, one dispatch, `3219ms`,
`SUCCEEDED`, sanitized text `HRH_RESTRICTED_RUNTIME_OK`, and provider request
ID `8G-UasvzJOC00ekPlfiWkA0`; policy digest/epoch were recorded without
asserting a signed deployment bundle. See `restricted-vertex-smoke-2026-08-30.md`.
