# Executable acceptance mapping — synthetic v0

| Matrix | Executable path | Current class |
|---|---|---|
| AC1 | `tests/static/test_forbidden_imports.py`, `tests/static/test_matrix_local.py::test_ac1_closed_import_graph`, `tests/container/test_runtime_image.py` | local/image recipe; image build pending daemon |
| AC2–3 | `tests/unit/test_contracts.py`, `tests/unit/test_conversation_execution.py` | local |
| AC4–5 | `tests/exact/` deployment receipt | exact-staging blocked |
| AC6 | `tests/integration/test_real_composition.py::test_real_composition_admits_dispatches_commits_reads_once_and_duplicate_is_read_only` | PostgreSQL green |
| AC7–9, 11–13, 15, 19–20 | `tests/integration/test_runtime_postgres.py` | PostgreSQL partial; expanded fault/crypto interleavings pending |
| AC10,16 | `tests/unit/test_vertex_response_profile.py`, `tests/static/test_matrix_local.py::test_ac10_ac16_no_partial_response_profile` | local |
| AC14,17–18, exact AC21 | `evidence/PHI_BLOCKERS.md` plus exact collectors | exact-staging blocked |
| AC21 local | `tests/unit/test_fingerprint_rotation.py` | local green |

The failure-injection, concurrency, and cryptographic association rows are
implemented as PostgreSQL-only test targets. They never downgrade to SQLite or
mocks; an unavailable local database is reported as unavailable infrastructure.
