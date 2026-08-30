# Executable acceptance mapping — synthetic v0

| Matrix | Executable path | Current class |
|---|---|---|
| AC1 | `tests/static/test_forbidden_imports.py`, `tests/static/test_matrix_local.py::test_ac1_closed_import_graph`, `tests/container/test_runtime_image.py` | local/image recipe; image build pending daemon |
| AC2–3 | `tests/unit/test_contracts.py`, `tests/unit/test_conversation_execution.py` | local |
| AC4–5 | `tests/exact/` deployment receipt | exact-staging blocked |
| AC6–9, 11–13, 15, 19–20 | `tests/integration/test_runtime_postgres.py` | PostgreSQL required; unavailable until isolated DB access |
| AC10,16 | `tests/unit/test_vertex_response_profile.py`, `tests/static/test_matrix_local.py::test_ac10_ac16_no_partial_response_profile` | local |
| AC14,17–18, exact AC21 | `evidence/PHI_BLOCKERS.md` plus exact collectors | exact-staging blocked |
| AC21 local | `tests/unit/test_contracts.py::test_identity_binds_all_associations_and_mac_is_fixed_size` | local |

The failure-injection, concurrency, and cryptographic association rows are
implemented as PostgreSQL-only test targets. They never downgrade to SQLite or
mocks; an unavailable local database is reported as unavailable infrastructure.
