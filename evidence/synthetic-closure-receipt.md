# Synthetic implementation closure receipt template

- repository base/head: `1128fdd` / `FINAL_HEAD_TO_BE_FILLED_BY_RELEASE_COMMIT`
- conversation/gateway image digests: `UNBUILT`
- policy digest/epoch: `UNSIGNED / UNCONFIGURED`
- system instruction digest: `afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b`
- response profile: `restricted-vertex-text-response.v1`
- migration: `001_restricted_runtime.sql`
- local/static tests: `python -m pytest tests/unit tests/static tests/integration tests/container -q` (recorded below at release)
- PostgreSQL integration: isolated PostgreSQL 18.4 at `127.0.0.1:57288`, migration applied per integration fixture
- synthetic real-provider receipt: contract fixture reference `restricted-vertex-smoke-2026-08-30.md`; no new provider probe dispatched
- PHI authorization: **BLOCKED**; see `PHI_BLOCKERS.md`.
