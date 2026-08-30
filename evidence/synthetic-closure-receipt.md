# Synthetic implementation closure receipt

This receipt records synthetic-only evidence at one immutable repository head;
it is not PHI deployment authorization.

- repository base: `1128fddfc83abd5ecba5989583243693a98e9756`
- code/test head: `2282e4a4fcc8a71411e9747111a1d70c13137936`
- conversation/gateway image digests: **PENDING** — Docker daemon was unavailable; no image digest is claimed
- policy digest/epoch: no signed deployment bundle is asserted; `policy/policy.template.json` remains a template and no policy digest is invented
- system instruction digest: `afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b`
- response profile: `restricted-vertex-text-response.v1`
- migration: `001_restricted_runtime.sql`

## Executed gates

- Local/static/integration/API/container command:
  `RESTRICTED_RUNTIME_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:57288/restricted_runtime_test python -m pytest tests/unit tests/static tests/integration tests/container tests/api -q`
  — **118 passed, 2 skipped**, 3 warnings. The two skips are the Docker image
  build/runtime tests; the Docker recipe scan passed. This includes the real
  HTTP composition test and the AC16 raw response fixture wave.
- PostgreSQL: **GREEN** against the isolated database at
  `127.0.0.1:57288/restricted_runtime_test`; migrations applied by the
  integration fixtures.
- Terraform: **GREEN** — `terraform -chdir=infra init -backend=false -input=false`
  followed by `terraform -chdir=infra validate` reported a valid configuration.
- synthetic real-provider receipt: existing sanitized fixture reference
  `restricted-vertex-smoke-2026-08-30.md`; no provider dispatch is claimed by
  this local receipt.
- provider smoke: **PENDING** — requires `gcloud` reauthentication; no result
  is inferred from the checked-in fixture.

## External boundary

- PHI authorization: **BLOCKED**; see `PHI_BLOCKERS.md`.
- The missing image digests and provider smoke are the only receipt items
  marked **PENDING**. Unsupplied signed policy/deployment values are explicitly
  not asserted here.
