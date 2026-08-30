# Synthetic implementation closure receipt

This receipt records synthetic-only evidence at one immutable repository head;
it is not PHI deployment authorization.

- repository base: `1128fddfc83abd5ecba5989583243693a98e9750`
- contract head: `5961788e08c9414e78f3dc26dc6d7b53ec56cca2`
- code/test head: `09cca80a3dd0dda20e5484a67b1693939ef0fb5b`
- successful runtime head range: `759760` through `09cca80` (Dockerfiles, `src/`, `pyproject.toml`, `policy/`, `infra/`, and `migrations`)
- local immutable conversation image ID (not a registry-pushed deployment digest): `sha256:0bf4d5c5b5bf640e45157a1e4d0b66cb2dcc9f11378ea6f17f85479adcd78301`, UID `10001`
- local immutable gateway image ID (not a registry-pushed deployment digest): `sha256:62acf9d31fa4716267e67281674cd8a55acd31cc878f679453b6a33890da4361`, UID `10002`
- policy digest/epoch observed by the final synthetic smoke: `faf98336bfe94b460a903662cb841e991682788ade1ad3a244348f22bb907687` / `synthetic-smoke-2026-08-30-final-r2`; no signed deployment bundle or registry/deployment claim is asserted
- system instruction digest: `afcf847cd029409e53bbcb07e92b9d407876e3190e9cf951844829cb34599c1b`
- response profile: `restricted-vertex-text-response.v1`
- migration: `001_restricted_runtime.sql`

## Executed gates

- Root-independent full run (WSL Docker, real ephemeral PostgreSQL at
  localhost `127.0.0.1:57288`, credentials omitted): **127 passed, 0 skipped,
  3 warnings in 27.45s**. This includes the real HTTP composition test and the
  AC16 raw response fixture wave.
- PostgreSQL: **GREEN** against the real ephemeral localhost instance at
  `127.0.0.1:57288`; migrations applied by the integration fixtures.
- Image isolation: **GREEN**. Imported-package and tar-readable `docker save`
  layer scans found zero forbidden lower-layer/site-packages modules; the
  conversation image excludes Vertex and opposite-service roots, and the
  gateway image excludes conversation production roots. Synthetic mutations
  for a site-packages lower-layer leak and a zero-readable-layer archive were
  exercised.
- Container runtime identities: conversation runs as UID `10001`; gateway runs
  as UID `10002`.
- Terraform: **GREEN** — `terraform -chdir=infra init -backend=false -input=false`
  followed by `terraform -chdir=infra validate` reported a valid configuration.
- Synthetic no-PHI diagnostics/smoke: six total requests; each product client
  was limited to one dispatch with no retry. Final real-provider smoke is
  recorded in `restricted-vertex-smoke-2026-08-30.md`.
- Final real-provider synthetic smoke: **GREEN / COMPLETED** with synthetic
  non-PHI input. Future `gcloud` authentication state is irrelevant to this
  receipt.

## External boundary

- PHI authorization: **BLOCKED**; see `PHI_BLOCKERS.md`.
- Registry push, deployed revision, BAA, IAM, egress, and PHI authorization
  remain **BLOCKED**. Local image IDs above are not registry-pushed digests.
- No signed policy artifact, deployment revision, or PHI readiness is asserted
  by this synthetic receipt.
