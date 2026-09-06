# Cryptography dependency remediation — 2026-09-06

**Scope:** direct Python dependency and the independently assembled Mattermost
ingress image

**Base:** `bdb6d2b8f42153176318a2ddbba9ed51bd5a32f9`

**Candidate code revision:** `b7c3d4d92a322ddd55756d8962dacf4b75bbe924`

**Host:** Windows; CPython 3.11; Docker Desktop Linux engine 29.4.3

## Observed baseline

A fresh `pip-audit .` on the base resolved the declared
`cryptography>=42,<45` range to `44.0.3` and exited nonzero with eight advisory
records, representing six unique identifiers:

- `GHSA-537c-gmf6-5ccf`
- `PYSEC-2026-35`
- `PYSEC-2026-2141`
- `PYSEC-2026-3552`
- `PYSEC-2026-3553`
- `PYSEC-2026-3554`

The audit data required versions from 46.0.5 through 50.0.0 depending on the
advisory. The old upper bound excluded every complete remediation set.

## Smallest-footprint remediation

Both authoritative declarations now use `cryptography>=50,<51`:

1. `pyproject.toml`, used by normal project installs and runtime images;
2. `Dockerfile.mattermost-ingress`, which installs the project with
   `--no-deps` and therefore owns a second explicit dependency declaration.

Changing only one declaration would leave a reachable consumer on the old
range. No API or cryptographic construction changed.

## Verification

- The amended project resolved `cryptography 50.0.1`; `pip-audit .` exited zero
  with no known vulnerabilities and explicitly reported zero findings for that
  package.
- An isolated `cryptography 50.0.1` import path passed 28 focused AES-GCM,
  HKDF, Ed25519, policy, outbox, and content-crypto contracts; four POSIX or
  PostgreSQL cases were skipped by their existing environment gates.
- The broad unit/static/API/integration command reached `2586 passed,
  70 skipped`. Its two failures were reproduced unchanged on the exact base:
  an ambient, non-isolated `DATABASE_URL` and the pre-existing readiness test
  that expects HTTP 200 while the implementation correctly fails closed with
  HTTP 503. Neither failure intersects dependency resolution or cryptographic
  behavior; the stacked clinical-staging branch fixes both harness defects.
- `Dockerfile.mattermost-ingress` built successfully on the Linux engine,
  installed the CPython ABI3 manylinux wheel for `cryptography 50.0.1`, and
  passed an offline container probe importing every retained ingress module.
  The probe also confirmed the intentionally excluded FastAPI surface remained
  absent.
- `git diff --check`: pass.
- Hosted CI on evidence head `4e4780c95f5dc35ac5ba46b1dbfe64e5c31f9e63`
  completed successfully in
  [run 34068132326](https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34068132326):
  Python 3.11 contracts, Python 3.12 contracts, and the synthetic-only
  Linux/container E2E all passed. The hosted build resolved the amended
  dependency on both Python versions and rebuilt the role-specific images.

## Limits and remaining supply-chain work

- The project still declares compatible ranges rather than a hash-locked
  deployment set. This remediation removes the known-vulnerable direct range;
  it does not make later builds byte-reproducible.
- The local test did not exercise a source build. Cryptography 50 source builds
  require a newer Rust toolchain; declared Linux containers resolve published
  wheels instead.
- This receipt does not triage OS packages in base images and is not a VEX,
  SBOM, signature, provenance attestation, or PHI authorization.
- The hosted checks prove the repository's declared Linux/Python matrix. They
  do not prove unsupported source-build, Intel macOS, or 32-bit Windows paths.

No PHI was used.
