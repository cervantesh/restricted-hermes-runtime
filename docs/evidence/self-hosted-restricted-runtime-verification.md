# Self-hosted restricted runtime verification

**Code revision:** `d7afa834db4fce5fa5c708d64528056e7523aff2`  
**Date:** 2026-08-31  
**Data used:** synthetic, explicitly non-PHI

## Scope proved

This evidence covers the product-controlled `local-uds` slice: closed policy
and authorization contracts, local key adapters, UDS-only inference dispatch,
durable PostgreSQL behavior, image import closure, role socket ACLs, and the
three-socket request path. It does not assert HIPAA compliance, PHI
authorization, model attestation, or deployment conformance.

## Executed gates

| Gate | Environment | Result |
|---|---|---|
| Unit, API schema, and static guards | Windows / Python 3.11 | `151 passed, 12 skipped` |
| POSIX key, AF_UNIX, signal, launcher, authority, and lifecycle tests | WSL Ubuntu 24.04 / Python 3.12 / root | `29 passed` |
| Real PostgreSQL integration and API suites | Windows / ephemeral PostgreSQL 16 | `52 passed, 2 POSIX-only skipped` |
| Real three-socket composition and ACL matrix | WSL Ubuntu 24.04 / ephemeral PostgreSQL 16 | `2 passed` |
| All role-image builds and import-closure checks | Docker Desktop 29.4.3 | `7 passed` |
| Final local-image identity/import checks | Docker Desktop 29.4.3 | `2 passed, 5 deselected` |
| Bytecode and patch hygiene | Windows | `compileall` PASS; `git diff --check` PASS |

The PostgreSQL container was created only for this proof and removed after the
gates completed. No ambient `DATABASE_URL` was used: the test DSN named the
isolated container explicitly.

## Commands

```text
python -m pytest tests/unit tests/api tests/static -q

wsl -d Ubuntu-24.04 -u root -- bash -lc \
  'cd /mnt/c/dev/restricted-hermes-runtime && \
   env -u DATABASE_URL -u RESTRICTED_RUNTIME_TEST_DATABASE_URL \
   /tmp/restricted-hermes-verify/bin/python -m pytest \
   tests/unit/test_local_crypto_posix.py \
   tests/unit/test_local_uds_profile.py \
   tests/unit/test_migration_supervisor_posix.py \
   tests/unit/test_uds_entrypoint.py -q'

RESTRICTED_RUNTIME_TEST_DATABASE_URL=<isolated-postgresql-16-dsn> \
python -m pytest tests/integration tests/api -q

RESTRICTED_RUNTIME_TEST_DATABASE_URL=<isolated-postgresql-16-dsn> \
wsl -d Ubuntu-24.04 -u root -- bash -lc \
  '/tmp/restricted-hermes-verify/bin/python -m pytest \
   tests/integration/test_local_three_socket_composition.py -q'

python -m pytest tests/container/test_runtime_image.py -q
python -m compileall -q src collectors runner tools
git diff --check
```

Secrets and ephemeral credentials are intentionally omitted from this record.

## Adversarial findings and adjudication

| Finding | Adjudication at code revision |
|---|---|
| Uvicorn changed UDS permissions to `0666` | Closed: the launcher prebinds, applies `0660`, and passes an existing FD. An unrelated UID is denied. |
| Distinct service users could not traverse the intended sockets | Closed: fixed UID/GID roles, `root:20000` mode `1770`, role-specific socket groups, image identity inspection, and POSIX ACL matrix. |
| Local reconciliation ran only when readiness was queried | Closed: bounded startup and 30-second periodic lifespan, gated by operator authority. |
| Conversation image retained gateway/provider capabilities | Closed: conversation storage/contracts were split and prohibited modules are absent and non-importable in the built image. |
| Conversation authorization digest was 129 characters | Closed: a labeled aggregate SHA-256 is exactly 64 lowercase hex. |
| Active and retired keys could be swapped under one signed digest | Closed: purpose, active role, and retired set are distinct digest inputs. |
| Wrapped-key JSON accepted noncanonical encodings | Closed before key selection by byte-canonical JCS comparison. |
| Authority could expire between reservation and dispatch | Narrowed and closed at request boundaries: the gateway checks again immediately before the durable dispatch transition. Continuous trusted time is not claimed. |
| Probe receipt could appear attesting or carry arbitrary source text | Closed by contract and wording: closed revision/result inputs, immutable false external claims, and explicit non-attesting status. |
| PostgreSQL can use TCP despite a broad no-TCP reading | Closed by truthful scope: only inference dispatch is UDS-only; the database endpoint and transport remain operator-authorized deployment inputs. |
| Real Uvicorn responses added headers rejected by the closed parser | Closed: UDS services disable optional `Date` and `Server` headers; a real-Uvicorn framing test and three-socket E2E pass. |

## Residual operator evidence

Before an operator authorizes PHI, the operator still must prove and retain at
least: exact broker image/model artifacts; network namespace and firewall
state; PostgreSQL endpoint, transport, storage, backups, retention and deletion;
host hardening; workforce identity and access review; audit handling; incident
response; trusted time and rollback controls; and any required infrastructure
agreements. The shared socket mount must preserve the numeric ACL contract in
the design. The product neither creates nor endorses those external facts.

The broker in this verification was a synthetic closed-protocol fixture. No
real model, real PHI, production host, or healthcare workflow was exercised.
