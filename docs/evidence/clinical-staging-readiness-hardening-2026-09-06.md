# Clinical staging readiness hardening — 2026-09-06

**Scope:** synthetic, explicitly non-PHI verification only

**Candidate code revision:** `7dc0efb46e6d6277d472db98e0de511bd7110ccd`

**Candidate base:** `48c8baab424851aded7bfce1cd9979cfe52ee4c2`

**Evidence revision:** the commit containing this receipt

**Host:** Windows; Python 3.11; Docker Desktop engine 29.4.3

## Closed findings

1. `ClinicalStaging` now rejects a state directory located inside either the
   restricted-runtime or Health-Record-Hub build context. This prevents
   generated staging secrets and state from entering either Docker build
   context through an operator-selected path.
2. `status()` binds its authenticated-ready observation to the current ingress
   container's validated `State.StartedAt` value and queries logs with
   `docker compose logs --since <StartedAt>`. A missing, malformed, or zero
   start time fails closed. The timestamp is retained in the status receipt.
3. Database-backed tests now require
   `RESTRICTED_RUNTIME_TEST_DATABASE_URL`. They cannot adopt an unrelated
   application's ambient `DATABASE_URL`; a static invariant test enumerates
   any future fallback.
4. The database-enabled runtime-wave assertion now matches its stated and
   implemented fail-closed contract: an unprovable gateway-policy pair returns
   HTTP 503, not ready.

## RED witness

Before the implementation, the two new staging regressions produced:

```text
2 failed, 24 passed
```

The failures showed that a state directory inside either supplied build context
was accepted and that the readiness log query omitted a current-container
`--since` boundary.

## GREEN evidence

All commands were run with `PYTHONPATH` bound to this worktree's `src`, avoiding
the separately installed editable checkout.

- Focused staging, isolation, and readiness contracts:
  `33 passed, 1 warning`.
- Unit, static, API, and integration contracts without an explicitly isolated
  database: `2570 passed, 122 skipped, 1 warning`.
- Database-backed contracts against a temporary PostgreSQL 16 container bound
  only to `127.0.0.1:58114`, using the explicit isolated-test variable:
  `52 passed, 3 warnings`.
- Role-specific container contracts: `7 passed`.
- `git diff --check`: pass.
- Hosted CI on revision `45e883c498df301db68f046bd54339598a39f00f`:
  [run 34067103832](https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34067103832)
  completed successfully. Its three jobs passed: Python 3.11 contracts, Python
  3.12 contracts, and the synthetic-only Linux/container E2E. The E2E job
  rebuilt and exercised the composed runtime rather than reusing the local
  Windows test result.

The temporary PostgreSQL container was created with `--rm`, stopped after the
run, and verified absent from `docker ps -a`.

## Remaining evidence gates

- The Linux/container witnesses and complete synthetic Compose lifecycle are
  green in hosted CI. Real host-level service-manager validation remains open;
  a containerized process witness is not evidence for systemd, launchd, or
  Windows SCM behavior.
- Dependency and image findings still require a pinned-input inventory,
  reachability triage, and accepted VEX or remediation.
- Representative operator controls and independent technical/nontechnical
  evaluation remain open.

No test used PHI. This receipt is not a HIPAA certification, legal approval, or
authorization for medical production.
