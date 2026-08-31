# Local Linux deployment verification

**Runtime revision exercised by the real Compose E2E:**
`4cd828b248ca699d5e50f6400e0ba682b8d6e5ab`

**Final source revision before this evidence-only commit:**
`71f76a1099bdf2a7ee615546fca42ffde0b450fa`

**Date:** 2026-08-31

**Data:** disposable `SYNTHETIC_NON_PHI_ONLY` content only

The only source change after the real E2E was a container-test expectation
update adding the dedicated PostgreSQL socket group (`20004`) to the two fixed
runtime identities. No runtime or deployment artifact changed after the E2E.

## Environment

```text
Windows Python 3.11.7
WSL Ubuntu 24.04: Linux 6.6.87.2-microsoft-standard-WSL2 x86_64
Docker client/server 29.4.3
Docker Compose v5.1.3
```

## Executed evidence

| Gate | Exact command or scope | Result |
|---|---|---|
| Static deployment and existing guards | `python -m pytest tests/static -q` | `41 passed` |
| Existing unit suite | `python -m pytest tests/unit -q` | `117 passed, 4 skipped`; skips require POSIX |
| Real Linux Compose E2E | `wsl.exe -d Ubuntu-24.04 bash -lc 'cd /mnt/c/dev/restricted-hermes-runtime-deploy && bash tests/deployment/test_local_compose_e2e.sh rhrsynthetic0831n'` | PASS |
| Container suite, first pass | `python -m pytest tests/container -q` | `4 passed, 3 failed`; failures were stale expected supplementary groups after adding PostgreSQL GID `20004` |
| Corrected container failures | the three previously failing nodes from `tests/container/test_runtime_image.py` | `3 passed` on `71f76a1` |
| API readiness subset | `python -m pytest tests/api/test_readiness_wave.py -q` | `3 passed` |
| Source hygiene | `python -m compileall -q src/restricted_runtime deploy/local/synthetic`; `git diff --check` | PASS before commits |

The real E2E proved:

- an empty inference volume becomes `root:20000` mode `1770`;
- all three live sockets have the frozen UID/GID/mode and the positive and
  negative connection matrix passes;
- conversation and gateway cannot see the other role's key files;
- PostgreSQL peer roles can reach only their assigned schema;
- the production gateway row-lock/reservation path works, while both a direct
  `UPDATE(updated_at)` and a direct dispatch-control update by the gateway
  fail;
- disabled dispatch reaches no broker; explicit synthetic enablement permits
  one create/turn/replay cycle with exactly one broker invocation;
- forced recreation of conversation and gateway preserves the committed turn
  and idempotent replay;
- conversation and gateway fail IPv4, IPv6, DNS, and proxy-mediated egress;
- cleanup removed only the named Compose project's containers and volumes.

After the runs, an explicit inventory found no `rhrsynthetic0831*` container
or volume. Seventy-seven disposable images with that exact test prefix were
removed; unrelated Docker resources were not modified.

## Unverified or incomplete gates

- `tests/api/test_gateway_message_schema.py` and
  `tests/api/test_turn_schema.py` produced no result on Windows and were
  stopped after bounded 30-second attempts. WSL Python had no pytest
  installation. These are **unverified**, not passes or failures.
- The full container suite was not rerun after the expectation-only correction;
  the three previously failing nodes passed, while the other four had passed
  in the immediately preceding full run.
- The standalone real PostgreSQL integration suite and standalone
  three-socket suite were not rerun. The Compose E2E did exercise real
  PostgreSQL and all three sockets, but that is not a substitute for every
  assertion in those suites.
- Missing broker, missing PostgreSQL socket, missing operator authorization,
  and missing-key controls were not individually mutated in the final Compose
  run. The preflight is wired to fail closed for them, but AC6's executable
  negative matrix remains unproved.
- Symlink, wrong-owner, writable, and digest-mismatch artifact mutations were
  not re-executed against the final Compose images. Valid artifact startup and
  role mount separation were proved.

## Nonclaims

This is operational repeatability evidence, not byte reproducibility, HIPAA
compliance, PHI authorization, deployment conformance, or model attestation.
Every synthetic result remains:

```text
model_attested=false
deployment_conformant=false
phi_authorized=false
```

Real model/broker attestation, host firewall and physical security, HSM,
trusted time and rollback prevention, backups and restore, retention,
workforce controls, audit operations, incident response, BAA, and any decision
to authorize PHI remain operator-owned and outside this evidence.
