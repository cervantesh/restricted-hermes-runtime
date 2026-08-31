# Local Linux deployment verification

**Verified source frame:** `4b64ef1b5ec111ed826597bf93b13e828457a819`

**Date:** 2026-08-31

**Data:** disposable `SYNTHETIC_NON_PHI_ONLY` content only

The evidence commit containing this document changes documentation only. The
same complete gates listed here must also pass on that final commit before the
branch is considered closed.

## Environment

```text
Windows Python 3.11.7
WSL Ubuntu 24.04: Linux 6.6.87.2-microsoft-standard-WSL2 x86_64
Docker client/server 29.4.3
Docker Compose v5.1.3
```

## Required gates and observed baseline

| Gate | Command or scope | Result at source frame |
|---|---|---|
| Unit | `PYTHONPATH=src python -m pytest tests/unit -q` | `117 passed, 11 skipped`; related POSIX skips run below |
| Static | `PYTHONPATH=src python -m pytest tests/static -q` | `41 passed` |
| Linux API, PostgreSQL integration, POSIX controls | `bash tests/deployment/test_ac10_linux.sh <unique-project>` first bounded container | `88 passed` |
| Standalone root three-socket | same runner, second bounded container | `2 passed` |
| Role-image/container | `PYTHONPATH=src python -m pytest tests/container -q` | `7 passed` |
| Real Linux Compose E2E | `bash tests/deployment/test_local_compose_e2e.sh <unique-project>` | PASS |
| Hygiene | `python -m compileall -q src deploy/local/synthetic tests/unit/test_local_deployment_preflight_posix.py`; `git diff --check` | PASS |

Both deployment scripts use bounded waits where a process could otherwise hang.
Cleanup inventories and removes only the named Compose project and never runs a
global prune.

## Real deployment effects proved

The Compose E2E uses the exact production conversation and gateway roots and
proves:

- the inference volume is `root:20000` mode `1770`;
- all three live sockets match the frozen UID/GID/mode and ACL matrix;
- each role cannot see the other role's keys;
- PostgreSQL peer roles reach only their assigned schema;
- gateway row-lock/reservation works while direct gateway updates fail;
- disabled dispatch invokes no broker;
- explicit synthetic enablement permits one create/turn/replay and exactly one
  broker invocation;
- forced recreation preserves the committed turn and idempotent replay;
- IPv4, IPv6, DNS, and proxy-mediated egress fail;
- dispatch is explicitly disabled and read back false before normal exit.

## Fail-closed mutation matrix

Every mutation occurs before successful dispatch. Exact-image preflight fails
and broker count remains zero for:

- missing gateway and conversation operator authorization;
- missing gateway and conversation required keys;
- symlinked authorization;
- wrong-owner authorization;
- group-writable authorization;
- digest-mismatched authorization;
- missing/unreachable broker socket; and
- missing PostgreSQL socket.

The root-POSIX unit matrix independently covers valid, missing, symlinked,
wrong-owner, group-writable, world-writable, and digest-mismatched protected
files against `local_deployment_preflight._protected_file`.

## Nonclaims and operator ownership

This is operational repeatability evidence, not byte reproducibility, HIPAA
compliance, PHI authorization, deployment conformance, or model attestation.

```text
model_attested=false
deployment_conformant=false
phi_authorized=false
```

Real model/broker attestation, host firewall and physical security, HSM,
trusted time and rollback prevention, backups and restore, retention,
workforce controls, audit operations, incident response, BAA, and any decision
to authorize PHI remain operator-owned and outside this evidence.
