# Composed E2E Compose discovery — closure card

## Scope

This is a host-harness compatibility cut.  It preserves the composed E2E's
sealed `--env-file` contract while allowing the Docker CLI on Windows to find
its installed Compose plugin.  It is not a runtime, container, provider, or
host-conformance change.

## Closure contract

1. The child environment contains only the generated E2E contract, Docker
   transport variables, a disposable Docker configuration directory, and the
   minimum Windows installation-discovery variables (`ProgramFiles` or
   `ProgramW6432`) required by Docker CLI plugin discovery.
2. No inherited `CLINICAL_*` variable can override a value from the generated
   environment file.
3. On Windows, absence of both discovery variables fails before a Compose
   command is attempted, with a content-free diagnostic.
4. Docker's mutable client state and Windows temporary metadata are written
   below the harness temporary state, never below the source checkout, a
   system directory, or an operator's Docker configuration.
5. The actual `docker compose --env-file ... version` probe succeeds in the
   sealed environment before the expensive build is used as evidence.

## Negative controls

- An inherited clinical variable remains absent or is replaced by the sealed
  value.
- A Windows environment with neither discovery variable is rejected.
- The probe must still include `--env-file`; falling back to an ambient process
  environment is inadmissible.
- A probe that writes `.docker/` under the source checkout is inadmissible.
- A Windows probe that defaults its temporary metadata under a system directory
  is inadmissible.

## Nonclaims

This establishes only that the test harness can invoke its declared Docker
Compose implementation safely on this host.  It proves neither a composed E2E
result nor P2 representative-host admission, PHI readiness, or an A1 decision.
