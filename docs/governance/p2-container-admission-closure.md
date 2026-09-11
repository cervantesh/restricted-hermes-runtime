# P2 container-admission closure card

**Frame:** `P2-CONTAINER-ADMISSION v1`

## Strict scope

The representative-host witness must not run from a container that merely
mounts the host Docker socket. A matching container `/etc/os-release`, kernel
release, architecture, and default `unix:///var/run/docker.sock` endpoint are
not evidence that the witness itself executes on the administrator-provisioned
host.

Before the harness reaches Docker discovery, staging state, secrets, networks,
or receipt paths, the host-admission command must fail closed when
`systemd-detect-virt --container --quiet` detects a container or cannot return
its explicit non-container result.

## Closure criteria

- An Ubuntu 24.04 x86_64 non-container result is admitted.
- A detected container with otherwise matching platform facts is denied.
- Missing, failed, timed-out, or undecodable detector execution is denied
  without echoing detector output.
- The shell harness invokes the admission command before every Docker command.

## Non-goals

This is not hardware attestation, a general virtualization policy, proof of
operator identity, or representative-host conformance. It narrows a reachable
false-admission path before the later P2 RED/GREEN witness.
