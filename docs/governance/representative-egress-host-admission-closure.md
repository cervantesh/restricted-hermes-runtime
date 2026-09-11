# Representative egress host-admission closure

## Risk reduced

The representative egress harness must not collect a P2-looking receipt from
WSL or any other merely-Linux environment. Its first executable gate has to be
the shared Ubuntu 24.04 x86_64 non-WSL admission contract, before Docker,
staging, network creation, secrets, or receipt state are touched.

## Scope

- Invoke the shared P2 host-admission command from the real egress harness.
- Require an unoverridden local Docker Unix-socket context before Docker
  inspection.
- Deny unsupported hosts with a bounded diagnostic before Docker collection.
- Prove source ordering statically and exercise the live WSL negative control.

## Closure predicates

1. The harness invokes `p2_host_platform_admission.py` before `docker info`.
2. WSL exits with a bounded unsupported-host denial and creates no receipt,
   diagnostic directory, Docker resource, staging state, or evidence folder.
3. `DOCKER_HOST`, `DOCKER_CONTEXT`, or a non-local Docker endpoint is denied
   before Docker inspection.
4. An admitted host retains the existing later Docker and collector checks.
4. Focused tests and exact-head CI pass.

## Nonclaims

This rejects an invalid host; it does not create a representative-host receipt
or establish P2, A0, PHI, or deployment readiness.
