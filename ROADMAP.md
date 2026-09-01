# Roadmap

## Project posture

This repository is a research prototype and reproducible evidence package. It
is not a supported companion product for Hermes, and its publication does not
create a commitment by the repository owner to operate a new inference
platform or maintain a permanent Hermes fork.

The current implementation is useful for testing a narrow question: whether a
fail-closed, synthetic-only inference path can be composed around an exact
Hermes revision without exposing the normal agent surface. It is not approved
for PHI, production deployment, or unattended operation.

## Direction

### 1. Preserve the prototype as evidence

- Keep the synthetic witnesses reproducible and pinned to exact revisions.
- Correct security or reproducibility defects in existing claims.
- Do not expand the prototype with unrelated product features.
- Do not represent passing CI as compliance, provider attestation, or PHI
  authorization.

### 2. Seek the smallest viable Hermes adoption

- Identify the minimum restricted-mode contract that belongs in Hermes itself.
- Discuss that contract with Hermes maintainers before expanding core surface.
- Prefer an upstream implementation over a permanently maintained personal
  fork.
- Keep deployment infrastructure and organization-specific policy outside the
  Hermes core repository.

### 3. Avoid creating an ownerless security product

- Evaluate maintained infrastructure components before extending custom
  gateway, policy, storage, or deployment code.
- Replace prototype components when an adequately maintained alternative can
  satisfy the same fail-closed contract.
- Do not call the runtime production-ready until an identified organization or
  provider accepts operational ownership.

### 4. Assign deployment ownership before sensitive use

Any deployment handling sensitive data requires an explicit operational owner
responsible for, at minimum:

- identity and access administration;
- approved provider, model, region, retention, logging, and training terms;
- key management and rotation;
- egress and network controls;
- audit evidence, monitoring, backups, incident response, and recovery;
- dependency and security-update maintenance; and
- the applicable contractual and regulatory decisions.

That owner may be the deploying organization, a supported upstream project, or
a contracted provider. It must not be inferred from this public prototype.

## Decision gates

Further provider integration, including Vertex AI, should wait until all of
the following are true:

1. the Hermes-side contract has a credible upstream or organization-owned
   maintenance path;
2. the deployment runtime has an explicit operational owner;
3. maintained components have been evaluated against the frozen contract; and
4. any remaining custom code has a documented maintenance and incident path.

If no party accepts those responsibilities, the honest outcome is to retain
this repository as evidence only and select a supported alternative rather
than silently turning it into a personal security product.

