# Synthetic staging bootstrap — no apply in this repository

This manifest is a deployment scaffold, not deployed evidence. An approved
operator must supply digest-pinned images, a TTL, the signed generated policy,
and the public verification key. The Ed25519 private key stays outside this
repository and Docker context; use `tools/generate_synthetic_policy.py` to
write ignored files below `policy/generated/` before image construction.

Before either service receives traffic, the isolated migration job must run
`001_restricted_runtime.sql` followed by a rendered
`002_synthetic_iam_role_grants.sql.tmpl`, using its separately managed admin
secret. Runtime identities never receive DDL privileges. The conversation IAM
database user receives only `restricted_content_runtime`; the gateway receives
only `restricted_ledger_runtime`.

The VPC has Private Google Access and no NAT. It intentionally does not claim
FQDN/SNI/certificate enforcement; that receipt field is `UNDETERMINED` until a
separately approved inspected egress control is deployed and tested. The
synthetic runner payload is fixed and must never be replaced with PHI.
