# Synthetic staging bootstrap — no apply in this repository

This manifest is a deployment scaffold, not deployed evidence. An approved
operator must supply digest-pinned images, a TTL, the signed generated policy,
and the public verification key. The Ed25519 private key stays outside this
repository and Docker context; use `tools/generate_synthetic_policy.py` to
write ignored files below `policy/generated/` before image construction.

Before either service receives traffic, an approved database operator creates
the **external** Secret Manager secret named by `migration_bootstrap_secret_id`.
Its single version is the one-time `MIGRATION_ADMIN_DSN`, a private-socket
admin connection string; its value is never created, read, or stored by
Terraform. Terraform grants only the isolated migration service account access
to that named secret. The migration job fails closed unless the reference,
secret version, socket proxy, and both IAM DB user names are present. It runs
`001_restricted_runtime.sql` followed by a rendered
`002_synthetic_iam_role_grants.sql.tmpl`. Runtime identities never receive DDL
privileges. The conversation IAM database user receives only
`restricted_content_runtime`; the gateway receives only
`restricted_ledger_runtime`.

The VPC has Private Google Access and no NAT. It intentionally does not claim
FQDN/SNI/certificate enforcement; that receipt field is `UNDETERMINED` until a
separately approved inspected egress control is deployed and tested. The
synthetic runner payload is fixed and must never be replaced with PHI.
