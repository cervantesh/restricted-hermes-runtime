# Deployment policy

`main.tf` creates two separate Cloud Run identities and grants Vertex only to
the gateway identity. It intentionally cannot constitute a PHI deployment:
private Cloud SQL roles, exact KMS key resources/IAM, restricted egress, VPC
connectivity, exact project posture, BAA/Covered-Service evidence, cache
disablement, retention, and synthetic exact-revision receipts are required
inputs. Do not apply it for PHI until every item in `evidence/PHI_BLOCKERS.md`
is evidenced for the exact revision.
