# PHI deployment authorization blockers

Status: **BLOCKED — synthetic-only implementation**.

The following cannot be satisfied by fixtures, local tests, Terraform plans,
or this document. Each requires attributable proof on the exact deployed
revision and project:

- effective BAA and Covered Service/model status for the actual use;
- `cacheConfig.disableCache=true` fresh read for the exact project;
- payload logging, retention, training-use, and supported model-family posture;
- Cloud Run revisions/image digests, private Cloud SQL and separated schema
  roles, KMS separate-key grants, and no static/exportable credentials;
- restricted-service Vertex IAM denial and egress denial; gateway-only exact
  hostname/method reachability; redirects/proxies/alternate endpoints denied;
- real synthetic non-PHI Vertex, IAM, egress, crash, canary, and privacy-sink
  receipt using the exact policy digest/epoch/migration; and
- approved workforce-only administrative use, tenant/caller identity, owners,
  retention/deletion rule, deploy approvers, and incident owner.

Until all are green, this repository must not receive or send PHI.
