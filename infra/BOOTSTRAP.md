# Synthetic staging bootstrap — no apply in this repository

This manifest is a deployment scaffold, not deployed evidence. An approved
operator must supply digest-pinned images, a TTL, the signed generated policy,
and the public verification key. The Ed25519 private key stays outside this
repository and Docker context; use `tools/generate_synthetic_policy.py` to
write ignored files below `policy/generated/` before image construction.

`policy_digest` is the policy bundle's bare lowercase 64-hex JCS SHA-256
digest (for example `4ce0...e7e54`), not `sha256:<hex>`. Runtime configuration,
database rows, and gateway envelopes use that bare form. Image references and
receipt/provenance digests stay prefixed as `image@sha256:<hex>` and
`sha256:<hex>`, respectively.

## Two-stage image inputs (operator run; no fake digest)

This repository does not create an Artifact Registry and then invent a digest
in Terraform. First create the isolated repository and generate the public
policy artifacts, using an external private-key path:

```sh
PROJECT_ID=health-record-hub-dev REGION=us-central1 REV=approved-revision
gcloud artifacts repositories create restricted-synthetic-runtime --project="$PROJECT_ID" --location="$REGION" --repository-format=docker
python tools/generate_synthetic_policy.py --private-key-b64-file /approved/external/policy.key --output-dir policy/generated --project-id "$PROJECT_ID" --project-number "APPROVED_NUMBER" --epoch "APPROVED_EPOCH" --tenant-id "APPROVED_TENANT" --runner-principal "RUNNER_SA" --conversation-principal "CONVERSATION_SA"
gcloud builds submit --project="$PROJECT_ID" --config=infra/cloudbuild.images.yaml --substitutions=_REGION="$REGION",_REV="$REV" .
```

Second, resolve each pushed image's immutable digest from Artifact Registry and
write only those real values into the operator's ignored `terraform.tfvars`:

```sh
BASE="$REGION-docker.pkg.dev/$PROJECT_ID/restricted-synthetic-runtime"
gcloud artifacts docker images list "$BASE/conversation" --include-tags --filter="tags:$REV" --format='value(version)'
```

Repeat for `gateway`, `runner`, and `migration`; prepend each returned
`sha256:...` to its `BASE/image@` reference and write all real values into the
ignored tfvars file. Then import the manually created repository using that
same tfvars file:

```sh
terraform -chdir=infra import -var-file=../operator.synthetic.tfvars google_artifact_registry_repository.runtime "projects/$PROJECT_ID/locations/$REGION/repositories/restricted-synthetic-runtime"
```

Then run `terraform plan` and, only after approved preflight, `terraform
apply`. The Terraform check rejects all non-project-owned runtime images and
accepts no placeholder digest.

Before either service receives traffic, an approved database operator creates
the **external** Secret Manager secret named by `migration_bootstrap_secret_id`.
Its exact version `1` is the one-time `MIGRATION_ADMIN_DSN`, exactly a
password-authenticated PostgreSQL conninfo string with
`host=/cloudsql/PROJECT:us-central1:restricted-synthetic-postgres`, `dbname`,
`user`, and `password`. Its value is never created, read, or stored by
Terraform. Terraform grants only the isolated migration service account access
to that named secret. The migration job fails closed unless the reference,
secret version, exact socket host, password auth, and both IAM DB user names
are present. The one migration image copies the approved digest-pinned Cloud
SQL Auth Proxy binary and supervises it as a local child. It creates its owned
`/cloudsql` socket directory, waits for bounded localhost readiness, then runs
the migration and postflight; it always reaps the child. A migration or
postflight error remains the process error even if cleanup also fails; a clean
exit requires both the migration/postflight and proxy cleanup to succeed. The
job depends on its Secret Manager accessor binding and declares neither a
Cloud Run proxy sidecar nor a native Cloud SQL volume.
The two long-lived runtime services alone retain IAM-authenticated Cloud SQL
Auth Proxy sidecars with health checks and a localhost-only `quitquitquit`
shutdown endpoint. It runs
`001_restricted_runtime.sql` followed by a rendered
`002_synthetic_iam_role_grants.sql.tmpl`. Runtime identities never receive DDL
privileges. The conversation IAM database user receives only
`restricted_content_runtime`; the gateway receives only
`restricted_ledger_runtime`. Cloud SQL IAM database usernames are the service
account emails with the `.gserviceaccount.com` suffix removed; OIDC audiences
and Cloud IAM bindings retain full service-account emails.

The zonal PostgreSQL 16 instance explicitly pins `edition = "ENTERPRISE"` with
`tier = "db-custom-1-3840"`. This compatible pair must remain explicit: relying
on a provider default can select Enterprise Plus, where that custom tier is
invalid.

The VPC has Private Google Access and no NAT. Ordinary Google APIs use the
restricted VIP, but the frozen Vertex `us` endpoint uses its dedicated regional
PSC subnet, reserved PSC address passed to the endpoint as its resource URI, and exact private DNS record; it must never be substituted with
`aiplatform.googleapis.com` or routed to the restricted VIP. It intentionally
does not claim FQDN/SNI/certificate enforcement; that receipt field is
`UNDETERMINED` until a separately approved inspected egress control is deployed
and tested. The synthetic runner payload is fixed and must never be replaced
with PHI.

Private SQL egress is TCP/3307 to the Cloud SQL private-IP `/32` for the
conversation, gateway, and migration connector tags only. The runner has no
database path. TCP/5432 is not opened by this firewall.

Provider 6.50 reads the endpoint address back as its literal IP after creation.
`main.tf` therefore ignores only that normalized `address` field; do not widen
the exception, because target API, network, subnetwork, and access type must
remain drift-visible. A replacement of the reserved address triggers endpoint
replacement, and a postcondition requires the endpoint's returned address to
match the reserved PSC IP.

The receipt helper in this repository is local only and therefore permanently
returns `PARTIAL` unless an independent deployed collector/verifier is added in
an approved follow-up. Do not treat caller-provided `PASS` fields, Git SHAs, or
digests as deployed evidence.

The VPC's private DNS also maps `*.run.app` to the restricted VIP so the two
internal Cloud Run invocations retain a route after default-route removal. This
does not prove SNI/certificate enforcement; see `KILL_SWITCH.md` for the
separate durable dispatch disablement required before rollout or rollback.
