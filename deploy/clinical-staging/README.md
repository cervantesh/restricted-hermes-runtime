# Synthetic clinical staging lifecycle

This wrapper turns the existing composed clinical acceptance witness into a
stable, operator-driven **synthetic-only** local Linux environment. It reuses
the real Mattermost, restricted ingress, clinical adapter and Health-Record-Hub
paths. It adds no clinical operation and no model, provider, tool, plugin, MCP,
memory or general conversation path.

This environment is **not HIPAA compliance**, **not PHI authorization**, and
**not production readiness**. Never put real staff, patients, credentials,
hostnames or records in it. The certificates, accounts and appointments are
generated synthetic fixtures.

## Prerequisites and fixed frame

- Linux with Docker Engine and Compose v2.
- A clean runtime checkout descending from
  `c6c41a0980ed21de95d324c828ee9c5bb50cb8dd`.
- A clean Health-Record-Hub checkout at exactly
  `ad13735e9881a48580a9e138daac137f8c865dea`.
- A fresh absolute state directory outside either repository. Its basename must
  be `<project>.synthetic-clinical-staging`.
- A project matching `clinicalstaging[a-z0-9]{1,32}`.

The state directory holds secrets, the offline signing key and evidence with
mode 0600/0700. It must not be committed, copied into a build context or reused
with another project. Persistent Docker volumes carry three exact labels that
bind them to the project and state ID.

## Lifecycle

```bash
runtime=/absolute/path/restricted-hermes-runtime
hrh=/absolute/path/Health-Record-Hub
project=clinicalstagingdemo
state=/absolute/operator-state/${project}.synthetic-clinical-staging
tool="$runtime/deploy/clinical-staging/clinical_staging.py"

python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" init
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" status
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" stop
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" up
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" \
  refresh-policy --epoch clinical-e2
```

The only published endpoint is a staging-only, secretless NGINX TCP/TLS
passthrough bound to `https://127.0.0.1:18443` by default. It forwards opaque
encrypted traffic to Mattermost without terminating TLS. Mattermost and every
application service remain unpublished. The proxy alone joins the explicit
non-internal `operator_access` network plus the internal `mattermost_edge`;
the other four networks remain internal. This narrow operator-access exception
is not a universal no-egress claim. The generated CA is under the private state
directory. Its Mattermost certificate covers both the internal DNS name and the
advertised loopback IPv4 address; `status` verifies the advertised IP endpoint
from the host before it writes evidence.

`init` builds from the exact clean sources, initializes the external volumes,
runs the root controller only through `docker compose run --rm`, and then
verifies that no privileged provisioner remains. `stop` preserves every
credential, database and outbox volume. `up` does not reseed or rotate them.
`refresh-policy` stops ingress, installs and verifies a newly signed matched
policy/signature pair through the existing
controller helper, and restarts only ingress after the pair verifies. An
interruption can leave ingress stopped with a fail-closed mismatched pair;
rerunning `refresh-policy` safely replaces and verifies both files before the
restart.

`reset` and `destroy` are destructive. Both reread the closed state marker,
recheck the current source frame, discover volumes by both the staging and
Compose project labels, reject any unexpected or mislabeled volume, and remove
only the eleven exact external volume names. `reset` then initializes a fresh
synthetic environment; `destroy` removes the bounded state directory.

## Evidence and recovery

`status` writes `evidence/status.json`, binding the runtime and HRH heads and
trees, built image IDs, current policy digest, requested and effective loopback
publisher tuples, the CA-verified TLS probe, the narrow network exception,
lifecycle state and nonclaims. `evidence/last-transition.json` records a normal stop.
These are technical staging receipts, not compliance artifacts.

If initialization stops before `status` succeeds, do not hand-edit the marker,
environment file or Docker labels. Diagnose the failing bounded command, then
use `destroy` only after its label/path/project checks succeed. A failed safety
check is intentionally not bypassable through this wrapper.
