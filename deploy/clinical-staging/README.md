# Synthetic clinical staging lifecycle

The wrapper validates the exact pinned base-image references in the selected
HRH candidate Dockerfiles before Compose runs. It does not claim hermetic
inputs: Docker frontend and APK resolution remain an external publication
dependency.

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
  `41464aee8748f857153ba2b47377515d4847d210`.
- A clean Health-Record-Hub checkout at exactly
  `e30a4f968de6727519f49c08369f561fdf269ec5`, with tree
  `7fb2543a2ceb1649f05c467b38708d1404106659`.
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
the effective non-root identity, read-only root filesystem, dropped capabilities,
`no-new-privileges`, bounded tmpfs and exact mount modes of the restricted
ingress and clinical-adapter containers, lifecycle state and nonclaims.
`evidence/last-transition.json` records a normal stop.
These are technical staging receipts, not compliance artifacts.

If initialization stops before `status` succeeds, do not hand-edit the marker,
environment file or Docker labels. Diagnose the failing bounded command, then
use `destroy` only after its label/path/project checks succeed. A failed safety
check is intentionally not bypassable through this wrapper.

## Cold backup and restore

`backup` and `restore` are a deliberately bounded cold-recovery witness. This
is not a scheduled backup: it does not provide encrypted storage, retention
policy, support a hot restore, or make a production/PHI claim.

Stop a healthy candidate first. Choose a **new, absolute** backup directory
outside the runtime checkout, Health-Record-Hub checkout and private staging
state. The operator must record the printed manifest SHA-256 independently of
the backup directory; `restore` refuses a bundle without that external value.

```bash
backup=/absolute/operator-backups/clinicalstagingdemo-cold-001

python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" stop
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" \
  backup --backup-dir "$backup"
# Record manifest_sha256 from the JSON result outside "$backup".

python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" destroy
python "$tool" --hrh-root "$hrh" --state-dir "$state" --project "$project" \
  restore --backup-dir "$backup" --expected-manifest-sha256 '<externally-recorded-sha256>'
```

The backup contains the private state directory and ten explicitly named
persistent volumes. `clinical_socket` is intentionally not exported; the
restore creates it empty and `clinical-socket-init` reconstructs the transport
socket during the ordered startup. Before reading any volume, `backup` removes
the stopped Compose containers and refuses every remaining container mount of
an exact staging volume, including an unlabeled debug or orphan container. Each
archive is fsynced before the manifest is written; the manifest is fsynced
before `COMPLETE`, and `COMPLETE` is fsynced before the temporary directory is
atomically published. A partial directory is never a restore input.

The one-shot archive helper has no network, a read-only root filesystem,
`no-new-privileges`, no Docker socket, and only its two exact mounts. Backup
gets only `DAC_OVERRIDE`, which is required to read persisted service-owned
files and write the private `0700` bundle bind. Restore gets exactly
`DAC_OVERRIDE`, `CHOWN`, and `FOWNER`: the real cold-restore witness proved
that tar cannot restore PostgreSQL's archived numeric UID/GID without `CHOWN`,
then cannot restore the archived mode without `FOWNER`. A fixed per-volume UID
would not be safe or sufficient: existing data may have arbitrary persisted
service ownership, so it cannot universally traverse the source tree or
preserve the numeric owner and mode metadata required by this cold format. The
helper is always root only for that bounded transfer; it receives only one
named source/destination volume and the bundle bind for that invocation.

Before Docker state or the destination state directory is changed, `restore`
requires the exact member allowlist, completion marker, external manifest hash,
safe non-link tar members, marker/source identity, every member hash and an
empty destination with no conflicting named or labeled Docker resource. It
first copies the complete input bundle into a private snapshot, validates that
snapshot, and consumes only that snapshot; a mutable operator directory is
never read after validation. It then starts databases/migration,
Mattermost/proxy, HRH/socket/adapter and ingress in that order, and runs the
normal status/identity/confinement/policy checks. The immediate receipt records
only a mechanical restore. The separate `causal_e2e_verified` receipt is
published only by the synthetic drill after its causal controls and artifact
scan pass. If an error occurs after the temporary recovery state is published,
it remains in a non-operational `recovering` lifecycle; use `destroy` before
retrying instead of attempting to start or hand-edit it.
