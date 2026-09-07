# Durable published HRH operator contract v1

Status: **design contract; not implemented**

Inspected runtime frame: `4aa366adfb09cf8d230dce92ff98eb12dcc9029b`

Required publication implementation frame: Health-Record-Hub
`a96effc11ec1436974d6f3a3cdbfaf3cd37d306c`.

This document defines the smallest complete operator contract for choosing an
HRH delivery mode when a clinical-staging generation is created or restored.
It does not authorize production or PHI use.

## Observed

1. Clinical staging currently implements one durable operator mode: HRH is
   built from a fixed, clean Git checkout. The CLI requires `--hrh-root`, the
   source frame is checked before mutation, and the source-build Compose
   overlay is always selected.
2. The source marker and cold-backup manifest bind HRH by Git head and tree.
   Their schemas are closed and their bytes are existing recovery evidence.
3. `init`, `up`, `status`, `stop`, `backup`, `restore`, `reset`, and `destroy`
   all ultimately rely on that source identity and Compose selection.
4. Migration already gates web startup during initialization and restore.
5. The published HRH Compose overlay already uses digest-only images,
   `pull_policy: never`, no HRH source mount, and a successful-migration
   dependency. The staging overlay independently adds an `hrh.build` block,
   which would survive a published merge.
6. The standalone composed E2E harness demonstrates the useful primitives:
   repo-independent candidate verification, a private Docker configuration,
   explicit host pulls, effective image inspection, and migration-before-web.
   It is not wired into the durable operator lifecycle.
7. The current runtime candidate verifier predates the exact output of HRH
   `a96effc`: it does not yet accept digest-specific image and attestation
   retention evidence or verify the signed receipt.
8. HRH `a96effc` can produce a signed receipt and a digest-pinned evidence
   image. The publication remains evidence-incomplete until a hosted run is
   externally observed as successful and its evidence image is reconstructed
   and verified with a second clean registry-reader context.

## Confirmed

- Compose selection alone is insufficient. Mode identity crosses marker,
  backup, restore, status, evidence, authentication, and CLI boundaries.
- Source-build compatibility can be preserved exactly: it remains the default,
  retains its existing marker and backup schemas, and keeps `built_images`.
- Published operation can omit the HRH checkout, build context, and source
  mounts. Runtime/controller source remains present and must be disclosed.
- Registry credentials are acquisition inputs, not generation identity. They
  must never be persisted in state, marker, backup, evidence, logs, or argv.
- Cache presence is not authority. Every published restore needs fresh
  independent evidence and credentials and must explicitly pull the exact
  approved subjects before target mutation.
- The completed migration container and running web container are both parts
  of published image evidence.

## Control

### Source-build

Source-build is the compatibility control.

- Omitting `--hrh-mode` during `init` selects `source-build`.
- `--hrh-root` is parser-optional. After reading or selecting the authoritative
  mode, source-build requires it and published mode rejects it, before any
  Docker or Compose invocation.
- Its current Git frame, build inputs, Compose overlay, marker schema
  `restricted-synthetic-clinical-staging.v1`, backup schema, and
  `built_images` evidence remain byte- and behavior-compatible.
- Existing source lifecycle and cold-recovery tests must pass without fixture
  or schema rewrites.
- An already-created generation does not ask the operator to repeat its mode.
  The persisted marker is authoritative.

## Decision

### Mode authority

The operator selects `source-build` or `published` only when running `init` or
`restore`. Every ordinary lifecycle command infers the mode from the closed
marker. A CLI mode argument on `up`, `status`, `stop`, `backup`, `destroy`, or
TLS operations would create a second authority and is forbidden.

For CLI and test compatibility, omitted mode on `restore` means source-build.
Only published restore requires explicit `--hrh-mode published`. The selected
or defaulted mode must equal the closed backup schema and generation identity;
a mismatch fails before target mutation.

### CLI matrix

| Command | Source-build | Published |
|---|---|---|
| `init` | Default; requires `--hrh-root` | Requires `--hrh-mode published` and all published evidence inputs; rejects `--hrh-root` |
| `restore` | Omitted mode defaults to source-build; requires `--hrh-root` | Requires explicit `--hrh-mode published`, fresh independent trust and reconstructed evidence, and private Docker config |
| `up` | Mode inferred from marker; then requires `--hrh-root` | Mode inferred from marker; rejects `--hrh-root`; never pulls |
| `status` | Mode inferred; then requires `--hrh-root`; reports `built_images` | Mode inferred; rejects `--hrh-root`; reports `effective_images` |
| `stop` | Mode inferred; then requires `--hrh-root` | Mode inferred; rejects `--hrh-root` |
| `backup` | Mode inferred; then requires `--hrh-root`; existing source backup schema | Mode inferred; rejects `--hrh-root`; distinct published backup schema |
| `destroy` | Mode inferred; then requires `--hrh-root` | Mode inferred; rejects `--hrh-root` |
| `reset` | Existing behavior | Unsupported; fail closed with instructions to destroy and perform a new explicit published init/restore |
| TLS lifecycle | Mode inferred from marker | Mode inferred from marker |

### Published init inputs

Published `init` accepts exactly three explicit paths, not ambient behavioral
environment variables:

1. a closed independent trust declaration;
2. the reconstructed publication evidence directory, which contains the exact
   receipt, receipt signature, KMS public key, and SHA-256 manifest;
3. a private Docker configuration directory for registry-reader access.

There are no separate CLI paths for the receipt, signature, or public key. That
would create duplicate authorities for the same bytes. The runtime snapshots
the evidence directory once, validates its exact allowlist and manifest, and
consumes the receipt, signature, and public key only from that verified
snapshot.

Trust, evidence files, and the Docker configuration are each snapshotted once
into run-owned, private temporary paths. The Docker snapshot is created before
any Cosign verification, including registry-backed SBOM/provenance
verification. One snapshot serves all four role/predicate verifications and
both explicit pulls, and is deleted before marker publication. Parsing, hashes,
exact-receipt-byte signature verification, Cosign mounts, and pulls consume
only verified snapshot bytes. Cleanup targets only run-owned paths and runs
after every ordinary success or failure. Credential bytes and private paths are
excluded from public evidence.

As proportional crash hardening, the existing init lock may clean credential
snapshots orphaned by `SIGKILL`, but only inside a dedicated private snapshot
parent and only when a closed ownership marker identifies this staging project
and run. It must reject symlinks and unexpected entries and must never recurse
through an operator-supplied or broad directory.

### Closed independent trust declaration

Schema: `restricted-runtime-hrh-trust.v2`

Exact keys:

```json
{
  "schema_version": "restricted-runtime-hrh-trust.v2",
  "clinical_contract_revision": "<40 lowercase hex C>",
  "build_source_revision": "<40 lowercase hex H>",
  "platform": {
    "os": "linux",
    "architecture": "amd64"
  },
  "publisher_identity": "<exact Forgejo workflow identity>",
  "kms_key_version": "<exact enabled asymmetric KMS key-version resource>",
  "kms_public_key_sha256": "<64 lowercase hex>",
  "subjects": {
    "web": "<registry/repository@sha256:...>",
    "migrate": "<registry/repository@sha256:...>",
    "evidence": "<registry/repository@sha256:...>"
  }
}
```

This is the minimal structural extension of trust v1: the existing canonical
fields and nested subject shape are preserved, with only `subjects.evidence`
added and `schema_version` advanced. Unknown or missing keys fail closed. The
declaration is independently operator-owned; neither the producer handoff,
receipt, attestation, nor reported workflow status may declare its own trust
anchors.

### Published evidence input

The evidence directory must contain exactly `SHA256SUMS.json` plus this sorted
allowlist emitted by HRH `a96effc`:

```text
candidate-receipt.json
candidate-receipt.sig
cleanup-policies.raw.json
cleanup-policy-observation.json
kms-public.pem
migrate.attachment.manifest.json
migrate.attestation-retention-evidence.json
migrate.downloaded-attestations.json
migrate.material-evidence.json
migrate.provenance.json
migrate.retention-evidence.json
migrate.runtime-identity.json
migrate.spdx.json
migrate.subject.config.json
migrate.subject.manifest.json
web.attachment.manifest.json
web.attestation-retention-evidence.json
web.downloaded-attestations.json
web.material-evidence.json
web.provenance.json
web.retention-evidence.json
web.runtime-identity.json
web.spdx.json
web.subject.config.json
web.subject.manifest.json
```

`SHA256SUMS.json` must itself have the closed schema emitted by the producer
and list each allowlisted file exactly once, in sorted order, with its SHA-256
and size. It does not list itself.

The evidence-image subject comes only from independently owned
`trust.json.subjects.evidence`. The producer handoff and externally observed
workflow status are evaluation evidence, never runtime trust. Runtime records
that declared identity but cannot establish that an extracted directory is the
child of that OCI subject. Equality to the independently reconstructed evidence
image is proved only by A21. Runtime verifies the retained directory allowlist,
file hashes and sizes, the signature over the exact receipt bytes, and the SBOM
and provenance outer envelopes for both roles. C, H, platform, publisher, exact
KMS key version, public-key fingerprint, and web/migrate subjects must agree
across independent trust, receipt, provenance, SBOM metadata where applicable,
and retained evidence bytes.

For published mode, the independent trust declaration is the sole authority
for C and H. Runtime validates their form and cross-document agreement but does
not pin them to constants. Source-build continues to pin its existing HRH
revision and tree unchanged.

No nested statement may substitute for a mismatching outer signed statement.
Ambiguous, additional, missing, malformed, mixed-run, wrong-role, wrong-key,
wrong-subject, or retention-inconsistent evidence fails closed.

### Published marker

Source marker v1 is unchanged. Published mode uses the distinct closed schema
`restricted-synthetic-clinical-staging-published.v1`.

Exact top-level keys:

```text
schema
synthetic_only
project
state_dir
state_id
compose_env_sha256
lifecycle
runtime_head
runtime_tree
volumes
hrh_candidate
effective_images
```

`hrh_candidate` has exactly:

```text
clinical_contract_revision
build_source_revision
platform
publisher_identity
kms_key_version
kms_public_key_sha256
subjects
trust_sha256
receipt_sha256
receipt_signature_sha256
evidence_manifest_sha256
verification_sha256
```

`platform` and `subjects` retain the exact closed nested shapes from trust v2.

The persisted verification result is canonical closed identity JSON with
exactly `schema_version`, `trust_sha256`, `receipt_sha256`,
`receipt_signature_sha256`, `evidence_manifest_sha256`, `kms_public_key_sha256`,
`subjects`, and `verified_predicates`. `verified_predicates` is exactly the
sorted four-element set `migrate:provenance`, `migrate:sbom`,
`web:provenance`, and `web:sbom`. Canonical serialization uses sorted keys and
no insignificant whitespace. It contains no timestamp, hostname, username,
temporary path, Docker-config path, or other machine-specific value.

`effective_images` has exactly `hrh` and `hrh-migrate`. Each value binds the
approved subject, local image ID, effective RepoDigest, and platform. No
credential or credential path is stored.

Allowed lifecycle states remain the current closed set. Marker publication is
atomic and occurs only after evidence verification and exact image acquisition.

### Published backup

Source backup v1 remains unchanged. Published mode uses
`restricted-synthetic-clinical-cold-backup-published.v1` with the existing
common backup fields, but replaces source-only HRH Git fields with the exact
published `hrh_candidate` and `effective_images` objects from the marker.

Its exact top-level keys are:

```text
schema
synthetic_only
complete
project
state_id
state_dir
compose_env_sha256
runtime_source
hrh_candidate
effective_images
volumes
excluded_volume
members
```

`runtime_source` contains exactly `runtime_head` and `runtime_tree` as
40-character lowercase Git object IDs. `hrh_candidate` and
`effective_images` have exactly the same closed shapes and values as the
published marker. `members` retains the existing exact backup allowlist and
per-member `sha256`, `size`, and `ownership_sha256` shape.

The state archive includes the public immutable trust, receipt, receipt
signature, public key, verification result, and evidence manifest snapshots.
It excludes the Docker configuration and all credentials. The archived marker,
manifest, member allowlist, ownership hashes, completion marker, and external
manifest hash retain the current cold-backup atomicity contract.

### Published init transition

```text
ABSENT
  -> snapshot private registry configuration
  -> validate independent trust and snapshotted reconstructed evidence
  -> verify signature over exact receipt bytes
  -> verify SBOM and provenance outer envelopes for web and migrate
  -> pull exact web and migrate subjects
  -> inspect digest, image ID, RepoDigests, and linux/amd64
  -> delete private snapshot
  -> atomically create state and publish INITIALIZING marker
  -> create owned volumes
  -> start databases
  -> run and await hrh-migrate
  -> on success start web and remaining clinical witnesses
  -> verify status and atomically publish READY
```

Any failure before state mutation leaves the target absent. A failure after
marker publication remains visible under the existing incomplete-lifecycle
recovery rules. A nonzero migration result never starts web or clinical
witnesses.

### Published restore transition

```text
ABSENT
  -> validate backup without trusting its mode assertion alone
  -> require explicit published mode and the three fresh independent inputs
  -> snapshot private registry configuration, trust, and evidence
  -> validate retained evidence and exact receipt-byte signature
  -> verify SBOM and provenance outer envelopes for web and migrate
  -> require exact equality with backup generation identity
  -> pull both exact subjects with the same private snapshot
  -> inspect effective image identity and delete private snapshot
  -> only then publish RECOVERING marker and mutate target resources
  -> restore volumes/state
  -> start databases
  -> run and await hrh-migrate
  -> on success start web and remaining clinical witnesses
  -> verify status and atomically publish READY
```

An existing local image is not authority and never removes the explicit pull.
Failure before `RECOVERING` leaves the target absent. Failure afterward leaves
the target visibly recovering and stops long-running services.

### Published incomplete-state resume

An `initializing` or `finalizing` published marker cannot be resumed by
ordinary `up`. The recovery entrypoint requires explicit
`--hrh-mode published` and the same three fresh inputs required by published
init: independent trust, reconstructed evidence directory, and private Docker
configuration.

Under the init lock it snapshots and reverifies all evidence, explicitly pulls
the same exact web and migrate subjects, and recomputes the closed verification
identity and effective-image objects. Every persisted candidate field,
snapshot hash, verification hash, subject, image ID, RepoDigest, and platform
must match before any further resource mutation. A mismatch fails closed and
leaves the incomplete marker and owned resources available for diagnosis or
destroy. On equality, it deletes the credential snapshot and resumes only the
existing migration-before-web transition appropriate to the persisted state.

### Ordinary published lifecycle

- `up` uses the persisted exact subjects and `docker compose ... --pull never`.
  A missing local image fails closed.
- `status` compares the running web container and completed migration container
  against persisted subject, image ID, RepoDigest, and platform evidence.
- `stop`, `backup`, `destroy`, and TLS paths select Compose files and identity
  solely from the marker.
- No ordinary lifecycle path reads an HRH checkout, accepts registry
  credentials, performs a pull, or silently falls back to source-build.

## Implementation order

The first implementation unit is the repo-independent publication verifier,
not lifecycle integration. It must accept the exact receipt format emitted by
HRH `a96effc`, digest-specific image-retention evidence,
attestation-retention evidence, receipt signature, and reconstructed
evidence-bundle allowlist while retaining all negative controls. Its focused
tests must be GREEN before any marker, Compose-selection, init, or restore code
is changed.

The immediately executable fixture is format-exact but synthetic: it uses a
test key and a valid signature over exact fixture receipt bytes. It proves the
consumer format and cryptographic binding without claiming hosted provenance.
A byte-exact fixture reconstructed from the hosted evidence image can be added
only after A21; it must not be fabricated from local producer outputs.

Only after that compatibility boundary is executable may implementation proceed
to mode parsing, effective Compose proof, published init, marker/status, and
published backup/restore in that dependency order. This prevents lifecycle code
from being built against a hypothetical producer format.

## Acceptance rows

| ID | Executable predicate |
|---|---|
| A01 | Omitted mode on `init` or `restore` selects source-build; parser-optional `--hrh-root` is then required before Docker/Compose. |
| A02 | Published `init` rejects any HRH root argument/environment and every missing, ambiguous, or extra published input before Docker/Compose or mutation. |
| A03 | Ordinary lifecycle commands have no mode option, infer the authoritative mode from the closed marker, and require/reject parser-optional `--hrh-root` accordingly before Docker/Compose. |
| A04 | Only published restore requires explicit mode; every restore rejects a mode/backup-schema mismatch before target mutation. |
| A05 | Effective source Compose contains the source-build overlay and preserves current builds and source context. |
| A06 | Effective published Compose has exactly one HRH overlay, digest-only images, no HRH build/context/source mount/tag/fallback, and `pull_policy: never`. |
| A07 | Published init snapshots Docker config before Cosign, verifies trust, retained evidence allowlist, signature over exact receipt bytes, and four outer role/predicate attestations before state, volume, or service mutation. Receipt, signature, and key have no duplicate CLI paths. |
| A08 | One private Docker-config snapshot serves all Cosign registry verification and both exact pulls; it is deleted before marker publication, then Compose starts only with `--pull never`. |
| A09 | Sentinel credential bytes never enter argv, environment evidence, marker, backup, logs, or public artifacts; normal cleanup and bounded init-lock cleanup remove only run-owned snapshots, including after a simulated `SIGKILL`. |
| A10 | Web and migrate effective subject, image ID, RepoDigest, and platform equal the persisted approved identities. |
| A11 | A nonzero migration prevents web and clinical-witness startup during init and restore. |
| A12 | Published `up` fails closed when an exact local image is absent and never pulls. |
| A13 | Published restore always revalidates fresh independent evidence with a fresh Docker-config snapshot and explicitly pulls; a warm cache cannot satisfy authority. |
| A14 | Source marker, backup schema, source frame, and `built_images` evidence remain unchanged. |
| A15 | Published marker and backup accept exact closed schemas and reject unknown, missing, substituted, or cross-generation fields. |
| A16 | Published backup contains the public generation snapshots and no Docker config, token, credential path, or private key. |
| A17 | Failure before published init verification/pull leaves no target state. After verification/pull, the initializing marker is atomically published before owned volumes are created; later failure remains visibly incomplete. Restore failure before `RECOVERING` leaves the target absent and later failure remains visibly recovering. |
| A18 | Published reset fails closed without changing resources; source reset preserves current behavior. |
| A19 | Real-process source control passes `init -> status -> stop -> backup -> restore -> destroy`. |
| A20 | A real subprocess drives `clinical_staging.py` commands through `verify -> pull -> migrate -> web -> status -> stop -> backup -> restore -> destroy` with no HRH checkout. It may reuse harness primitives, but the environment-variable harness is test-only and is not the operator entrypoint. |
| A21 | Hosted HRH `a96effc` publication status is captured externally; its digest-pinned evidence image is reconstructed with a second clean reader context; its pulled subject equals independently trusted `subjects.evidence`; and its retained bytes are independently verified. |
| A22 | Resume of published `initializing` or `finalizing` requires explicit published mode and three fresh inputs, reverifies and repulls, and refuses any persisted candidate/effective mismatch before further mutation. |
| A23 | Verification result is byte-stable canonical closed identity JSON and contains no timestamp, host, user, source path, Docker-config path, or temporary path. |

## Real entrypoint RED and controls

Before implementation, tests must establish these RED witnesses through the
real CLI/process entrypoint rather than direct helper calls:

1. `init --hrh-mode published` is unavailable.
2. Operator staging cannot select the published overlay.
3. Merged staging plus published Compose retains an HRH build block.
4. The current verifier rejects the exact `a96effc` receipt and does not prove
   its receipt signature.
5. Durable status and restore cannot represent a published generation without
   an HRH checkout.

Controls:

1. Existing source init and full cold lifecycle remain GREEN.
2. Missing/wrong trust, key, signature, role, subject, platform, retention,
   evidence bundle, Docker config, and local image all remain negative.
3. Swapped input files/symlinks after snapshot cannot change verified bytes,
   effective image identity, or emitted hashes.
4. Failed migration proves that neither web nor a clinical witness starts.

Exact test entrypoints:

- `tests/unit/test_clinical_staging_lifecycle.py` — unchanged source control.
- New `tests/unit/test_clinical_staging_hrh_modes.py` — parser, mode authority,
  closed schemas, lifecycle reuse, mutation ordering, and negative controls.
- `tests/unit/test_hrh_published_candidate.py` — exact `a96effc` receipt,
  exact receipt bytes and test-key signature, outer-envelope, trust, snapshot,
  and credential controls. Hosted byte-exact fixture is gated by A21.
- New `tests/unit/test_clinical_staging_backup_modes.py` — unchanged source
  backup control plus published generation/restore identity.
- `tests/deployment/test_clinical_composed_e2e.py` — reusable low-level
  primitives and controls; its environment-variable mode remains test-only.
- `tests/static/test_clinical_staging_surface.py` — effective-overlay ownership:
  common/staging Compose must not define HRH build, while the source overlay
  retains the `BUILD_SHA` build control.
- A real subprocess test that invokes `clinical_staging.py` for every A20
  operator command.
- Effective `docker compose config --quiet` witnesses for both modes.

## File ownership and collision map

| File | Intended ownership | Collision/risk rule |
|---|---|---|
| `deploy/clinical-staging/clinical_staging.py` | Thin parser, mode dispatch, and common lifecycle calls | High-collision integrated lifecycle/TLS file near the file cap; no published verification implementation here. |
| New `deploy/clinical-staging/clinical_hrh_mode.py` | Closed mode identities, Compose selection, acquisition, effective-image proof | New focused owner; no cold-backup codec or generic lifecycle. |
| `deploy/clinical-staging/clinical_backup_bundle.py` | Mode-specific generation serialization and validation | High semantic risk; source v1 path must remain byte-compatible. |
| `deploy/clinical-staging/compose.yaml` | Common staging labels/configuration | Remove only the redundant HRH build stanza; HRH delivery belongs to exactly one mode overlay. |
| `tests/deployment/clinical-composed-e2e/compose.source-build.yaml` | Source HRH delivery | No behavioral change. |
| `tests/deployment/clinical-composed-e2e/compose.published-hrh.yaml` | Published HRH delivery | Preserve digest-only, no-build, `pull_policy: never` contract. |
| `tools/verify_hrh_published_candidate.py` | Repo-independent trust/evidence verification | Supply-chain boundary; update to exact `a96effc`, including receipt signature, without orchestration. |
| New `tests/unit/test_clinical_staging_hrh_modes.py` | Published operator contract | Avoid growing the near-cap lifecycle test file. |
| New `tests/unit/test_clinical_staging_backup_modes.py` | Source control and published backup/restore identities | Do not grow or invent a nonexistent generic backup test module. |
| `tests/unit/test_clinical_staging_lifecycle.py` | Source behavior control | Change only if an assertion must prove exact unchanged behavior. |
| `tests/static/test_clinical_staging_surface.py` | Static Compose ownership and source `BUILD_SHA` control | Invert the current redundant staging-build assertion; assert that only the source overlay owns the build. |
| `tests/deployment/test_clinical_composed_e2e.py` | Test-only primitives and composed control | Reuse its host-pull/image-proof primitives, but do not expose its environment-variable mode as operator behavior. |
| New real-entrypoint subprocess test | A20 durable operator lifecycle | Drive `clinical_staging.py`; do not substitute direct harness/helper calls for CLI proof. |

## Closure predicate

This contract is complete only when:

```text
source-build control is unchanged
AND mode is selected only at init/restore and otherwise marker-authoritative
AND published inputs are closed, independent, snapshotted, and fail-closed
AND the runtime verifies the exact HRH a96effc publication format
AND published effective Compose contains no HRH source/build/fallback
AND exact subjects are pulled and inspected before target mutation
AND every Compose start uses --pull never
AND migration-before-web holds during init and restore
AND marker/backup/restore bind one immutable mode-specific generation
AND web and migrate effective identities match the approved subjects
AND registry credentials never become durable or public evidence
AND source and published real-entrypoint lifecycle witnesses pass
AND a hosted a96effc publication succeeds and its evidence bundle is
    reconstructed and independently verified
```

Until the final hosted-publication clause is demonstrated, the published path
is `NO_GO / evidence-incomplete`, even when synthetic tests pass.

## Nonclaims and no-goals

- No production, PHI, HIPAA, BAA, certification, or compliance claim.
- No Matrix, Mattermost, clinical application, or channel authorization work.
- No cloud, registry, Forgejo, IAM, or KMS mutation by runtime tests.
- No generic artifact-provider, plugin, or deployment framework.
- No mutable tags, anonymous fallback, credential refresh, or cached-image
  authority.
- No Docker config, token, private key, or credential path in durable state.
- No downgrade support for runtimes that do not understand the published
  marker.
- No published reset in v1.
- No change to source-build evidence schemas, ClinicalStaging TLS semantics, or
  cold-recovery failure semantics.
- "Source-free HRH" refers only to HRH web and migration delivery. Runtime and
  controller sources remain part of this repository and deployment.
