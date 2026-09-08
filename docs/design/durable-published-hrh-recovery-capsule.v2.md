# Durable published HRH recovery capsule contract v2

Status: `READY FOR ADVERSARIAL REVIEW`

This contract replaces only the published-HRH backup and restore portion of
`durable-published-hrh-operator.v1.md`. Source-build cold backup v1 remains
byte-compatible. Published init, status, up, stop and destroy retain their v1
contracts unless this document says otherwise.

The reason for this version is concrete: the v1 published backup contract
forbids credentials and private keys in the shareable backup, while the current
runtime needs secrets stored in `compose.env`, `seed/` and ten Docker volumes to
restore the databases, encrypted HRH fields, authenticated outbox, TLS,
Mattermost bot and policy signer. Filtering those bytes makes recovery
non-functional. Keeping their plaintext violates v1 A16.

## Decision and security boundary

Published recovery v2 consists of two separately classified artifacts:

```text
shareable public bundle  --identity and ciphertext hash-->  private age capsule
         ^                                                        |
         +------------- backup_identity_sha256 -------------------+
                                                                  |
                                      external age identity -------+
```

- The **public bundle** contains no runtime credential, token, private key,
  credential path, database payload or secret-bearing volume payload. It may be
  shared as verification evidence.
- The **private capsule** is an age-encrypted artifact whose plaintext preserves
  the complete state archive and every backed-up volume. It is sensitive
  clinical recovery material even while encrypted and is never public evidence.
- The **age identity** is an external recovery authority. It never accompanies
  either artifact and is supplied only through stdin during restore.

For this contract, “the published backup contains no secrets” means the public
bundle contains neither plaintext secrets nor the encrypted private capsule.
It does not mean that encrypted clinical recovery material ceases to be
sensitive.

The first supported mechanism is exactly `age-x25519-v1`. This contract does
not define a provider abstraction, KMS integration or password-based mode.

## Existing surfaces reused

The implementation reuses:

- existing deterministic tar ownership metadata and member hashing;
- atomic per-artifact publication with final `COMPLETE`;
- immutable restore snapshots and run-owned cleanup;
- duplicate-option rejection and explicit path inputs;
- published candidate verification and exact image acquisition; and
- the current cold TLS renewal path after a mechanically valid restore.

The existing local and KMS data-key wrappers wrap small data keys; they are not
whole-archive encryption and must not be presented as such.

## Schemas and compatibility

Exact schemas:

- source bundle: `restricted-synthetic-clinical-cold-backup.v1` (unchanged);
- public bundle: `restricted-synthetic-clinical-cold-backup-published.v2`;
- public identity: `restricted-synthetic-clinical-backup-identity-published.v1`;
- capsule manifest: `restricted-synthetic-clinical-recovery-capsule.v1`;
- recovery trust: `restricted-synthetic-clinical-recovery-trust.v1`;
- published backup receipt:
  `restricted-synthetic-clinical-cold-backup-receipt-published.v1`;
- published mechanical receipt:
  `restricted-synthetic-clinical-cold-restore-published.v1`;
- published causal receipt:
  `restricted-synthetic-clinical-cold-restore-verification-published.v1`.

Published v1 plaintext bundles are recognized only to return
`PUBLISHED_BACKUP_V1_UNSAFE`. They are never extracted, restored or silently
converted. An offline migration procedure, if ever approved, is separate work.

Every JSON object is closed, UTF-8, canonical, newline-terminated and parsed
with duplicate-member rejection. Integers never accept booleans. Unknown,
missing, repeated or non-canonical fields fail before target mutation.
Every control JSON file is at most 1 MiB. Before copying any variable-size
public member or capsule, restore authenticates the bounded public manifest
against the externally supplied expected SHA-256; its declared member sizes
then become the copy bounds.

## Operator inputs

### Published backup

In addition to the normal stopped published target and `--backup-dir`:

```text
--recovery-trust PATH
--recovery-sealer PATH
--recovery-capsule PATH
```

- `--backup-dir` is the final, initially absent public bundle directory.
- `--recovery-capsule` is the final, initially absent private ciphertext file.
- Both parents already exist. Each final artifact and its staging path must be
  on the same filesystem as its own parent so publication is atomic.
- Both parents are operator-owned, non-symlink directories that are not
  group/world writable. The capsule parent is mode `0700`; the public parent
  may be `0700` or `0750` according to its reader group.
- The final capsule is `0600` on POSIX.
- `--recovery-trust` and `--recovery-sealer` are explicit, duplicate-rejecting
  options. No environment alias exists.
- Resolved mutable output/staging roots are disjoint from each other and from
  every immutable input path/root: no equality, aliasing, hard-link alias,
  ancestor or descendant relationship is allowed. In particular, neither the
  public bundle nor capsule can contain, or be contained by, the state
  directory, runtime repository, HRH repository, trust file or sealer.
  Inputs are opened and snapshotted before archive, ciphertext, public-bundle,
  Docker or target effects. Run-owned input snapshots are the only earlier
  output; inode/path swaps and symlinks are rejected within the platform's
  supported identity checks.

### Published restore

Restore retains the fresh HRH publication inputs:

```text
--hrh-trust PATH
--hrh-evidence PATH
--hrh-docker-config PATH
```

and requires:

```text
--recovery-trust PATH
--recovery-sealer PATH
--recovery-capsule PATH
--recovery-identity-stdin
```

`--recovery-identity-stdin` is a boolean declaration. The wrapper reads a
byte- and duration-bounded stdin payload into memory and requires exactly one newline-terminated
native `AGE-SECRET-KEY-1...` record. Blank, comment, additional, SSH,
passphrase-encrypted, plugin and non-ASCII identity forms are rejected. The
exact accepted bytes are piped to `age --decrypt --identity -`; they never
enter argv, an environment variable, a temporary identity file, a marker, a
receipt or retained logs. No Python/OS memory-zeroization claim is made. The
operator is responsible for connecting an authorized external custody source
to stdin.

All v2-only inputs are rejected for source mode and ordinary lifecycle
commands. Published backup or restore without the complete exact input set
fails before Docker, archive creation, decryption or target mutation.

## Recovery trust

`recovery-trust.json` has exactly:

```text
schema
policy_epoch
scheme
sealer_sha256
recipients
```

- `schema` is `restricted-synthetic-clinical-recovery-trust.v1`.
- `policy_epoch` is a positive integer.
- `scheme` is exactly `age-x25519-v1`.
- `sealer_sha256` is the lowercase SHA-256 of the approved regular `age`
  executable.
- `recipients` is non-empty, sorted by `recipient_sha256` and duplicate-free.

Each recipient has exactly:

```text
recipient
recipient_sha256
not_before
not_after
status
```

- `recipient` is one canonical age X25519 recipient line.
- `recipient_sha256` is SHA-256 of its ASCII bytes plus one newline.
- timestamps are UTC `YYYY-MM-DDTHH:MM:SSZ` with second precision and
  `not_before < not_after`.
- `status` is exactly `active`, `retired` or `revoked`.
- backup requires exactly one currently valid active recipient;
- restore accepts the bound recipient only while active or retired and valid;
- revoked always fails before reading the identity or starting decryption; and
- fresh restore policy has `policy_epoch` greater than or equal to the epoch
  bound into the backup.

The sealer source is opened once without following links and must be a regular
file that is not group/world writable. Its already-open bytes are copied to a
run-owned private mode-`0500` snapshot, fsynced and hashed. Only that snapshot
is executed, without PATH lookup, a shell, a TTY or unrelated inherited file
descriptors; the operator path is never reopened. Backup recipient syntax is
validated before private archive construction by a bounded zero-byte
encryption preflight using the snapshotted sealer. This rejects invalid Bech32,
SSH and plugin recipients while retaining the exact `age1...` X25519 scheme.

The sealer child has a bounded timeout and process-group termination policy.
Its environment is an explicit minimal allowlist and contains no credential,
identity, plugin path, proxy or ambient configuration. The wrapper never uses
`age --output`: it opens a run-owned mode-`0600` output with exclusive-create,
connects child stdout only to that file, fsyncs success and deletes the partial
on every nonzero, timeout or exception. Encrypt receives plaintext through
stdin. Decrypt receives the bounded identity through stdin and only a run-owned
capsule snapshot path in argv. Ciphertext or decrypted bytes exist only in
their named run-owned outputs; they are never relayed or logged. Raw child
stderr is suppressed and never retained.

The exact fresh recovery-trust bytes are treated as an already-authenticated
external operator decision. The runtime validates conformance to those bytes;
it does not establish their authorization, trusted time or organizational
anti-rollback. The protected staging filesystem must permit execution of the
verified mode-`0500` sealer snapshot. Pinning or signing the current trust
belongs to the external deployment gate.

## Public bundle

The exact public directory allowlist is:

```text
COMPLETE
backup-identity.json
backup-manifest.json
public-evidence.tar
recovery-trust.json
```

It contains no `state.tar`, volume archive, capsule ciphertext, Docker config,
age identity, private key, credential, token or private filesystem path.

### Public identity

`backup-identity.json` has exactly:

```text
schema
project
state_id
compose_env_sha256
runtime_source
hrh_candidate
effective_images
volumes
excluded_volume
capsule_id
recipient_sha256
recovery_policy_epoch
recovery_trust_sha256
sealer_sha256
```

The runtime, candidate, image and volume shapes retain the closed published-v1
forms. `runtime_source.runtime_head` and `runtime_source.runtime_tree` are
40-character lowercase Git object IDs. `capsule_id` is 32 lowercase random hex
characters. `state_id` is a non-secret stable identity; no `state_dir` path is
recorded. Canonical public-identity bytes define
`backup_identity_sha256`.

### Public evidence

`public-evidence.tar` contains exactly the verifier-owned `EVIDENCE_FILES` plus
the verifier-required `SHA256SUMS.json`, and the runtime-owned `trust.json` and
`verification.json`, with deterministic names and metadata. The runtime imports
or is passed the verifier-owned constant and adds only its two named files; it
does not maintain a second sample of the verifier list. Secret canaries and
private paths are prohibited.

### Public manifest

`backup-manifest.json` has exactly:

```text
schema
synthetic_only
complete
backup_identity_sha256
recovery_trust_sha256
public_evidence
recovery_capsule
members
```

`synthetic_only` and `complete` are true. `public_evidence` has exactly
`sha256`, `size` and `ownership_sha256`. `recovery_capsule` has exactly
`capsule_id`, `ciphertext_sha256` and `ciphertext_size`.

`members` contains exactly `backup-identity.json`, `public-evidence.tar` and
`recovery-trust.json`, each with `sha256`, `size` and `ownership_sha256`.
`COMPLETE` is exactly `b"complete\n"` and is published last.

All duplicated authorities are equality constraints, never fallbacks:

- actual recovery-trust bytes, identity `recovery_trust_sha256`, manifest
  `recovery_trust_sha256` and the trust member hash are identical;
- actual public-identity bytes and manifest `backup_identity_sha256` are
  identical;
- `public_evidence` equals `members["public-evidence.tar"]` field for field;
- actual public-evidence bytes equal those hashes and sizes; and
- capsule ID, ciphertext hash and ciphertext size equal every corresponding
  public-identity, public-manifest and final-file value.

Any disagreement fails before identity input, decryption, pull or target
mutation.

The public identity intentionally omits the ciphertext hash. The capsule
manifest binds to the already-canonical public identity; the later public
manifest binds both. This avoids a circular hash.

## Private capsule

The final capsule is one binary age ciphertext. Its plaintext is a
deterministic tar with exactly:

```text
capsule-manifest.json
state.tar
volumes/<each BACKED_UP_VOLUME_KEYS entry>.tar
```

`capsule-manifest.json` has exactly:

```text
schema
capsule_id
backup_identity_sha256
project
state_id
compose_env_sha256
members
```

`members` contains exactly `state.tar` and the complete frozen volume set, each
with `sha256`, `size` and `ownership_sha256`.

Bindings are transitive and independently recomputed:

1. private member bytes bind to the capsule manifest;
2. capsule-manifest `backup_identity_sha256`, `capsule_id`, `project`,
   `state_id` and `compose_env_sha256` exactly equal the public identity, and
   its volume member names exactly equal the frozen public volume set;
3. public manifest binds the public identity and final capsule ciphertext; and
4. public identity binds the approved runtime/candidate generation, recovery
   trust, recipient and capsule ID.

Mixing artifacts, generations, recipients or manifests fails before target
mutation even when an attacker reseals inner hashes they control.

## Backup transition

Under the existing persistent operator lock:

1. reread the authoritative marker and require exact `stopped` state;
2. prove cold quiescence;
3. snapshot recovery trust once and validate policy, time, active recipient and
   sealer bytes;
4. create a run-owned private staging directory (`0700`);
5. create the existing state and volume archives in that staging directory;
6. create and validate the exact public evidence tar;
7. write the canonical public identity;
8. write the capsule manifest and deterministic private plaintext tar;
9. stream the private plaintext tar through stdin to the snapshotted sealer and
   stream stdout into a wrapper-opened exclusive temporary capsule;
10. fsync the ciphertext, compute hash/size, atomically rename it to the final
    capsule and fsync its parent;
11. create the temporary public bundle and bind the final ciphertext;
12. write and fsync manifest, then `COMPLETE`;
13. atomically rename the public bundle and fsync its parent;
14. delete run-owned plaintext and temporary paths; and
15. emit a content-safe receipt only after both final artifacts exist and
    revalidate.

There is no atomic rename spanning two filesystems. The enforced invariant is:
a public bundle with valid `COMPLETE` never references a partial capsule.

Publication exposes the following content-safe stage IDs to the test-owned
observation pipe: `CAPSULE_CIPHERTEXT_FSYNCED`, `CAPSULE_PUBLISHED`,
`CAPSULE_PARENT_FSYNCED`, `PUBLIC_MANIFEST_FSYNCED`,
`PUBLIC_COMPLETE_FSYNCED`, `PUBLIC_PUBLISHED` and
`PUBLIC_PARENT_FSYNCED`. They carry no path or secret bytes.

The test seam is dependency-injected into the Python entry point only; it has
no production CLI, environment or configuration surface. At a selected stage
it writes the stage ID, flushes, then blocks until the parent test kills the
real subprocess. This acknowledgement makes each SIGKILL boundary
deterministic without allowing the child to cross the next publication stage.

An ordinary exception before public completion removes only final or temporary
capsules created by that invocation and all run-owned plaintext. `SIGKILL` or
host loss can leave a private plaintext staging directory or an encrypted
orphan. The next operator command performs bounded, ownership-checked cleanup
of its own non-final stale staging paths. It never discovers or deletes final
capsules by scanning.

If the exact requested final capsule exists without a complete public bundle,
retry returns `RECOVERY_CAPSULE_ORPHANED` before mutation or overwrite. Recovery
is an explicit operator choice: retain/move that exact artifact for forensic
handling and select a new absent capsule path, or delete that exact path after
confirming no complete public manifest references its hash. The runtime never
makes that decision. No secure-erase claim is made. Capsule and staging storage
must therefore be protected as sensitive storage by the host profile.

## Restore transition

Under the same persistent lock:

1. require an absent/empty target; open `COMPLETE` and the bounded public
   manifest without following links; authenticate the manifest bytes against
   the expected external hash; parse them canonically and validate the exact
   public allowlist before copying variable-size input;
2. open every declared public member and the capsule without following links,
   require initial regular-file size to equal the authenticated declared size,
   and copy exactly that many bytes into exclusive run-owned snapshots while
   hashing; growth, truncation, trailing bytes or metadata change fails and
   removes the partial; snapshot the bounded fresh recovery trust, HRH
   trust/evidence and Docker config under their existing validators;
3. validate public `COMPLETE`, every copied public hash/size, canonical JSON
   and duplicate rejection; compare archived and fresh recovery policies;
   reject epoch rollback,
   revoked/invalid recipient and sealer mismatch before reading stdin;
4. verify capsule hash and size before reading stdin;
5. reverify fresh HRH publication evidence, explicitly pull both approved
   images and inspect exact identities even with a warm cache;
6. require exact equality with the public backup generation;
7. delete the Docker-config snapshot and fsync its staging parent before
   identity input, decryption or target mutation; later cleanup is idempotent;
8. validate one bounded native X25519 identity record, pipe it to the
   snapshotted sealer, and stream decrypted stdout into a wrapper-opened
   exclusive private output;
9. validate the private tar, capsule manifest, member hashes, ownership and all
   public/private bindings;
10. validate the restored marker duplicate-free and equal to the public
   identity; validate `compose.env` and every volume archive before target
   mutation;
11. close the identity pipe and retain no identity bytes;
12. atomically publish `recovering` before the first target volume;
13. create and restore volumes, start databases, run migration, then start web
    and clinical witnesses;
14. verify effective state, publish `ready` and write only the bound mechanical
    receipt; the separate `finalize-cold-recovery-verification` command writes
    a causal receipt only after all external causal checks pass; and
15. clean every run-owned plaintext, capsule snapshot, already-absent Docker
    snapshot and input snapshot.

Image-cache acquisition is the only allowed pre-target side effect. No target
state directory, volume, network or service exists before `recovering`.

## Closed failures

| Condition | Required result |
|---|---|
| Published v1 bundle | `PUBLISHED_BACKUP_V1_UNSAFE`, no extraction |
| Missing capsule | `RECOVERY_CAPSULE_MISSING`, before stdin/pull/mutation |
| Missing identity declaration or unusable stdin fd | `RECOVERY_IDENTITY_REQUIRED` before decrypt |
| Identity stdin does not complete within its bounded read deadline | `RECOVERY_CAPSULE_UNAVAILABLE` before decrypt |
| Recipient not yet valid or expired | `RECOVERY_RECIPIENT_NOT_YET_VALID` / `RECOVERY_RECIPIENT_EXPIRED` |
| Recipient revoked | `RECOVERY_RECIPIENT_REVOKED`, before stdin |
| Fresh policy epoch lower | `RECOVERY_POLICY_ROLLBACK` |
| Missing/substituted sealer | `RECOVERY_SEALER_UNTRUSTED` |
| Sealer timeout or forced process-group termination | `RECOVERY_SEALER_UNAVAILABLE`, partial output removed |
| Wrapper exclusive-output open finds an existing path | `RECOVERY_OUTPUT_EXISTS`, child not started |
| Requested final capsule exists without a complete matching public bundle | `RECOVERY_CAPSULE_ORPHANED`, no overwrite |
| Ciphertext hash/size mismatch | `RECOVERY_CAPSULE_MISMATCH` |
| Empty, malformed, additional or wrong identity; age authentication failure against exact authorized ciphertext | one `RECOVERY_CAPSULE_UNAVAILABLE` |
| Invalid inner tar/manifest/member | `RECOVERY_CAPSULE_INVALID` |
| Public/private generation mismatch | `RECOVERY_GENERATION_MISMATCH` |

The runtime never relays age diagnostics. Child stdout is consumed only by the
named private wrapper output. Operator output exposes stable stage/error codes;
receipts contain only their exact declared public and bound fields below.

## Rotation, revocation and rollback ceiling

To rotate, the operator adds a new active recipient, retires the old one,
increments `policy_epoch` and creates a new backup. An old capsule remains
restorable through its bound retired recipient only while that recipient is
valid and not revoked. Revocation increments the epoch and destroys or disables
the external identity. Existing capsules are never silently rewrapped.

For the recipient bound into an existing backup, fresh trust must preserve the
exact recipient bytes, `recipient_sha256`, `not_before` and `not_after`; it
cannot extend the archived validity window. Fresh `policy_epoch` is not lower,
schema/scheme/sealer are unchanged, and the only allowed status transitions are
`active -> active`, `active -> retired` and `retired -> retired`. Any transition
to `revoked`, any removal, or any other field change makes restore fail before
identity input. Additional recipients are allowed only in canonical order with
unique hashes and exactly one fresh active recipient; they confer no authority
over the capsule bound to another recipient.

Loss, expiry or revocation of the only usable identity makes that capsule
deliberately unrestorable.

The fresh trust file and external expected manifest hash are operator
authorities. Without a monotonic external checkpoint, trusted time or signed
generation allowlist, this contract does not claim organizational anti-rollback.

## Receipt correction

The receipt defect is independently closable. A successful published backup
emits a receipt with exactly:

```text
schema
synthetic_only
project
state_id
mode
manifest_sha256
backup_identity_sha256
capsule_id
capsule_ciphertext_sha256
capsule_ciphertext_size
backup_recovery_trust_sha256
backup_recovery_policy_epoch
recipient_sha256
sealer_sha256
runtime_source
hrh_candidate
effective_images
excluded_volume
backed_up_at
nonclaims
```

It contains no bundle/capsule path, credential, private member name or
unencrypted claim. Its manifest/identity/capsule/trust/recipient/sealer and
generation fields equal the final public bundle and capsule bytes revalidated
after publication.

The published mechanical restore receipt has exactly:

```text
schema
synthetic_only
project
state_id
mode
manifest_sha256
backup_identity_sha256
capsule_id
capsule_ciphertext_sha256
backup_recovery_trust_sha256
backup_recovery_policy_epoch
restore_recovery_trust_sha256
restore_recovery_policy_epoch
restore_recipient_status
recipient_sha256
runtime_source
hrh_candidate
effective_images
excluded_volume
status_observed_at
verification
restored_at
nonclaims
```

The published causal receipt has exactly:

```text
schema
synthetic_only
project
state_id
mode
manifest_sha256
mechanical_receipt_sha256
backup_identity_sha256
capsule_id
capsule_ciphertext_sha256
backup_recovery_trust_sha256
backup_recovery_policy_epoch
restore_recovery_trust_sha256
restore_recovery_policy_epoch
restore_recipient_status
recipient_sha256
runtime_source
hrh_candidate
effective_images
verification
causal_checks
verified_at
nonclaims
```

The receipt rules are:

- source mechanical and causal receipts remain byte-compatible;
- a published causal receipt requires a closed published mechanical receipt;
- `mechanical_receipt_sha256` is recomputed from the exact retained canonical
  mechanical bytes;
- backup recovery trust hash/epoch equal the public backup identity and
  manifest; restore recovery trust hash/epoch equal the exact fresh trust bytes
  that authorized restore; `restore_recipient_status` equals the bound
  recipient's status in that fresh trust; both authority pairs remain distinct
  after rotation;
- every other repeated project, state, manifest, identity, capsule,
  recipient, runtime, candidate and effective-image field equals the public
  bundle, current marker and mechanical receipt before writing the causal
  receipt;
- each receipt's `mode` equals its own operation-specific constant below and
  is not copied from the bundle, marker or preceding receipt;
- mechanical `verification` is exactly `mechanical_restore_only`; causal
  `verification` is exactly `causal_e2e_verified`; `causal_checks` is exactly
  the existing closed check set with every value true;
- published receipts use only their published schemas; and
- cross-mode, minimal, duplicate-member and substituted receipts fail before a
  `verified-restore-*` artifact is written.

### Causal-finalization authority

Published-v2 causal finalization does not trust the retained mechanical receipt
by filename or content alone. In addition to the closed causal-check set, its
CLI/method boundary requires exactly:

```text
--backup-dir PATH
--expected-manifest-sha256 HASH
--expected-mechanical-receipt-sha256 HASH
```

The restore result exposes the mechanical receipt SHA-256 as public output for
independent operator custody. Finalization snapshots and revalidates the exact
public bundle against the expected manifest hash, validates the current
published marker, reads the exact retained mechanical bytes with duplicate
rejection, and requires their recomputed hash to equal the independently
supplied expected mechanical hash. It then enforces every bundle/marker/
mechanical equality above before constructing the causal receipt. The causal
`mechanical_receipt_sha256` is that recomputed and externally expected value.

Missing, extra or duplicate finalizer inputs; a missing, substituted or
cross-mode bundle; a mechanical hash mismatch; or any field mismatch fails
before a causal artifact is created. The finalizer does not require the private
capsule, recovery identity, Docker configuration or a KMS/IAM call.

For every published receipt, `synthetic_only` is true; hash strings are
lowercase 64-character SHA-256 values; epochs and ciphertext size are positive
integers that do not accept booleans; timestamps are UTC
`YYYY-MM-DDTHH:MM:SSZ`; `restore_recipient_status` is `active` or `retired`;
shared nested runtime/candidate/image shapes retain their closed v1
definitions; and these operation-specific values are exact, not free text:

| Receipt | `mode` | `nonclaims` |
|---|---|---|
| Backup | `published_backup` | `not a scheduled backup`; `not PHI-authorized`; `not production`; `not a compliance certification` |
| Mechanical restore | `published_restore` | `not a causal recovery verification`; `not PHI-authorized`; `not production`; `not a compliance certification` |
| Causal restore | `published_restore_verification` | `not PHI-authorized`; `not production`; `not a compliance certification` |

This correction may land with the integrated v2 implementation, but its
justification and tests remain separate from capsule confidentiality.

## Acceptance matrix

| ID | Executable closure predicate |
|---|---|
| B01 | Source-v1 golden fixtures, frozen clock and normalized paths preserve exact bytes, schemas and results; every v2 flag in source mode fails before effects. |
| B02 | Published backup/restore reject every missing, extra or duplicate option before Docker/archive/decrypt/mutation. |
| B03 | Recovery trust rejects non-canonical, missing, extra or duplicate fields/recipients, SSH/plugin/invalid-checksum recipients and invalid time/status cardinality. |
| B04 | Backup rejects an untrusted sealer and any active recipient outside its validity window; post-open operator-path substitution cannot alter the trusted hash or executed bytes because both use one private snapshot copied from the already-open source. |
| B05 | Public bundle has exactly five members and no secret/path canary. |
| B06 | Public evidence contains exactly verifier `EVIDENCE_FILES` plus `SHA256SUMS.json`, then runtime `trust.json` and `verification.json`, and nothing else. |
| B07 | Decrypted capsule has exactly manifest, state and frozen volume members; all duplicated capsule/public project, state, Compose-environment, identity and capsule fields are equal. |
| B08 | Secret canaries exist in private fixtures and the private Compose runtime environment but never in the public bundle, argv, retained/public environment evidence, output or logs. |
| B09 | With the independently custodied expected manifest hash and fresh trust fixed, every public/private/candidate/capsule substitution fails even after bundle-internal hashes are resealed. |
| B10 | Final capsule precedes public `COMPLETE`; success receipt follows both final revalidations. |
| B11 | Exception failpoints at every named publication stage leave no public partial or run-owned plaintext. |
| B12 | A real subprocess is SIGKILLed at observable capsule/public boundaries; the next invocation removes only owned non-final staging and returns `RECOVERY_CAPSULE_ORPHANED` for an exact final orphan without overwriting or deleting unrelated paths. |
| B13 | Missing or mismatched capsule fails before stdin, pull and target mutation; manifest authentication and declared sizes bound every public/capsule snapshot before variable-size bytes are copied. |
| B14 | Missing declaration/unusable stdin returns `RECOVERY_IDENTITY_REQUIRED`; empty, stalled beyond the read deadline, multi-record, SSH, encrypted, plugin or malformed identity input returns `RECOVERY_CAPSULE_UNAVAILABLE`, all before target mutation. |
| B15 | Outer byte/size mismatch returns `RECOVERY_CAPSULE_MISMATCH` before stdin; any nonzero age decrypt exit other than timeout or forced termination reached after an outer hash/size match returns `RECOVERY_CAPSULE_UNAVAILABLE`, with a wrong well-formed identity as the real-process witness and a controlled nonzero child for generic diagnostic suppression; existing output prevents child start. |
| B16 | A not-yet-valid, expired, revoked or removed bound recipient, a lower policy epoch, or a forbidden trust-field/status transition fails before identity bytes are read. |
| B17 | Traversal, link, special, duplicate, extra or missing tar member fails pre-mutation. |
| B18 | Duplicate JSON members fail in trust, public manifest/identity, capsule manifest and restored marker. |
| B19 | Restore performs fresh publication verification, pull and inspect despite a warm cache. |
| B20 | HRH generation mismatch fails before decrypt and target mutation. |
| B21 | Successful age decrypt cannot bypass inner identity/member validation. |
| B22 | Real subprocess restores on a distinct state path without an HRH checkout or preexisting HRH web/migrate images; pinned third-party and locally built clinical images are explicit preconditions. |
| B23 | `recovering` precedes the first volume; later failure remains visible and non-operational. |
| B24 | Migration failure never starts HRH web or clinical witnesses. |
| B25 | Backup emits the exact content-safe published backup receipt; restore success reaches `ready`, emits only a bound mechanical receipt plus its public SHA-256 and removes run-owned snapshots/plaintext; the separate causal finalizer requires the revalidated public bundle and independently custodied expected mechanical hash. |
| B26 | Exact trust comparison demonstrates allowed active/retired transitions, no validity-window extension, revoked/removal rejection and lost-identity fail-closed behavior; receipts bind archived backup trust and fresh restore authority separately. |
| B27 | Published v1 returns `PUBLISHED_BACKUP_V1_UNSAFE` without opening `state.tar`. |
| B28 | Source-v1 and published-v2 schema substitution fails before mutation. |
| B29 | A sealer hang is terminated as a process group within the bounded timeout, produces only `RECOVERY_SEALER_UNAVAILABLE`, leaves no output/plaintext partial, and does not relay child diagnostics. |
| R01 | Source receipt golden fixtures remain byte-identical under frozen clock/path inputs. |
| R02 | Closed published receipts bind exact revalidated bundle/current marker/mechanical bytes through the independently supplied and recomputed `mechanical_receipt_sha256`, preserve distinct backup-trust and fresh-restore-authority hashes/epochs/status across rotation, and require independent finalization. |
| R03 | Mutants that hard-code source `BACKUP_SCHEMA` or substitute the mechanical receipt are killed. |

## Planned implementation footprint

- New `deploy/clinical-staging/clinical_recovery_capsule.py`: recovery trust,
  pinned age boundary, capsule codec and private cleanup.
- `deploy/clinical-staging/clinical_backup_bundle.py`: published-v2 public
  identity/manifest only; source-v1 output remains unchanged.
- `deploy/clinical-staging/clinical_staging.py`: duplicate-rejecting orchestration
  and parser wiring. It remains at or below 2,000 lines through cohesive
  extraction, never formatting compression.
- New `tests/unit/test_clinical_recovery_capsule.py`: trust, age boundary,
  bindings, leak scans and mutations.
- `tests/unit/test_clinical_staging_backup_modes.py`: lifecycle, publication,
  compatibility and v1 refusal.
- A real-process cross-path/cross-host-layout E2E after unit closure.

No Compose change is required by this contract.

## Deferred operator decisions and external gates

Implementation and synthetic local proof do not require KMS/IAM. A real
deployment later requires the operator to provide:

1. an age X25519 recipient and independently custodied identity;
2. the exact trusted age executable and its SHA-256 on backup and restore hosts;
3. validity, retention, retirement and revocation policy;
4. distinct destinations and access controls for the public bundle and private
   capsule; and
5. a protected host staging boundary appropriate for sensitive plaintext.

These are requested only when the corresponding deployment task begins.

## Non-goals

- KMS, IAM, cloud secret providers or provider-specific adapters;
- password-based encryption or custom cryptographic envelopes;
- capsule discovery, transport, replication, pruning or scheduled backup;
- automatic rewrap/rekey or conversion of published v1 plaintext bundles;
- application-by-application DB, field, outbox, bot, policy or TLS rekey;
- padding or ciphertext-size concealment;
- Python/OS memory zeroization or physical secure erase;
- anti-rollback without an external monotonic authority;
- PHI use, production authorization, HIPAA/BAA or certification claims; and
- any source-v1 byte or behavior change.
