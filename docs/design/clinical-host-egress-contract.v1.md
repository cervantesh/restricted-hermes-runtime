# Clinical host and operator-proxy egress contract v1

## Frame, scope and status

**Contract:** `restricted-clinical-host-egress-contract.v1`.
**Inspected source:** `4aa366adfb09cf8d230dce92ff98eb12dcc9029b`.
This is a documentary contract, not an implementation or an observed host PASS.
It refines platform rows P1/P2/P4 and host observations H02/H04/H05/H06/H08/H12
in the [readiness ledger v2](../assessment/phi-readiness-acceptance-ledger.v2.md).
That frozen ledger and its closed assessment profile are not modified here.

The current candidate is the deterministic clinical-staff `next-appointment`
command over Mattermost, the clinical adapter and HRH. It makes zero model
calls. This contract covers the selected Linux/Docker deployment boundary,
including its operator access proxy, not every process on the operator's host.
Application subjects remain `linux/amd64` under the existing published contract.
All drills use owned, isolated synthetic destinations and non-PHI fixtures.

- **FROZEN:** the predicates, row IDs and documentary witness schema below.
- **PROVISIONAL:** collectors and enforcement mechanism; no host firewall,
  privileged helper, new cloud service or vendor is implemented/selected here.
- **MISSING:** exact-candidate local evidence has not been produced for this
  contract. Inspected older tests do not count as a fresh pass.
- **BLOCKED:** effective-host evidence requires an accessible selected host,
  explicit bounded operator action and its baseline inventory.
- Missing or blocked observations export as `NOT_VERIFIED`; machine outcomes
  remain the ledger's `PASS`, `FAIL`, `NOT_VERIFIED`, `NOT_APPLICABLE` lattice.
  `EXTERNALLY_ACCEPTED` is a separate risk decision, never technical PASS.

## Existing implementation and its limit

All locations refer to the inspected source above, not a moving branch.

| Existing surface | Exact location | Reuse / limit |
|---|---|---|
| Inbound TLS passthrough | `deploy/clinical-staging/nginx-stream.conf:9` | Fixed `mattermost:8065` upstream; this is not an outbound filtering proxy |
| Sole loopback publisher and non-internal exception | `deploy/clinical-staging/compose.yaml:11`, `:50` | Proxy alone joins `operator_access`; the four core networks are internal |
| Effective membership and publisher checks | `deploy/clinical-staging/clinical_staging.py:696`, `:749` | Reuse actual Docker inspection; topology alone does not prove host egress policy |
| Sealed Compose environment | `deploy/clinical-staging/clinical_staging.py:63`, `:906` | Reuse environment isolation; ordinary proxy variables are not inherited |
| Bounded egress policy inventory | `tools/representative_clinical_egress.py:33` | Only ingress and adapter, not the proxy or full host boundary |
| Network-namespace probes | `tools/representative_clinical_egress.py:488`, `:624`, `:650` | Reuse positive/negative controls; helper execution is not application-transport proof |
| Proxy and metadata checks | `tools/representative_clinical_egress.py:456`, `:32` | Absent environment is not attempted proxy-route denial; metadata timeout is not PASS |
| Real-path composition | `tests/deployment/test_clinical_composed_e2e.py` | Preserve clinical success and zero unauthorized disclosures in both modes |

No clinical host-firewall implementation was found in this source. Host
operator + verifier remain the A6 producers; no named operator is invented.

## Closed route profile

The effective profile must preserve these initiated application routes. Replies
to an approved established connection are not new outbound authority.

| Initiator | Approved destination / purpose |
|---|---|
| Operator client | Existing `127.0.0.1:<selected staging port>` TLS listener only |
| `operator-proxy` | Mattermost TCP 8065; reply traffic to its approved inbound connection |
| `mattermost` | `mattermost-postgres` TCP 5432 |
| `hrh` | `hrh-postgres` TCP 5432 |
| `hrh-tls` | `hrh` TCP 8080 |
| `clinical-adapter` | `hrh-tls` TCP 8443; existing ingress-facing Unix socket |
| `ingress` | Mattermost TCP 8065 REST/WebSocket; existing clinical Unix socket |
| Both database services | No independently initiated application egress |
| `hrh-migrate` | HRH database only, during the existing successful one-shot prerequisite |
| Provisioner / socket initializer | Existing bounded provisioning lifetime and mounts; no new operational network authority |

Internal service-name resolution is permitted only as needed for these routes.
External DNS resolution, arbitrary IP literals, metadata access, telemetry,
media downloads, alternate proxies and other initiated application destinations
are denied. The proxy's non-internal network is an explicit enforcement target,
not a waiver. No general forward-proxy or CONNECT capability is introduced.

Image pulls, trusted evidence retrieval, package maintenance, time service and
operator management are a **separate host-management inventory**. They must not
be silently inherited by an application. This contract neither grants new
management destinations nor requires globally disabling unrelated host traffic.
An operator must identify the actual processes/principals/namespaces, approved
existing paths and enforcement attachment before a host witness can pass.

## Closure predicates

1. **E1 identity:** requested and effective candidate, mode, policy and workload
   generation agree before and after observation; stale or mixed evidence fails.
2. **E2 function:** approved clinical and loopback TLS paths still work. A policy
   that blocks the clinical feature cannot pass merely because all negatives fail.
3. **E3 reachability:** controlled IPv4, IPv6, DNS and literal-IP alternatives are
   denied from the effective deployment boundary, including the proxy exception.
   Each negative has an independent working positive control. Enforced IPv6
   disablement is valid evidence; a missing IPv6 test is not `NOT_APPLICABLE`.
4. **E4 auxiliaries:** proxy-environment attempts and content-free metadata
   reachability checks cannot create an alternate application route. No metadata
   credentials or response body are collected.
5. **E5 attribution:** a dead sink, resolver failure, probe crash or ambiguous
   timeout cannot be accepted as an enforcement deny. Record effective policy
   readback and the attributable outcome, not just desired Compose text.
6. **E6 lifecycle:** enforcement exists before operational admission and survives
   the selected restart boundary. Installation failure or incomplete readback
   prevents operational readiness. Controlled mutations never open a running
   candidate to unrelated external destinations.
7. **E7 custody:** exact witness bytes, scope, producer/run and host baseline are
   retained and independently verified. Container evidence cannot fill A6 host
   observations. Partial coverage leaves those observations `NOT_VERIFIED`.

## Identity, artifact and mode contract

`K` retains its ledger-v2 meaning: five source SHAs (including independent HRH
C/H), four role-specific OCI digest subjects, policy epoch/digest and producer,
run, toolchain and host IDs. A source-build fixture still records its exact tree
and local image identities, but missing published subjects prevent it from
being promoted to a published K-bound witness.

`candidate_manifest_sha256` pins an immutable **pre-observation input** manifest,
not the later A6/A10P/A10F output containing this witness. It may not reference
these generated witness bytes/hashes. Keep the input manifest available in the
retained candidate handoff; final assessment consumers can reference the result
without making generation identity self-referential.

The exact mode enum is **`source-build|published`**. Reject `source`, aliases,
case changes and unknown values; the same enum applies to the witness and both
generation files. This matches `test_clinical_composed_e2e.py:28` and `:87`.

Retain **`platform/generation.before.json`** and
**`platform/generation.after.json`** in every conforming witness. Each is a
canonical `restricted-clinical-platform-generation.v1` object with exactly:
`schema`, `mode`, `candidate_id`, `policy`, `compose_sha256`, `resolver_sha`,
`project`, `state_id`, `host_baseline_sha256`, `enforcement_sha256`, `workloads`.
`policy` contains exactly `epoch` and `digest`, equal to the pinned candidate's
policy (normalize its digest to bare lowercase SHA-256, not its epoch).
`candidate_id` is `sha256:` followed by 64 lowercase hex digits and equals the
pinned candidate manifest's independently verified canonical candidate ID.
`resolver_sha` is an exact 40-character lowercase Git SHA. Project/state IDs
are opaque `[A-Za-z0-9_-]{1,64}` strings, never personal identifiers.

Workloads are uniquely sorted by `service` and match the frozen effective
inventory. Each record has exactly `service`, `container_id`, `image_id`,
`image_digest`, `started_at`, `networks`. Container IDs are 64 lowercase hex
digits; image IDs/digests are `sha256:` plus 64 lowercase hex digits. A locally
built subject may have null `image_digest` in `source-build` only; published
roles require their exact pinned digest. `started_at` is a valid UTC timestamp
normalized to `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`. Networks are uniquely sorted
records with exactly `network_id` (64 lowercase hex), `name_sha256` (bare hash)
and `internal` (JSON boolean), matching effective Docker readback. Required
fields cannot be omitted just because a service is unhealthy.

Canonical JSON means UTF-8 without BOM, sorted object keys, compact separators
`,` and `:`, ASCII JSON escapes, no floats/NaN/duplicate keys, and exactly one
final LF. A consumer reserializes and requires byte equality before hashing.
`G_before`/`G_after` are SHA-256 of those exact retained bytes. A generated hash
without the underlying file is not a generation witness. Compare the decoded
identity with the pinned candidate/mode and retained actual readback; a matching
hash alone cannot establish that the contents describe the running candidate.

The witness's `generation` has exactly `operation`, `before_sha256`,
`after_sha256`, `parent_sha256`; `operation` is `observe` or `restart`.
Recompute both hashes from the declared files and require exact equality to
these fields and their `witness_files` entries. `observe` requires byte-identical
before/after files and null parent: a changed identity needs another witness,
not a silent exception. `restart` requires `parent_sha256 == before_sha256`.
A row claiming successful restart also requires `after_sha256 != before_sha256`
and changed start/container identity for the restarted workload, while mode,
candidate, policy, Compose, resolver, host baseline and enforcement remain
equal. A failed restart may retain the same generation but cannot satisfy a
successful-recovery row; its retained proof must show the expected failure.
Deliberate invalid-identity inputs are mutation proof files, not replacements
for the valid enclosing witness frame. Missing actual generation identity means
no conforming witness can be issued; the ledger retains `NOT_VERIFIED` without
fabricating generation files or hashes.

**Canonical supporting artifact:** `platform/egress-witness.v1.json`;
documentary schema `restricted-clinical-egress-witness.v1`. Exact root fields:
`schema`, `scope`, `contract_sha256`, `candidate_manifest_sha256`, `mode`,
`producer`, `host_baseline_sha256`, `generation`, `observations`, `witness_files`.
`scope` is `SYNTHETIC_NON_PHI_ONLY`; SHA-256 fields use 64 lowercase hex digits.
`producer` has `id`, `run_id`, `engine`, `toolchain_sha256`; `generation` follows
the retained-byte rules above.
An observation has exactly `id`, `outcome`, `diagnostic`, `proof_sha256s`.
IDs are the uniquely sorted acceptance-row IDs below; missing work remains an
explicit `NOT_VERIFIED` observation with no invented proof hash.
`witness_files` is a uniquely sorted list of relative `path`, `sha256`, `size`,
`media_type`; reject traversal, links, duplicate paths and undeclared bytes.
Both generation files are mandatory declared members. Recompute every member's
byte length and SHA-256; `size` is an integer from 1 through 1,048,576, not a
boolean. Every `proof_sha256s` entry must resolve to declared retained file bytes
whose recomputed hash matches, not an arbitrary or external unresolved hash.
An observation's PASS or FAIL requires 1..64 unique sorted proof hashes,
including row-specific result evidence beyond the generation files. The file
contents must actually prove that row's positive or negative effect; cardinality
alone is insufficient. `NOT_VERIFIED` requires exactly `proof_sha256s: []` and
a missing/unobserved diagnostic. No row here permits `NOT_APPLICABLE` as a
waiver. A failed validation mutation can be a passing test only when its proof
records the expected rejection. Neither the root witness nor any file containing
its hash can be its own proof; the retained-byte graph must be acyclic.

Diagnostics are closed: `none`, `identity-mismatch`, `approved-route-failed`,
`unexpected-route`, `ambiguous-denial`, `proxy-route`, `metadata-route`,
`enforcement-incomplete`, `witness-unavailable`, `host-not-observed`.
`none` is used only for a demonstrated PASS; a missing host produces
`NOT_VERIFIED/host-not-observed`. Errors contain no payload, credential,
hostname, connection string or raw command output. Restricted raw configuration
readback may be retained separately by the operator; its safe witness is hashed.

This artifact lives in retained supporting evidence, **outside** A10P/A10F's
closed file inventory. Producer: platform-control runner + operator; consumer:
independent verifier and A6 curator. Existing bundle observation fields refer
to independently checked witness hashes; no new keys are added to A6/A7.
The new parser/collector is PROVISIONAL and absent at this base. A complete
schema/parser plus full acceptance delivery is required before these bytes
can be called machine-verified evidence.

## Local executable acceptance matrix

`U` = planned `tests/unit/test_clinical_host_egress_contract.py`;
`D` = planned `tests/deployment/test_clinical_host_egress_contract.py`.
Both files are absent at the inspected base. Each name below is a required
executable test, not a claim of existing coverage. `Py`/`Docker` have their
ledger meanings. All rows produce the supporting artifact above; all are
**MISSING**. Contract/schema is FROZEN; implementation is PROVISIONAL.

| ID / predicate | Setup and bounded mutation | Required observable | Exact test | Engine |
|---|---|---|---|---|
| EL01 / E1 | Alter one mode, C/H, subject, policy or G field in a valid fixture | Identity rejection before accepting observations | `U::test_identity_or_mode_substitution_rejected` | Py |
| EL02 / E2 | Apply profile to isolated exact composition | Clinical response and operator TLS succeed; model dispatch remains zero | `D::test_approved_clinical_and_operator_routes_remain_usable` | Docker |
| EL03 / E3 | Known reachable owned IPv4 sink versus each scoped workload namespace | Approved route works; disallowed initiated IPv4 route denied | `D::test_disallowed_ipv4_denied_with_positive_control` | Docker |
| EL04 / E3 | Owned IPv6 sink, or verified enforced disablement | Alternate IPv6 egress cannot pass; unsupported probe stays unverified | `D::test_ipv6_denial_or_enforced_disablement_is_attributed` | Docker |
| EL05 / E3 | Internal service name and controlled external DNS name | Required internal resolution works; disallowed resolution denied | `D::test_dns_policy_preserves_only_required_resolution` | Docker |
| EL06 / E3 | Owned service address used as a disallowed literal-IP destination | Literal syntax cannot bypass the selected route policy | `D::test_literal_ip_does_not_bypass_route_profile` | Docker |
| EL07 / E3 | Approved proxy inbound/reply flow plus owned unapproved outbound sink | TLS passthrough works; proxy cannot initiate the unapproved route | `D::test_operator_proxy_exception_does_not_grant_general_egress` | Docker |
| EL08 / E4 | Isolated application clone with upper/lowercase proxy variables pointing at owned sink | No request/content reaches alternate proxy; no ambient inheritance | `D::test_proxy_environment_cannot_create_alternate_route` | Docker |
| EL09 / E4 | Content-free fixed metadata checks plus synthetic metadata controls | Access is explicitly denied without fetching credentials/body | `D::test_metadata_checks_are_content_free_and_attributable` | Docker |
| EL10 / E5 | Stop sink, break resolver or return ambiguous probe outcome | No false enforcement PASS | `U::test_outage_and_probe_failure_never_prove_denial` | Py |
| EL11 / E6 | Fail enforcement installation/readback in isolated lifecycle | Candidate never reports operational readiness | `D::test_enforcement_failure_prevents_admission` | Docker |
| EL12 / E6 | Restart isolated scoped process/container boundary | Same candidate/profile returns under new linked G; negatives remain denied | `D::test_container_restart_preserves_enforcement_binding` | Docker |
| EL13 / E7 | Substitute bytes, mix runs or label container proof as host proof | Fail closed; missing host stays NOT_VERIFIED | `U::test_witness_substitution_and_host_promotion_rejected` | Py |
| EL14 / E1 | Supply `source` alias versus the two exact mode values | Alias rejected; source-build/published never conflated | `U::test_mode_enum_has_no_aliases` | Py |
| EL15 / E1 | Remove or alter generation bytes, replace them with matching asserted hashes, or mix before/after identities | Recompute canonical bytes and reject missing/substituted generation | `U::test_generation_files_are_retained_canonical_and_recomputed` | Py |
| EL16 / E1 | Change generation during observe, give restart wrong parent, or claim successful restart without a new generation | Exact observe equality and causal restart-parent rules enforced | `U::test_observe_equality_and_restart_parent_binding` | Py |
| EL17 / E7 | Empty PASS/FAIL proofs, unresolved hash or invented NOT_VERIFIED proof | Cardinality and declared retained-byte resolution enforced | `U::test_observation_proofs_resolve_with_status_cardinality` | Py |

Existing inspected controls to preserve: `tests/unit/test_representative_clinical_egress.py`
tests for actual initialized image binding, ambiguous metadata and mixed proof
generation; `tests/unit/test_clinical_staging_lifecycle.py` tests for effective
loopback publishing and proxy-only network membership. Their inspected source
is a baseline, not this contract's fresh evidence.

After implementation, exact commands are
`python -m pytest tests/unit/test_clinical_host_egress_contract.py -q` and
`python tests/deployment/test_clinical_host_egress_contract.py` in an isolated
Linux candidate environment. The planned deployment runner must refuse an
unowned project or missing positive-control inputs. Do not run nonexistent
entrypoints now or silently substitute mock results for Docker evidence.

## External observations and freeze

All rows below are **BLOCKED / NOT_VERIFIED**, produced by the host operator
and verifier for A6. They depend on P1's inventory, S3's identity and the shared
resolver freeze; runtime/recovery observations additionally depend on V4.

| Ledger observation | Required actual-host procedure / observable |
|---|---|
| H02 `dns` | `manual:host-dns-v1`: actual application/proxy resolver paths preserve approved resolution and deny controlled external resolution |
| H04 `ingress-ports` | `manual:host-ingress-ports-v1`: actual selected listener and management boundary expose only the approved route |
| H05 `ipv4` | `manual:host-ipv4-v1`: effective workload/proxy boundary denies controlled IPv4 egress while approved flow works |
| H06 `ipv6` | `manual:host-ipv6-v1`: actual alternate-family denial or enforced disablement, not absence of a local test |
| H08 `metadata-endpoints` | `manual:host-metadata-endpoints-v1`: content-free deny from actual runtime boundary, with attribution |
| H12 `proxy-env` | `manual:host-proxy-env-v1`: controlled alternate settings cannot create an application route |
| H03 dependency | `manual:host-effective-host-runtime-v1`: host/daemon restart restores enforcement before admission, linked to the supervision contract |

Freeze witness bytes only after independent source/subject/G/policy readback,
positive/negative results and retention checks. Failed predicates remain FAIL;
unobserved predicates remain NOT_VERIFIED. Code alone cannot close A6.

## Collision, cold fences and change control

The collector currently hardcodes source C/H at
`tools/representative_clinical_egress.py:29` and assembles a separate two-file
Compose command at `:342`. **Shared staging/Compose/marker integration waits
for the published-mode resolver.** Reuse that resolver for mode, immutable
subjects and effective identity; do not create a second mode selector or
source-build fallback. One integration owner changes shared files. Schema/
fixture tests may proceed independently before that freeze.

No enforcement/restart helper may start workloads while lifecycle is
`renewing_tls`, `tls_prepared` or incomplete `recovering`. It must respect the
existing operator lock, successful migration ordering, and `restore --renew-tls`
completion. Network policy changes requiring recreation happen cold; no
temporary broad allow rule is permitted for a live candidate.

Changes to predicates/schema require a new contract version and impact matrix:
old/new artifact hash, affected row/consumer IDs, source/subject inputs, mandatory
reruns, owner, reason and freeze trigger. Mechanism-only changes still generate
new exact-candidate evidence. Preserve ledger v2 and legacy collector receipts;
do not silently reinterpret them as this profile.

Pre-publication correction of local draft commit `54df4f0`: the initial v1
freeze is amended, not deployed or silently migrated. No v1 collector or
consumer exists at this base. Impact: mode affects EL01/EL14 and both contracts;
retained G and proof resolution affect EL15-EL17 and supervision SL17-SL19.
Rerun their planned matrices when implemented, then freeze the corrected commit
and document hashes. Previously generated hashes do not become accepted proofs.

Nonclaims: no PHI use, medical production approval, HIPAA certification,
universal host isolation, malicious-host protection, generalized Hermes/model
egress, new cloud infrastructure or other operating-system support. Those are
not covert closure requirements. A future new capability/host uses the ledger's
existing deferred-contract process, not an expanded pass claim here.
