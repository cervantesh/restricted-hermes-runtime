# Restricted clinical readiness: six-lane acceptance ledger v2

## Frozen frame and scope

**Contract version:** `restricted-clinical-readiness-ledger.v2`.
**Inspected base:** `6ea42294f855e3ee5e5f8a50c0fc8449253fe5fc`.
**Contract update:** this commit adds machine-enforced A9/A10P binding.
The frozen [v1 ledger](phi-readiness-acceptance-ledger.v1.md) remains unchanged.
Schema fixture tests do not supply publication, host, governance or independent
evaluator evidence. All candidate rows retain MISSING/BLOCKED status; the
version-change impact matrix below is part of this new freeze.

The deliverable is an independently evaluable, self-hosted clinical candidate:
the deterministic staff `next-appointment` command in an exact two-party
Mattermost direct channel, the restricted clinical adapter, and the two HRH
application subjects. The clinical command makes **zero model calls** and does
not enable Hermes tools, plugins, memory, or general conversation. See
[the existing clinical contract](../design/clinical-staff-next-appointment.md).
All execution evidence in this plan uses synthetic, non-PHI data.

Technical readiness is evidence for a subsequent operator/evaluator decision,
not HIPAA certification, a BAA, legal authorization, proof that arbitrary PHI
is detected, or approval for medical production. No requirement to harden all
Hermes capabilities, add Matrix, select a new model, or create cloud storage is
introduced here. A new clinical/model capability needs a separate contract,
owner, and acceptance ledger before it can enter this candidate.

## Status, identity, and row interpretation

- **FROZEN:** the observable requirement and artifact schema are fixed by v2.
  Frozen does not mean implemented, passed, approved, or immutable forever.
- **PROVISIONAL:** a proposed mechanism or collector; implementation may change
  without changing the observable contract. A new external service is not
  implicitly authorized by this label.
- **MISSING:** the required exact-candidate evidence has not been attached and
  independently verified in this ledger. Historical results cannot fill it.
- **BLOCKED:** the witness requires a specified external input/action that this
  local documentation task has not performed. It is not a code defect or a
  claim that authorization can never be obtained.

All acceptance rows below are FROZEN predicates. Their evidence status is
MISSING or BLOCKED; implementations/collectors marked `planned` are PROVISIONAL.
These labels are planning metadata, **not** additional machine outcome values.
Machine outcomes remain `PASS`, `FAIL`, `NOT_VERIFIED`, `NOT_APPLICABLE`, and the
separately retained `EXTERNALLY_ACCEPTED` risk decision supported by the existing
bundle verifier. Missing/blocked evidence exports as truthful `NOT_VERIFIED`.
No accepted risk can turn an unverified technical control into PASS.

Every row joins its artifact ID in the register below. This join is normative:
it supplies that row's exact filename/schema, producer, consumer, version
identity, and freeze trigger. Row dependencies govern when work may start;
register dependencies govern final artifact freeze, not creation of its draft.
A producer never needs its own completed artifact before starting a row.
`Tn::name` means the exact test at the Tn path; `main` means its real executable
entrypoint. `planned:<path>::<name>` is absent at the inspected base and must
not be counted as existing coverage. `manual:<id>` is a named evidence
procedure/decision, not an automated test or permission to mutate a host.

`K` is the immutable candidate identity: five source SHAs required by the
assessment profile (governance contract, HRH contract **C**, HRH publication
source **H**, restricted edge, restricted runtime); four role-specific OCI
digest subjects; policy epoch/digest; and producer/run/toolchain/host IDs.
Record `linux/amd64` for the current published-HRH contract. A different
platform needs a new contract, not an inferred equivalent. Never use a branch,
tag, PR number, locally cached image ID, or the latest log as a substitute for K.

## Six sprints, six lanes

Sprints name intermediate deliverables, not serial timeboxes. `W1` through
`W16` are dependency waves: a wave starts only after all dependencies in prior
waves are complete; entries in the same wave may run concurrently. `G`, `R`,
`S`, `P`, `V`, and `I` are governance, runtime, supply chain, platform controls,
verification/recovery, and independent evaluation respectively.

| Sprint / inspectable delivery | Governance | Runtime | Supply chain | Platform controls | Verification / recovery | Independent evaluation |
|---|---|---|---|---|---|---|
| 1: bounded assessment frame | W1 G1; W2 G2 | — | W1 S1; W2 S3 | W2 P1 | W2 V1 | W2 I1 |
| 2: signed inputs and bounded controls | W3 G3; W4 G4 | W3 R1; W4 R2 | W3 S2; W4 S4 | W3 P2/P3; W4 H02-H15 | — | — |
| 3: source-free composed candidate | — | W7 R3 | W5 S5 | — | W5 V2; W6 V3 | — |
| 4: recoverable candidate | — | W8 R4; W9 R5 | — | W10 H01 | W9 V4 | W8 I2 |
| 5: immutable pre-review bundle | — | — | — | W11 P4 | W11 V5P pre-review bundle | W11 I3; W12 I4 independent evaluation |
| 6: explicit technical disposition | W16 G5 | — | — | — | W14 V5F final bundle; W15 V6 | W13 I5 independent verdict |

Sprint 1 can finish with missing evidence clearly inventoried. Sprint 2 can
deliver a rejected/unavailable publication rather than fabricate one. Sprint 4
can deliver a truthful partial-host receipt. Sprint 5 always produces a
verifiable pre-review bundle, including a NOT_READY bundle. Sprint 6 can end NO_GO with
bounded unresolved work. None of these deliveries implies the next gate passed.

## Canonical artifact register

The verifier in this commit defines `restricted-clinical-candidate.v2`.
The outer manifest schema remains `restricted-clinical-assessment-bundle.v1`;
its root fields do not change. The nine payload paths remain, with an additional
`independent-review/prereview.manifest.json` for a completed v2 review. Legacy
profile v1 retains its old semantics but cannot satisfy this v2 binding contract.
Do not add workflow bookkeeping keys to those closed JSON payloads. Their
common proof frame is `{scope,outcome,sources,subjects,producer,policy}`;
status-specific shapes and additional fields are those enforced by that
verifier. Non-PHI work logs and raw witness attachments live in the retained
evidence handoff **outside** the closed bundle and are referenced by hash.

| ID | Canonical file / schema authority | Producer -> consumer | Version identity; dependency; freeze trigger |
|---|---|---|---|
| A0 | This `phi-readiness-acceptance-ledger.v2.md`; documentary schema above | orchestrator -> all six lanes | ledger version + commit; none; row review and documentation commit |
| A1 | `contracts/clinical-composition.json`; bundle profile, including `claim_id` | runtime contract owner -> composition runner/evaluator | K + claim ID; A0; bounded clinical observable and nonclaims accepted |
| A2 | `subjects/images.json`; bundle profile; supporting `immutable-candidate.json` uses `restricted-runtime-immutable-candidate.v1` | candidate publishers -> consumers/bundle builder | K + four role digests + platform; A1; signed subject verification and role/platform readback |
| A3 | `evidence/hrh-publication.json`; bundle profile with `publication_receipt_sha256` and `verification_receipt_sha256` | HRH publisher + independent consumer -> composition/bundle builder | C/H, both subjects, exact run and key fingerprint; A2; durable producer handoff plus fresh consumer verification |
| A4 | `evidence/clinical-receipt.json`; bundle profile with closed `negative_controls` | composed runner -> bundle builder/evaluator | K + exact composition receipt hash; A1-A3; positive and independently counted negative witnesses retained |
| A5 | `evidence/cold-recovery.json`; bundle profile with independent `manifest_sha256` and `recovery_receipt_sha256` | recovery operator -> bundle builder/evaluator | K + backup generation + both hashes; A4; cold restore and causal controls independently verified |
| A6 | `evidence/representative-host.json`; bundle profile with all 15 observations | host operator + verifier -> bundle builder/evaluator | K + effective host baseline ID + per-observation witness hash; A2, P1; each observation's outcome and aggregate reconciled |
| A7 | `evidence/bounded-inputs.json`; bundle profile and its fixed classified input inventory | evidence curator -> bundle builder/evaluator | exact historical source/run hashes plus K compatibility account; A0; bounded scope checked without promoting it to representative-host proof |
| A8 | `governance/risk-map.json`; bundle profile with `risk_owner` and `risks` | named operator/risk owner -> independent evaluator | K + governance-contract SHA + decision references; A0; accountable decisions and unresolved controls recorded, never synthesized by a model |
| A9 | `independent-review/findings.json`; profile v2 PASS/FAIL requires bare lowercase-hex `reviewed_manifest_sha256` | independent evaluator -> final builder/operator | K + exact A10P manifest SHA-256; A1-A8,A10P; I5 freezes verdict and verifier checks retained-byte binding |
| A10P | `bundles/pre-review/assessment.manifest.json`; exact bytes copied to `bundles/final/independent-review/prereview.manifest.json` | pre-review builder -> evaluator/final verifier | canonical manifest SHA-256; A1-A8; V5P freezes v2 input with review gate NOT_VERIFIED and no nested retained manifest |
| A10F | `bundles/final/assessment.manifest.json`, fixed README/verifier, nine payloads and retained A10P manifest; profile v2 | final builder -> clean-room verifier/operator | new final manifest SHA-256; A1-A9,A10P; V5F verifies retained A10P/A9 binding and unchanged non-review inputs |
| A11 | retained handoff directory: `hrh-trust.json`, `hrh-candidate-receipt.json`, `hrh-verification.json`, `kms-public.pem`, `publication-run.txt`, `handoff-index.v1.json` | publisher/evidence custodian -> independent HRH consumer | exact approved trust + C/H + subjects + run + immutable KMS version; S2; reconstruction/readback after producer scratch loss, with custody/retention recorded |

A11 trust uses `restricted-runtime-hrh-trust.v1`, producer receipt uses the
existing numeric `schema_version: 1`, and consumer result uses
`restricted-runtime-hrh-verification.v1`. The approved public key fingerprint
comes from independent trust, never from the receipt being verified. Keep
registry credentials out of A11. Retain signed SBOM/provenance envelopes with
hashes if needed for offline custody; successful verification summaries are
not the raw signatures or a durable producer-completion receipt.

The **PROVISIONAL** A11 collector may reconstruct receipt fields from the
existing exact OCI subjects, verified SBOM/provenance, public key, and protected
run receipt/log. Its documentary index schema is FROZEN here, but no parser or
durable sink is claimed: `schema_version=restricted-clinical-handoff-index.v1`,
`scope=SYNTHETIC_NON_PHI_ONLY`, `candidate_id`, `run_id`, `files` (unique relative
`path`, SHA-256, byte length, media type), `custodian_id`, `retention_policy_ref`.
Reject traversal, duplicate paths and undeclared bytes. A checksummed index
detects corruption; it does not replace the approved key or signed provenance.
Do not assume Forgejo artifact uploads work or create GCS/release storage as
an incidental implementation detail. Selection of an available approved
retention location is an operator dependency. Publication can be technically
successful while durable handoff remains `evidence-incomplete`.

## Acceptance ledger

Engines: `Py` = pytest on the exact candidate; `Docker` = real isolated Linux
containers/processes; `Registry` = actual private OCI registry and Cosign;
`Host` = selected representative self-hosted environment; `Human` = attributable
operator/evaluator decision. Command-double/unit evidence cannot substitute
for a listed Registry, Docker, Host, or Human witness. Freeze only when the
artifact-register trigger and the row's expected observable both hold.

| ID | Setup / bounded mutation | Required observable effect | Exact existing/planned test or procedure | Engine; status | Artifact; row dependencies |
|---|---|---|---|---|---|
| G1 | Ask for a capability outside the one command or an unidentified decision owner | Explicit exclusion/owner gap, not implicit approval | `manual:scope-and-owner-review-v1` | Human; BLOCKED | A0,A8; none |
| G2 | Change publisher, KMS version, C/H or allowed retention location | New independent trust decision required; receipt cannot self-approve | T2::test_identity_and_trust_mismatches_fail_closed; `manual:trust-custody-decision-v1` | Py+Human; BLOCKED | A8,A11; G1,S1 |
| G3 | Remove retention, recovery, access-revocation or incident owner/decision from the operating contract | Incomplete operator control explicitly retained; no invented decision | `manual:clinical-data-lifecycle-review-v1` | Human; BLOCKED | A8; G1,P1 |
| G4 | Label an unverified technical control externally accepted | Risk decision remains attributable and separate from technical PASS | T1::test_external_acceptance_is_a_retained_risk_decision_not_a_technical_pass | Py+Human; BLOCKED | A8; G2,G3 |
| G5 | Supply a NO_GO review, missing dependency or unresolved closure failure | No technical GO; operator receives exact unresolved work | T1::test_pass_and_fail_require_complete_proof_shapes_and_no_go_cannot_be_ready; `manual:operator-disposition-v1` | Py+Human; BLOCKED | A9,A10F; I5,V6 |
| R1 | Valid command versus malformed namespace/model fallthrough attempt | Exact deterministic command works; malformed forms cause zero model dispatch | T3::test_exact_root_command_is_deterministic_and_never_reaches_conversation; T3::test_clinical_namespace_is_reserved_and_malformed_forms_never_fall_to_model | Py+Docker; MISSING | A1,A4; V1 |
| R2 | Wrong channel/actor pair, changed DM roster or source identity | No clinical query/disclosure outside signed pair and authoritative source | T3::test_direct_roster_and_channel_actor_pair_are_authoritative; T3::test_source_identity_swap_before_query_discloses_nothing | Py+Docker; MISSING | A4; R1 |
| R3 | Revoke permission/change roster after query, or swap a self-consistent response DTO | Delivery is denied and payload erased; new DTO cannot reuse authorization | T3::test_swapped_self_consistent_dto_is_rejected_by_hrh_digest_binding; T3::test_roster_is_revalidated_after_hrh_delivery_authorization; T8::main | Py+Docker; MISSING | A4; R2,V3 |
| R4 | Crash/timeout after delivery claim and restart with pending content | No blind repost or second authorization of ambiguous claim; payload erased | T3::test_crash_after_clinical_delivery_claim_never_reauthorizes_or_posts_after_restart; T3::test_clinical_post_timeout_after_reauthorization_is_ambiguous_and_erased | Py+Docker; MISSING | A4,A5; R3 |
| R5 | Interrupt policy pair publication or change bytes between validation and use | Unprovable epoch/digest pair fails closed; retry uses verified same bytes | T4::test_policy_pair_interruption_is_fail_closed_and_retryable; T4::test_active_policy_binding_uses_the_same_verified_bytes_for_epoch_and_digest | Py+Docker; MISSING | A4; R4,G2 |
| S1 | Present dirty/wrong source frame, stale C/H or swapped role/platform | Reject before candidate startup; independent C/H and role subjects remain exact | T5::test_source_frame_requires_clean_runtime_ancestry_and_exact_clean_hrh; T2::test_identity_and_trust_mismatches_fail_closed | Py; MISSING | A2,A11; A0 |
| S2 | Wrong-purpose signature, mixed-run provenance, missing/ambiguous envelope | All four role/purpose verifications required; no first/latest match shortcut | T2::test_separate_trust_declaration_and_four_signed_statements_are_required; T2::test_cosign_result_rejects_ambiguous_or_malformed_envelopes; `manual:registry-exact-run-readback-v1` | Py+Registry; BLOCKED | A3,A11; S1,G2 |
| S3 | Alter runtime subject digest, platform, source or final-image attestation relationship | Candidate verifier rejects mismatch; deployment consumes same final subjects | T6::test_candidate_verifier_accepts_matching_subjects_and_rejects_relational_failures; T6::test_actual_candidate_layout_receipts_build_and_verify_from_repo_root | Py+Registry; BLOCKED | A2; S1 |
| S4 | Producer scratch/log unavailable; attempt mixed-run reconstruction or mutable keeper retarget | Exact retained evidence reconstructs/verifies, otherwise evidence-incomplete; no invented success | `planned:tests/unit/test_hrh_evidence_handoff.py::test_exact_run_reconstruction_rejects_missing_or_mixed_evidence`; `manual:durable-handoff-readback-v1` | Py+Registry+Human; BLOCKED | A3,A11; S2,G2 |
| S5 | Candidate retention reference no longer resolves; dependency finding has no disposition | Unavailable subject/evidence or untriaged finding blocks its claimed gate | T2::test_registry_native_retention_resolution_can_bind_the_exact_digest; `manual:exact-subject-vulnerability-triage-v1`; `manual:retention-readback-v1` | Registry+Human; BLOCKED | A2,A8,A11; S3,S4 |
| P1 | Inventory desired host but omit effective network, principals, stores or management path | Missing host input remains NOT_VERIFIED, never inferred from Compose | T1::test_partial_host_and_multifile_control_evidence_follow_the_closed_lattice; `manual:representative-host-inventory-v1` | Py+Host; BLOCKED | A6; G1 |
| P2 | Replace initialized container image or make a negative network witness ambiguous | Reject generation mismatch/ambiguous probe; successful clinical route still observed | T9::test_actual_container_image_must_match_the_initialized_marker_before_probing; T9::test_fixed_metadata_reachability_or_ambiguous_timeout_is_not_green; T10 | Py+Docker; MISSING | A7; V1,S3 |
| P3 | Canary in child failure output, argv, retained logs or unsafe secret file | No secret reaches those outputs; secret boundary rejects unsafe input | T11::test_composed_e2e_retained_logs_reject_every_secret_canary; T11::test_linux_procfs_witness_requires_the_same_uid_provisioner_and_rejects_canaries | Py+Docker; MISSING | A7; V1 |
| P4 | Operator cannot perform bounded revoke/stop/recovery using retained instructions | Handoff remains incomplete; no assumed operational ownership | `manual:operator-handoff-rehearsal-v1` | Host+Human; BLOCKED | A6,A8; H01-H15,V4,G3 |
| V1 | Ambient application DATABASE_URL/HRH root or unrelated installed runtime available | Test remains in generated isolated frame and exact worktree imports | T7::test_compose_ignores_inherited_clinical_variables_and_uses_generated_e30_frame; T5::test_compose_interpolation_uses_sealed_environment_not_ambient_hrh_root | Py+Docker; MISSING | A4,A7; S1 |
| V2 | Run published mode with no HRH checkout mounted/available, wrong local cache, or failed migration | Exact signed digests pulled; no build/fallback; migration failure prevents web startup | T7::test_published_mode_rejects_even_an_empty_hrh_root_variable; T7::test_failed_published_migration_stops_before_web_or_clinical_startup; T12::main in published mode | Py+Docker+Registry; BLOCKED | A3,A4; S2,S4 |
| V3 | Real Mattermost command traverses HRH query and delivery authorization; apply each negative control | Positive bounded response plus zero unauthorized disclosures with effective image identity | T12::main; T8::main | Docker; BLOCKED | A4; R1,R2,S2,S3,V2 |
| V4 | Cold backup/restore, tampered archive, mixed generation and interrupted recovery | Verified restore with causal controls; invalid/incomplete restore never operational | T13::main; T5::test_verified_recovery_receipt_requires_all_causal_controls; T5::test_restore_post_start_failure_returns_to_non_operational_recovering_state | Py+Docker+Host; BLOCKED | A5; V3,R4 |
| V5P | Replace pre-review proof bytes, omit a required gate/dependency or use dummy/partial candidate | Exact closed pre-review bundle rejects substitution and remains NOT_READY; A9 is NOT_VERIFIED | T1::test_profile_rejects_a_dummy_or_incomplete_candidate_from_ready; T1::test_profile_dependency_inventory_mapping_and_not_applicable_cannot_waive_readiness | Py; MISSING | A10P; A1-A8 |
| V5F | Missing/wrong review hash, final manifest as input, or substituted non-review proof bytes | Exact retained A10P required; substitution fails even after final rehashing | T14::test_v2_review_rejects_missing_wrong_self_and_substituted_inputs_even_if_rehashed; T14::test_v2_missing_retained_manifest_cannot_export_final_review | Py; MISSING | A10F; V5P,I5 |
| V6 | Copy only retained final bundle to clean directory; add/change/symlink a file | Offline verifier accepts exact truthful final set and rejects every mutation | T1::test_synthetic_bundle_is_clean_room_verifiable_and_not_ready; T1::test_verifier_fails_closed_for_extra_changed_symlinked_reordered_and_bad_status_content; `tools/verify_assessment_bundle.py` | Py+clean-room process; MISSING | A10F; V5F,I5 |
| I1 | Reviewer proposes a requirement outside the bounded command or makes a unit-only closure claim | Adjudication separates strict closure, proportional hardening and future scope | `manual:closure-rubric-review-v1` | Human; BLOCKED | A0,A9; G1 |
| I2 | Independent reviewer challenges concrete R/S/V boundary and author counters with reachable evidence | Each finding has exact frame, falsifier and disposition; no vote-based PASS | `manual:bounded-adversarial-counterreview-v1` | independent review; MISSING | A9; I1,V2,R3 |
| I3 | Review reuses container evidence for host control, self-selected key or unsigned completion claim | Overclaim rejected; missing external evidence stays explicit | `manual:host-and-evidence-boundary-review-v1` | independent review; MISSING | A9; P1,S4,H01-H15 |
| I4 | Clean-room evaluator receives only immutable A10P and its retained K-bound inputs | Evaluator can reproduce the pre-review verifier result and trace each control to its producer | `manual:independent-evaluation-v1` | independent evaluator; BLOCKED | A10P; I2,I3,V4,V5P,G4 |
| I5 | Evaluator emits PASS/FAIL with missing, wrong or self-referential input hash | Verdict identifies immutable A10P; authority/attribution still needs evaluator evidence | T14::test_v2_review_binds_retained_exact_prereview_bytes_without_self_reference; `manual:independent-technical-disposition-v1` | Py+independent evaluator; BLOCKED | A9; I4,A10P |

V5P builds and freezes A10P with the schema-required A9 payload truthfully
NOT_VERIFIED. I4 reviews only that immutable input, and I5 freezes A9 against
the A10P manifest. V5F then creates distinct A10F; it never rebuilds, replaces,
or reuses the A10P artifact identity. V6 receives only A10F. The independent
record must bind SHA-256 of the exact retained A10P bytes. A10F hashes that
file and A9 without self-reference. Verification requires canonical v2 A10P,
a NOT_VERIFIED review gate, unchanged source/subject/producer/policy/dependency
and nonclaim metadata, and unchanged non-review control/file records. A changed
input requires a new A10P and review. This verifies content identity, not that
a reviewer truly read it or holds external authority. The operator still pins
A10F through its independently selected expected manifest hash.

To export v2: first build/freeze A10P with the original nine files and an A9
NOT_VERIFIED placeholder. For final export, copy its exact manifest bytes to
the input directory's `independent-review/prereview.manifest.json`, add that
path to the uniquely sorted declaration `files`, and put its bare 64-character
SHA-256 in the completed A9 `reviewed_manifest_sha256`. Update only the review
gate/verdict; keep all non-review evidence bytes and metadata unchanged. Build
into a new output directory, never over A10P. Verify A10F with its own external
`--expected-manifest-sha256`; that argument is not the A10P hash.

I1-I4 may accumulate attributable working notes outside either closed bundle,
but those notes are not A9 and cannot be used as a readiness result. A9 comes
into existence only at I5. The A9-shaped payload inside A10P is a generated
NOT_VERIFIED placeholder required by the existing bundle schema; A10F replaces
that placeholder only in the distinct final bundle after A9 is frozen.

## Representative-host subledger (fifteen independent observations)

All rows join A6, depend on P1/S3 (H01 additionally on V4; H13 on G2/G3),
use the **Host** engine and are **BLOCKED**
pending a selected accessible representative host and bounded operator action.
Their exact planned procedure IDs are `manual:host-<observation>-v1`. Freeze
each witness only after its effective host/candidate identity and observation
hash are recorded. A partial set does not become representative-host PASS.
Selected denials apply to controlled synthetic destinations, never unrelated
third-party targets. Outages/timeouts alone do not demonstrate a firewall deny.

| ID / observation | Setup / controlled mutation | Observable effect / planned procedure |
|---|---|---|
| H01 `backup-recovery` | Restore selected backup into isolated target | Application state and authorization/replay controls survive; `manual:host-backup-recovery-v1` |
| H02 `dns` | Allowed resolution plus controlled disallowed name | Intended resolution succeeds; disallowed path demonstrably denied; `manual:host-dns-v1` |
| H03 `effective-host-runtime` | Restart selected host service boundary | Same approved candidate and confinement return; `manual:host-effective-host-runtime-v1` |
| H04 `ingress-ports` | Probe approved ingress and a controlled unapproved listener path | Only intended exposure is reachable; `manual:host-ingress-ports-v1` |
| H05 `ipv4` | Approved IPv4 flow plus controlled disallowed destination | Functional route and effective denial both witnessed; `manual:host-ipv4-v1` |
| H06 `ipv6` | Attempt analogous IPv6 route, or verify enforced disablement | No IPv6 alternate egress; `manual:host-ipv6-v1` |
| H07 `logging-audit-sinks` | Synthetic canaries and one audit event through real configured sinks | No canary content retained; required bounded audit delivered; `manual:host-logging-audit-sinks-v1` |
| H08 `metadata-endpoints` | Controlled reachability check from actual workload boundary | Metadata access denied without credential/content collection; `manual:host-metadata-endpoints-v1` |
| H09 `mounts` | Compare effective mounts; test denied access to a scoped fixture | Only approved mounts/permissions accessible; `manual:host-mounts-v1` |
| H10 `patch-baseline` | Reconcile observed packages/runtime against approved baseline | Untriaged drift prevents a passing baseline; `manual:host-patch-baseline-v1` |
| H11 `principals-iam-denials` | Approved action and explicitly denied synthetic action using workload identity | Least-privilege result is observed, not inferred from role names; `manual:host-principals-iam-denials-v1` |
| H12 `proxy-env` | Start isolated witness with controlled alternate proxy settings | No alternate sensitive-data route; `manual:host-proxy-env-v1` |
| H13 `secret-mounts-rotation` | Rotate synthetic credential and retry old/new credential | New works, old denied; no argv/log leak; `manual:host-secret-mounts-rotation-v1` |
| H14 `time-source` | Observe effective time source; bounded isolated skew/freshness control | Expired policy/requests rejected, no stale delivery; `manual:host-time-source-v1` |
| H15 `trust-roots` | Approved certificate versus unapproved issuer/hostname | Approved TLS succeeds, invalid trust fails closed; `manual:host-trust-roots-v1` |

## Existing test entrypoints and historical evidence

| Alias | Exact repository path |
|---|---|
| T1 | `tests/static/test_assessment_bundle.py` |
| T2 | `tests/unit/test_hrh_published_candidate.py` |
| T3 | `tests/unit/test_mattermost_clinical.py` |
| T4 | `tests/unit/test_clinical_policy_pair.py` |
| T5 | `tests/unit/test_clinical_staging_lifecycle.py` |
| T6 | `tests/static/test_immutable_candidate_supply_chain.py` |
| T7 | `tests/unit/test_clinical_composed_e2e_environment.py` |
| T8 | `tests/deployment/test_clinical_delivery_reauthorization_e2e.py` |
| T9 | `tests/unit/test_representative_clinical_egress.py` |
| T10 | `tests/deployment/test_representative_clinical_egress.sh` |
| T11 | `tests/unit/test_clinical_staging_secret_boundary.py` |
| T12 | `tests/deployment/test_clinical_composed_e2e.py` |
| T13 | `tests/deployment/test_clinical_cold_recovery_e2e.py` |
| T14 | `tests/static/test_assessment_prereview_binding.py` |

Relevant already-versioned evidence includes
[staging hardening](../evidence/clinical-staging-readiness-hardening-2026-09-06.md),
[clinical verification](../evidence/clinical-staff-next-appointment-verification.md),
and `docs/evidence/clinical-composed-e2e.json`. These documents retain their own
frames. For example, the staging report names candidate `7dc0efb4...` and hosted
run on `45e883c4...`; neither is this ledger's inspected base. It explicitly
leaves representative operator controls and independent evaluation open.
T1's fixed bounded-input inventory points to prior runs for secret boundary,
delivery reauthorization and container egress. Retain these as **bounded
historical inputs**, not substitute passes for changed code or real host IAM,
service-manager, registry publication, or governance evidence.

The [published-HRH design](../design/source-free-hrh-candidate-consumption.md)
explicitly says only HRH web/migrate are source-free; runtime/controller still
build from this repository. Its local tests use synthetic fixtures/command
doubles and do not prove actual publication. V2 requires a fresh environment
without an available HRH source tree, not merely an unset path variable.

## Dependency graph, freeze points and critical path

The graph is a DAG of **deliverables**, not a demand to serialize six lanes:

```text
START -> A0 scope/acceptance contract
  |-> G1 + S1 -> G2 -> S2 -> S4 durable handoff ---------------------------|
  |-> S1 -> S3 runtime subjects -------------------------------------------|-> V2 -> V3
  |-> V1 -> R1 -> R2 ------------------------------------------------------|         |
  |-> G1 + P1 -> G3 -> G4 risk map ---------------------------------------|         v
  |-> V1 + S3 -> P2; V1 -> P3 --------------------------------------------|   R3 -> R4 -> V4
  |-> S3 + S4 -> S5 -------------------------------------------------------|               |
  |-> P1 + S3 -> H02-H15 --------------------------------------------------|               |
  |-> V4 + P1 + S3 -> H01 ------------------------------------------------|---------------|
  |-> R4 + G2 -> R5 -------------------------------------------------------|---------------|
                                                                                          v
                                                                            V5P -> A10P pre-review

  I1 -> I2 ---------------------------------------------------------------|
  P1 + S4 + H01-H15 -> I3 -----------------------------------------------|-> I4
  A10P + V4 + G4 ---------------------------------------------------------|
                                                                                |
                                                                      I5 -> final A9
                                                                                |
                                                             V5F -> A10F final bundle
                                                                                |
                                                               V6 clean-room verification
                                                                                |
                                                                  G5 + P4 -> END GO / NO_GO
```

The likely evidence-critical chain is actual signed publication -> durable
handoff -> source-free composition -> recovery -> integrated bundle ->
independent disposition. Representative-host evidence or accountable operator
decisions can instead become critical if unavailable. No effort estimate is
asserted without measured inputs. Runtime unit work, secret checks, host input
collection, evidence schema checks and scope review can proceed independently.
There is no value in waiting for all Sprint 2 cells before starting an already
unblocked Sprint 3 cell.

Freeze points: **F0** A0 contract at this commit; **F1** trusted C/H/subjects and
key after S1-S3; **F2** composition/recovery/host witness bytes after their
individual observations; **F3** immutable A10P pre-review bundle; **F4** A9
evaluator disposition bound to F3; **F5** distinct A10F and its clean-room
verification. A witness belongs to exactly one K and one producer run. Reuse
requires an explicit unchanged-input/dependency comparison, never just a green
older CI link.

## v1 -> v2 change-control impact

Bounded schema evidence on this implementation: TDD RED rejected the new v2
profile before code changes. Windows/Python 3.11: **28 passed**. Linux WSL2
Ubuntu 24.04/Python 3.12.3: **27 passed, one Windows-junction skip**. Both ran:
`python -m pytest tests/static/test_assessment_prereview_binding.py tests/static/test_assessment_bundle.py -q --disable-warnings`.
The new tests build actual bundles, mutate/re-hash inputs, and execute the
bundled clean-room verifier as a separate process. `compileall` and
`git diff --check` passed. No publication, real candidate review, host evidence
or certification is implied by these synthetic fixture results.

| Old artifact identity | New version / affected consumers | Rerun and freeze trigger |
|---|---|---|
| Ledger v1 at `6ea42294` | ledger v2; A0/A9/A10P/A10F, V5F, I5 | Preserve v1 bytes; review revised register and dependency rows; freeze new document |
| Review/profile v1 at `6ea42294` | profile v2 adds exact retained-manifest binding | PASS/FAIL positive controls plus missing/wrong/self/substitution mutations; freeze code and tests together |
| Closed nine-file inventory | v2 permits exactly one additional retained manifest for completed review | Pending/completed inventory tests; NOT_VERIFIED retains original closed shape |
| Legacy verifier | v1 interpretation preserved, no automatic migration | Full existing v1 assessment suite; older verifiers reject unknown v2 |

Exact old/new file identities are the base/resulting commit Git blob hashes,
reported with delivery. No old candidate evidence becomes a v2 PASS by migration.
No outer root fields, generic artifact store, reviewer-signature system or
certification claim are introduced. Missing external evidence remains missing.

## Change control and terminal conditions

1. Frozen artifact bytes are never silently replaced. Change their version or
   immutable content identity and record an impact matrix **before** consuming
   the replacement: old/new artifact hash, changed requirement IDs, changed
   producer inputs, affected consumer IDs, reused evidence justification,
   mandatory reruns, owner, reason and new freeze trigger. Keep this matrix in
   the versioned ledger change, not as new keys in a closed bundle schema.
2. A predicate/schema change requires a subsequent version (or the corresponding schema's next
   version), compatibility decision and consumer review. A mechanism-only
   change keeps the predicate but changes source/subject identity and reruns
   affected evidence. An unrelated upstream commit does not trigger automatic
   daily rebases/retests if the frozen frame remains the reviewed candidate.
3. Missing publication, retained evidence, host inputs or human decisions stays
   NOT_VERIFIED. Code can implement collectors and fail-closed verification;
   **code alone cannot manufacture durable publication/retention readback or
   independent operator/evaluator evidence**, and cannot lift evidence-incomplete.
4. Any observed required-control failure yields NO_GO. An independent reviewer
   may challenge scope, but only the recorded adjudication/version change can
   remove a requirement. Do not make a recommendation a new gate by accident.
5. END means an attributable technical GO or truthful NO_GO with exact remaining
   requirements/owners. Even GO does not authorize PHI or assert certification;
   it identifies the exact hardened candidate available for external evaluation.

Deferred destinations: model-mediated clinical access and additional Hermes
capabilities belong to a future runtime-capability contract (runtime owner;
trigger: an explicit new clinical use case); another host/platform belongs to
a host-profile revision (operator; trigger: chosen deployment differs);
external retention service changes belong to an operator infrastructure
decision (evidence custodian; trigger: existing approved retention cannot meet
S4/S5). No new umbrella platform work is required merely to finish this ledger.
