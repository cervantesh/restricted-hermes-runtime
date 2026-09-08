# Clinical lifecycle supervision and observability contract v1

## Frame, scope and status

**Contract:** `restricted-clinical-supervision-contract.v1`.
**Inspected source:** `4aa366adfb09cf8d230dce92ff98eb12dcc9029b`.
This document specifies a bounded future implementation. It changes no product
code, Compose configuration, host service or assessment schema.

It refines P3/P4, R4/R5, V4 and H03/H07 of the
[readiness ledger v2](../assessment/phi-readiness-acceptance-ledger.v2.md), with
H01/H13/H14/H15 as recovery, rotation, clock and trust dependencies. The scope
is the existing Linux/Docker deterministic clinical-staff command, not a new
general supervisor platform. No model, channel, cloud service or alert vendor
is added. All execution fixtures are synthetic and non-PHI.

Predicates, row IDs and documentary schemas are **FROZEN**; the supervision,
health and alert mechanisms are **PROVISIONAL**. Local exact-candidate evidence
is **MISSING**. Selected service-manager, host reboot, real log sinks and alert
delivery evidence is **BLOCKED**. Export missing/blocked work as `NOT_VERIFIED`.
The ledger's technical outcome lattice and separate `EXTERNALLY_ACCEPTED` risk
decision remain unchanged. Frozen is not implemented, passed or certified.

## Existing responsibilities to preserve

Locations refer to the exact inspected source.

| Existing owner surface | Exact location | Reuse / limit |
|---|---|---|
| Operational lifecycle and operator lock | `deploy/clinical-staging/clinical_staging.py:1187`, `clinical_operator_lock.py` | One owner for start/stop/recovery; do not bypass through a parallel Compose wrapper |
| Effective service inventory | `deploy/clinical-staging/clinical_staging.py:731` | Requires all long-running services running and successful one-shots; not ongoing supervision |
| Status and generation check | `deploy/clinical-staging/clinical_staging.py:1296`, `:1312` | Reuse TLS, exact images, topology, confinement and current-start identity; old authenticated log marker is not continuously fresh health |
| Cold TLS generation | `deploy/clinical-staging/clinical_tls.py`; `clinical_staging.py:1373` | Pending renewal remains non-operational; renewal publishes stopped, never starts workloads |
| Application reconnect / terminal exit | `src/restricted_runtime/services/production_mattermost_ingress.py:134`, `:168`, `:216` | Retryable connection failures differ from terminal rejection; do not duplicate inside a second application loop |
| Application-safe recovery | `tests/deployment/test_clinical_cold_recovery_e2e.py:52`, `:156` | Actual ingress kill and cold-restore witness; not host service-manager proof |
| Existing local health pattern | `deploy/local/compose.yaml:160`, `:199` | Separate gateway/conversation composition; do not copy blindly into clinical lifecycle |
| Current clinical health/log configuration | `tests/deployment/clinical-composed-e2e/compose.yaml:9`, `:46`, `:33` | DB healthchecks and reduced Mattermost log level, but no clinical restart policy or log-size caps |
| Content-safe log baseline | `tests/unit/test_clinical_staging_secret_boundary.py:462` | Canary rejection is not bounded storage, retention or delivered alerts |

The root controller is an ephemeral provisioning helper with `restart: "no"`
at `deploy/clinical-staging/compose.yaml:42`. It must not become a permanent
health observer. `migration_supervisor.py` supervises only a one-shot migration
proxy child and is not the missing host supervisor. The existing A6 owner is
host operator + verifier; the runtime owner produces implementation evidence.

## Closed outcome and lifecycle contract

1. **S1 exact recovery:** a scoped process crash either returns the same approved
   candidate/policy under a new linked generation within a configured finite
   recovery budget, or remains non-operational with a retained failure event.
   Restart budget, delay and observation deadline are explicit finite profile
   values; their units and values are frozen with each effective host profile.
2. **S2 cold fence:** no automatic or manual supervisor path starts workloads
   during `renewing_tls`, `tls_prepared` or incomplete `recovering`. Explicit
   operator stop remains stopped. `restore --renew-tls` must complete the full
   certificate publication before startup; migration success precedes web.
3. **S3 authority:** recovery rechecks effective image identity, current signed
   policy and required configuration/trust. Failed or stale checks never fall
   back to a build, a mutable tag, old policy or an unverified operational state.
   Terminal policy/authentication/protocol rejection is not an infinite restart
   loop; a bounded repair/retry requires revalidated operator state.
4. **S4 fresh health:** distinguish `starting`, `ready`, `degraded`, `failed`,
   `stopped` and `cold-fenced`. These are health states, not new lifecycle marker
   or assessment outcomes. `ready` requires all required dependencies and fresh
   authenticated ingress state for the current generation, with an explicit
   finite freshness deadline. PID/running status or an old log line alone fails.
5. **S5 delivery safety:** crash recovery preserves current ambiguous-delivery,
   expiration, source/roster reauthorization and payload-erasure behavior. It
   must not create a second clinical disclosure or provider dispatch.
6. **S6 bounded logs:** every scoped long-running service and provisioner has
   explicit finite storage/rotation bounds verified from effective state.
   Include stdout/stderr, daemon logs and application-managed files in the
   inventory. A Docker logging cap alone cannot waive an application log file.
7. **S7 actionable safe events:** terminal failure, exhausted recovery budget,
   prolonged non-ready health, cold-fence intervention, logging failure and
   recovered health produce a fixed-shape event without clinical content or
   credentials. Repeated polls of the same state transition deduplicate.
8. **S8 alert honesty:** the operator's existing selected sink either confirms
   receipt of that event or delivery remains unverified/failed. Notification
   failure never changes authorization, posts to a clinical channel, or reports
   the runtime ready. The alert queue is bounded; exhaustion is locally visible
   through a bounded failure counter/state, not silent success or infinite disk.

The recovery mechanism must enter through the existing lifecycle owner and
cooperative operator lock. Blind per-container `unless-stopped`, a service unit
that only executes raw `docker compose up`, or a permanent root controller is
not an implementation of S2. The observer does not receive database credentials,
clinical responses or policy signing authority merely to assess liveness.

## Identity and documentary artifacts

`K` is exactly the ledger-v2 candidate identity. The exact mode enum is
**`source-build|published`**, with no `source` alias, case normalization or
fallback. The effective generation `G` and mode semantics are shared with the
[egress contract](clinical-host-egress-contract.v1.md#identity-artifact-and-mode-contract).
The health profile adds a hashed effective supervision/logging configuration:
finite recovery attempts, delay/deadline/freshness seconds, per-service log byte
and retained-file caps, finite alert queue capacity/expiry and observation
interval. No numeric threshold is represented as measured before a profile
and observed run exist. Units/finite bounds are required; operator choice does
not waive the predicates. A host-profile freeze records actual values before
tests start, so a failing run cannot change its thresholds retrospectively.

**Supporting witness:** `platform/supervision-witness.v1.json`; documentary
schema `restricted-clinical-supervision-witness.v1`. Exact root fields:
`schema`, `scope`, `contract_sha256`, `candidate_manifest_sha256`, `mode`,
`producer`, `host_baseline_sha256`, `generation`, `profile_sha256`,
`observations`, `witness_files`. Common field shapes, canonical ordering and
safe path/hash rules match the egress contract; `scope` is
`SYNTHETIC_NON_PHI_ONLY`. Observation IDs are the uniquely sorted local/host row
IDs below. Missing observations remain `NOT_VERIFIED` with no invented proofs.

Retain and declare `platform/generation.before.json` and
`platform/generation.after.json`. Recompute their canonical bytes and SHA-256
under the egress contract's exact generation schema. Require equality with
`generation.before_sha256`/`after_sha256` and the file inventory; do not accept
asserted hashes without these files. `operation=observe` requires identical
bytes and null parent. `operation=restart` requires parent equal to the before
hash; a successful-recovery claim requires a new effective start/container
generation with the same approved identity/profile. Failed restart evidence
cannot substitute for successful recovery. All row proof hashes resolve to
declared retained bytes: PASS/FAIL needs 1..64 unique sorted hashes with actual
row-result evidence; NOT_VERIFIED has an empty list, never fabricated proofs.
The egress contract's size bounds, non-self-reference and acyclic proof rules
apply to these files, events, acknowledgments and delivery proofs as well.

Closed diagnostics: `none`, `identity-mismatch`, `cold-fence`,
`recovery-budget-exhausted`, `dependency-unready`, `stale-health`,
`terminal-rejection`, `delivery-safety-failed`, `log-bound-unverified`,
`content-leak`, `alert-unconfirmed`, `witness-unavailable`, `host-not-observed`.
`none` means demonstrated PASS only. These are witness diagnostics; an expected
negative test can PASS only with retained proof that the rejection occurred.

**Event stream:** `platform/supervision-events.v1.jsonl`; documentary schema
`restricted-clinical-supervision-event.v1`. Each line contains exactly `schema`,
`event_id`, `candidate_id`, `generation_sha256`, `service`, `transition_sequence`,
`event_class`, `observed_at`, `outcome`. Event classes are `recovery_started`,
`recovered`, `terminal_failure`, `recovery_exhausted`, `health_degraded`,
`cold_fence_held`, `logging_failed`, `alert_delivery_failed`.
Each JSONL line is one canonical JSON object under the inherited byte rules;
no blank lines or duplicate event IDs are allowed in the retained event stream.
All objects reject unknown keys, null values, implicit coercion and duplicate
keys unless null is explicitly permitted by the inherited generation schema.
Hashes are bare lowercase 64-hex except `candidate_id`, which is exactly
`sha256:` plus 64 lowercase hex and must match the pinned candidate. Service
is exactly one of `mattermost-postgres`, `mattermost`, `hrh-postgres`, `hrh`,
`hrh-tls`, `clinical-adapter`, `ingress`, `operator-proxy`, `hrh-migrate`,
`clinical-socket-init`, `controller`, `lifecycle-observer`. A service absent from
the frozen profile is rejected, even if it belongs to this enum. Sequence and
attempt fields are JSON integers in `[1,9007199254740991]`, never booleans or
floats. Timestamps are calendar-valid UTC `YYYY-MM-DDTHH:MM:SS.sssZ`, years
1970..9999, with no alternate timezone or leap-second syntax. Hashes/strings
must match their exact formats; no additional free-form string is admitted.

The event `outcome` enum is finite and derived exactly from `event_class`:
`recovery_started=PENDING`, `recovered=SUCCEEDED`, `health_degraded=DEGRADED`,
`cold_fence_held=BLOCKED`; `terminal_failure`, `recovery_exhausted`,
`logging_failed` and `alert_delivery_failed` all map to `FAILED`. Reject a
different combination. These are event outcomes, not assessment PASS/FAIL.
`generation_sha256` must resolve to the declared before/after generation that
was effective at this transition, with the same candidate and service.

Define transition identity as the exact canonical JSON object containing
`candidate_id`, `generation_sha256`, `service`, `transition_sequence` and
`event_class`. `event_id` equals SHA-256 of the ASCII domain prefix
`restricted-clinical-supervision-event.v1` plus LF, followed by that canonical
object's bytes (including its final LF). Consumers recompute it. The first
event's timestamp/outcome and complete bytes are persisted; retry never changes
the event or allocates another transition sequence for the same transition.

Sequences are unique and strictly increasing per `(candidate_id, service)`,
including across workload-generation and observer restarts. Atomically persist
the allocated sequence, event bytes and transition/dedup cursor before enqueue.
Gaps are allowed; reuse, rollback or the same sequence with changed bytes is
rejected. Reopening existing state continues its cursor, never resets it to 1.
Missing/corrupt cursor state on an existing generation fails closed instead of
guessing a new sequence. This stores no clinical content and does not claim
exactly-once display by an arbitrary external sink. A deduplicating sink may
use the stable event ID; no new vendor is mandated.

**Delivery acknowledgments:** `platform/supervision-deliveries.v1.jsonl`, schema
`restricted-clinical-supervision-delivery.v1`. Each record contains exactly
`schema`, `event_id`, `sink_id_sha256`, `attempt`, `attempted_at`, `completed_at`,
`result`, `proof_sha256`. Event/hash/integer/timestamp formats are those above.
`sink_id_sha256` identifies an independently selected opaque sink identity in
the retained frozen profile, never a URL/token/address. `event_id` must resolve
to exactly one declared event with a valid recomputed ID. Attempts are unique
and increasing per `(event_id, sink_id_sha256)`, durably allocated before send;
replaying the exact acknowledgment is idempotent, not another attempt. Require
`completed_at >= attempted_at >= event.observed_at`. Unattempted delivery has no
acknowledgment and remains NOT_VERIFIED; it cannot fabricate attempt 1 or a
DELIVERED result.

`result` is exactly `DELIVERED`, `REJECTED`, `TIMED_OUT` or `TRANSPORT_ERROR`.
`proof_sha256` resolves to one declared canonical content-free delivery-proof
file, not the acknowledgment itself. Its schema is
`restricted-clinical-supervision-delivery-proof.v1`, with exactly `schema`,
`event_id`, `sink_id_sha256`, `attempt`, `result`, `observed_at`, `evidence_class`.
All shared fields must equal the acknowledgment, and `observed_at` lies within
its attempt interval. The exact evidence-class/result pairs are
`receiver_readback/DELIVERED`, `receiver_rejection/REJECTED`,
`deadline_observed/TIMED_OUT`, `transport_failure/TRANSPORT_ERROR`.
DELIVERED requires independently observed receipt of the bound event at that
selected sink; sender enqueue/write success is insufficient. A local fixture's
receiver readback proves only the fixture sink, not the operator's sink. The
operator/verifier attests actual-host readback; checksums alone cannot establish
truth or external authority. Missing proof bytes, mismatched bindings, duplicate
attempts with changed bytes or ambiguous results invalidate the acknowledgment.

No free-text detail field, chat/user/patient identifier, URL, environment value,
exception string, credential, payload or clinical-channel notification exists
in events, acknowledgments or delivery proofs. Delivery of
`alert_delivery_failed` must not recursively generate unbounded alerts.

Witness/events live in retained supporting evidence outside the closed A10P/F
file inventory. Runtime runner and host operator produce them; independent
verifier/A6 curator consume them. H03/H07 retain existing observation fields;
no new bundle payload keys are introduced. The parser/collector is absent and
PROVISIONAL: documentary schema is not a machine-validation claim.

## Local executable acceptance matrix

`U` = planned `tests/unit/test_clinical_supervision_contract.py`;
`D` = planned `tests/deployment/test_clinical_supervision_contract.py`.
Both files are absent at this base. Exact names below are implementation
acceptance requirements, not reported coverage. All local rows are **MISSING**,
produce the supporting witness/events, and require the exact profile/K/G frame.

| ID / predicate | Setup and bounded mutation | Required observable | Exact test | Engine |
|---|---|---|---|---|
| SL01 / S1 | Kill isolated operational ingress process | Bounded automatic recovery or retained exhausted failure; linked new G | `D::test_crash_recovery_is_bounded_and_generation_bound` | Docker |
| SL02 / S1 | Make repeated startup fail beyond frozen attempt/deadline budget | Attempts stop at budget; non-operational state and one transition event | `D::test_repeated_failure_exhausts_frozen_recovery_budget` | Docker |
| SL03 / S2 | Explicit operator stop followed by observer/restart tick | No workload starts | `D::test_explicit_stop_is_not_automatic_recovery` | Docker |
| SL04 / S2 | Interrupt TLS publication at each durable cold marker | No supervisor admission; retry retains complete-generation requirement | `D::test_tls_pending_markers_hold_supervisor_cold_fence` | Docker |
| SL05 / S2 | Interrupt restore, including restore with TLS renewal | No workload starts before renewal and restore completion | `D::test_incomplete_restore_never_auto_starts` | Docker |
| SL06 / S2 | Fail migration prerequisite | No HRH web or clinical operational admission | `D::test_failed_migration_blocks_supervised_start` | Docker |
| SL07 / S3 | Swap mode/subject/policy or expire required signed policy before restart | Rejection, no fallback/rebuild, no false operational state | `D::test_restart_revalidates_candidate_and_policy_without_fallback` | Docker |
| SL08 / S4 | Healthy exact candidate versus each failed required dependency | Ready only with fresh successful dependencies | `D::test_health_requires_effective_current_dependencies` | Docker |
| SL09 / S4 | Authenticate, then disconnect but retain old ready log marker | Freshness expiry becomes non-ready despite a running PID | `D::test_old_authenticated_marker_cannot_prove_current_health` | Docker |
| SL10 / S5 | Crash after durable clinical delivery claim, then supervise restart | No second disclosure or reauthorization of ambiguous claim; payload erased | `D::test_supervised_restart_preserves_ambiguous_delivery_fence` | Docker |
| SL11 / S6 | Omit cap or add unmanaged application log path | Effective log inventory fails, never inferred complete from daemon cap | `U::test_every_log_sink_requires_an_effective_finite_bound` | Py |
| SL12 / S6 | Emit bounded synthetic log load across rotation threshold | Measured retained bytes/files stay within frozen envelope | `D::test_actual_log_rotation_respects_frozen_storage_envelope` | Docker |
| SL13 / S6-S7 | Inject synthetic secret/clinical canaries in scoped failures | No canary in logs, events, receipts, argv or sink acknowledgment | `D::test_failure_observability_contains_no_sensitive_canaries` | Docker |
| SL14 / S7 | Poll same failure repeatedly across observer restart; recover and fail in a new generation | One local event per transition; new transition has distinct ID | `U::test_events_deduplicate_by_bound_transition_not_forever` | Py |
| SL15 / S8 | Controlled sink acknowledges, then times out/rejects and queue fills | Confirmed versus unconfirmed delivery explicit; bounded retry/storage; no readiness promotion | `D::test_alert_failure_is_bounded_and_does_not_change_runtime_authority` | Docker |
| SL16 / S8 | Re-hash mixed-run/stale/container-only host witness or malformed event | Independent verifier rejects substitution and false host promotion | `U::test_supervision_evidence_requires_exact_frame_and_closed_events` | Py |
| SL17 / S3 | Use `source` alias or mix the two exact mode identities | No alias or source-build/published conflation | `U::test_supervision_mode_enum_has_no_aliases` | Py |
| SL18 / S1-S3 | Remove/rewrite retained generation files, change observe generation or give restart wrong parent | Recompute bytes and enforce equality/parent rules | `U::test_supervision_generation_bytes_and_parent_are_verified` | Py |
| SL19 / S8 | Give PASS/FAIL no proof, unresolved proof hash or NOT_VERIFIED invented proof | Exact retained-byte resolution and cardinality required | `U::test_supervision_proofs_require_declared_bytes_and_status_cardinality` | Py |
| SL20 / S7 | Alter event outcome/type/range/hash input or reuse sequence after observer restart | Closed scalars, derived outcome, recomputed event ID and persistent unique sequence enforced | `U::test_event_scalars_identity_and_persistent_sequence_are_closed` | Py |
| SL21 / S8 | Swap event, sink, attempt, result or proof in delivery acknowledgment | Exact binding rejected; sender-only/fixture evidence never proves real sink receipt | `U::test_acknowledgment_binds_exact_event_sink_attempt_result_and_proof` | Py |

Existing baseline tests to preserve include
`tests/unit/test_clinical_staging_tls.py::test_interrupted_renewal_blocks_up_status_backup_and_can_retry`,
`::test_expired_backup_restore_renews_before_start_or_remains_recovering`,
`tests/unit/test_clinical_staging_lifecycle.py::test_restore_interruption_never_publishes_stopped_or_ready_and_blocks_normal_up`,
and `tests/unit/test_clinical_adapter.py::test_main_fails_closed_when_websocket_worker_stops_without_terminal_event`.
Real cold-recovery and delivery-reauthorization runners remain integration
controls; mocks cannot replace those tests' causal application effects.

After implementation: `python -m pytest tests/unit/test_clinical_supervision_contract.py -q`
and `python tests/deployment/test_clinical_supervision_contract.py` in an isolated
Linux candidate environment. The planned runner must refuse unowned workloads,
missing frozen profile values or a real clinical sink. These entrypoints do
not exist yet; no results are claimed by listing their commands.

## Actual-host acceptance and handoff

These rows are **BLOCKED / NOT_VERIFIED**. Host operator + verifier produce A6
observations, with the existing accountable operator/risk decision in A8.

| ID / ledger mapping | Procedure and observable | Dependency |
|---|---|---|
| SH01 / H03 | `manual:host-effective-host-runtime-v1`: selected daemon/service-manager crash and host restart restore the exact candidate or stay failed within frozen budget; no cold-fence bypass | P1, S3, published resolver, SL01-SL09, effective egress profile |
| SH02 / H07 | `manual:host-logging-audit-sinks-v1`: actual stdout/stderr, daemon and application stores obey finite bounds; canaries absent | P1, SL11-SL13, frozen log/retention inventory |
| SH03 / H07 and P4 | `manual:operator-handoff-rehearsal-v1`: actual selected operator sink receives a safe failure/recovery event; unavailable sink stays unconfirmed; operator can locate unresolved state | G3, SL14-SL16, selected existing sink and accountable operator |
| SH04 / H01 dependency | `manual:host-backup-recovery-v1`: real restored candidate plus supervisor retains delivery and TLS fences | V4, SL04-SL06, SL10 |
| SH05 / H13-H15 dependencies | Existing secret rotation, time-source and trust-root procedures demonstrate that restart/health cannot conceal expired credentials/policy or invalid trust | G2/G3, frozen profile, SL07-SL09 |

Multiple safe witness files may support one existing A6 observation. H07 cannot
PASS with bounded local logs but absent real-sink evidence. No test here proves
all fifteen host observations or supplies an independent evaluator verdict.
Freeze supporting evidence only after exact K/G/profile readback, actual host
effects and retained witness verification; an unavailable operator remains an
explicit dependency, not a fictional test pass.

## Sequencing, collision and change control

1. Unit schema/event/decision tests and isolated health prototypes can proceed
   in their own files while published-mode work continues.
2. **Shared staging/Compose integration waits for the published-mode resolver**
   and its marker/source/subject contract. One integration owner changes
   `clinical_staging.py`, Compose overlays and common lifecycle fixtures.
   Do not add a competing source selector or source-build fallback.
3. Integrate the egress admission prerequisite and this supervisor through the
   existing lifecycle/lock owner. Keep the root provisioner one-shot. Receipt
   consumers must bind the final shared resolver/profile identity.
4. Run both source-build and published integration matrices, including TLS partial
   publication, interrupted restore, failed migration, policy expiration and
   ambiguous delivery. Source-build results cannot promote published evidence.
5. Observe the selected real host and real existing alert sink only after the
   frozen local contract is delivered; export missing observations truthfully.

A predicate/schema change requires a new version plus impact matrix (old/new
hash, changed row IDs, inputs, affected consumers, reruns, owner, reason and
freeze trigger). A mechanism-only change retains predicates but reruns affected
exact-candidate evidence. Do not reinterpret old ledger or collector bytes.

Pre-publication correction of local draft commit `54df4f0`: amend the initial
v1 freeze because no implemented collector, published schema consumer or actual
host witness exists. Impact: SL17 closes mode naming; SL18-SL19 consume the
corrected shared generation/proof contract; SL14/SL20-SL21 close event sequence,
identity and delivery acknowledgment. These planned rows must be implemented
and rerun together before witness freeze. Earlier asserted hashes/event bytes
are not grandfathered. Record the corrected document hashes in the new local
commit; ledger v2 and assessment payload schemas remain unchanged.

Nonclaims: no medical production deployment, PHI use, certification, BAA,
guaranteed delivery through an arbitrary external sink, general high
availability, multi-host orchestration, new vendor/cloud service, or non-Linux
host support. Durable operator retention and independent evaluation remain
separate existing responsibilities; this code plan cannot certify them.
