"""RED oracle for the byte-only clinical supervision contract.

Contract: docs/design/clinical-supervision-contract.v1.md at 3810cc1c.

This suite covers only SL11 and SL16-SL21. SL14 restart-persistent deduplication,
SL01-SL10, SL12-SL13, and SL15 require durable/runtime effects and remain NOT_VERIFIED in
the valid packet.  The fixtures are synthetic and prove neither a host effect
nor readiness for PHI, production, or compliance.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "tools" / "clinical_supervision_contract.py"
BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
EVENTS = "platform/supervision-events.v1.jsonl"
DELIVERIES = "platform/supervision-deliveries.v1.jsonl"
DELIVERY_PROOF = "platform/proofs/delivery-1.json"
COVERED_ROWS = {"SL11", *(f"SL{index:02}" for index in range(16, 22))}
ROW_PROOFS = {row: f"platform/proofs/{row.lower()}.json" for row in COVERED_ROWS}
CANDIDATE = "sha256:" + "1" * 64
CONTRACT_HASH = "2" * 64
MANIFEST_HASH = "3" * 64
PROFILE_HASH = "4" * 64
HOST_HASH = "5" * 64
ALL_ROWS = tuple(f"SL{index:02}" for index in range(1, 22)) + tuple(
    f"SH{index:02}" for index in range(1, 6)
)
NOT_VERIFIED_ROWS = {
    *(f"SL{index:02}" for index in range(1, 11)),
    "SL12",
    "SL13",
    "SL14",
    "SL15",
    *(f"SH{index:02}" for index in range(1, 6)),
}

assert COVERED_ROWS | NOT_VERIFIED_ROWS == set(ALL_ROWS)
assert COVERED_ROWS.isdisjoint(NOT_VERIFIED_ROWS)


def canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def jsonl(values: list[dict[str, object]]) -> bytes:
    return b"".join(canonical(value) for value in values)


def event_id(event: dict[str, object]) -> str:
    identity = {
        key: event[key]
        for key in (
            "candidate_id",
            "generation_sha256",
            "service",
            "transition_sequence",
            "event_class",
        )
    }
    return sha256(b"restricted-clinical-supervision-event.v1\n" + canonical(identity))


@pytest.fixture
def parser():
    assert MODULE.is_file(), "RED: clinical supervision byte verifier is not implemented"
    spec = importlib.util.spec_from_file_location("clinical_supervision_contract_test", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generation(*, container: str = "6" * 64, started: str = "2026-09-07T12:00:00.123456789Z"):
    return {
        "schema": "restricted-clinical-platform-generation.v1",
        "mode": "published",
        "candidate_id": CANDIDATE,
        "policy": {"epoch": "Synthetic-Epoch-1", "digest": "7" * 64},
        "compose_sha256": "8" * 64,
        "resolver_sha": "9" * 40,
        "project": "clinical_test",
        "state_id": "state_1",
        "host_baseline_sha256": HOST_HASH,
        "enforcement_sha256": "a" * 64,
        "workloads": [
            {
                "service": "ingress",
                "container_id": container,
                "image_id": "sha256:" + "b" * 64,
                "image_digest": "sha256:" + "c" * 64,
                "started_at": started,
                "networks": [
                    {
                        "network_id": "d" * 64,
                        "name_sha256": "e" * 64,
                        "internal": True,
                    }
                ],
            },
            {
                "service": "lifecycle-observer",
                "container_id": "f" * 64,
                "image_id": "sha256:" + "0" * 64,
                "image_digest": "sha256:" + "a" * 64,
                "started_at": started,
                "networks": [],
            },
        ],
    }


def make_event(
    generation_hash: str,
    *,
    sequence: int = 1,
    event_class: str = "terminal_failure",
    outcome: str = "FAILED",
    observed_at: str = "2026-09-07T12:01:00.123Z",
):
    event = {
        "schema": "restricted-clinical-supervision-event.v1",
        "event_id": "",
        "candidate_id": CANDIDATE,
        "generation_sha256": generation_hash,
        "service": "ingress",
        "transition_sequence": sequence,
        "event_class": event_class,
        "observed_at": observed_at,
        "outcome": outcome,
    }
    event["event_id"] = event_id(event)
    return event


def packet():
    before = canonical(generation())
    after = before
    generation_hash = sha256(before)
    event = make_event(generation_hash)
    sink = "6" * 64
    proof = {
        "schema": "restricted-clinical-supervision-delivery-proof.v1",
        "event_id": event["event_id"],
        "sink_id_sha256": sink,
        "attempt": 1,
        "result": "DELIVERED",
        "observed_at": "2026-09-07T12:01:01.000Z",
        "evidence_class": "receiver_readback",
    }
    delivery = {
        "schema": "restricted-clinical-supervision-delivery.v1",
        "event_id": event["event_id"],
        "sink_id_sha256": sink,
        "attempt": 1,
        "attempted_at": "2026-09-07T12:01:00.500Z",
        "completed_at": "2026-09-07T12:01:01.500Z",
        "result": "DELIVERED",
        "proof_sha256": "",
    }
    retained = {
        BEFORE: before,
        AFTER: after,
        EVENTS: jsonl([event]),
        DELIVERY_PROOF: canonical(proof),
    }
    for row, path in ROW_PROOFS.items():
        retained[path] = canonical(
            {
                "schema": "restricted-clinical-supervision-test-proof.v1",
                "scope": "SYNTHETIC_NON_PHI_ONLY",
                "row": row,
                "expected_rejection": f"{row.lower()}-negative-control",
                "observed": "rejected",
            }
        )
    delivery["proof_sha256"] = sha256(retained[DELIVERY_PROOF])
    retained[DELIVERIES] = jsonl([delivery])
    observations = []
    for row in ALL_ROWS:
        if row in COVERED_ROWS:
            observations.append(
                {
                    "id": row,
                    "outcome": "PASS",
                    "diagnostic": "none",
                    "proof_sha256s": [sha256(retained[ROW_PROOFS[row]])],
                }
            )
        else:
            observations.append(
                {
                    "id": row,
                    "outcome": "NOT_VERIFIED",
                    "diagnostic": "host-not-observed",
                    "proof_sha256s": [],
                }
            )
    witness = {
        "schema": "restricted-clinical-supervision-witness.v1",
        "scope": "SYNTHETIC_NON_PHI_ONLY",
        "contract_sha256": CONTRACT_HASH,
        "candidate_manifest_sha256": MANIFEST_HASH,
        "mode": "published",
        "producer": {
            "id": "synthetic-runner",
            "run_id": "synthetic-run-1",
            "engine": "Py",
            "toolchain_sha256": "7" * 64,
        },
        "host_baseline_sha256": HOST_HASH,
        "generation": {
            "operation": "observe",
            "before_sha256": generation_hash,
            "after_sha256": generation_hash,
            "parent_sha256": None,
        },
        "profile_sha256": PROFILE_HASH,
        "observations": observations,
        "witness_files": [
            {
                "path": path,
                "sha256": sha256(value),
                "size": len(value),
                "media_type": "application/x-ndjson" if path.endswith(".jsonl") else "application/json",
            }
            for path, value in sorted(retained.items())
        ],
    }
    expected = {
        "expected_before": before,
        "expected_after": after,
        "expected_contract_sha256": CONTRACT_HASH,
        "expected_candidate_manifest_sha256": MANIFEST_HASH,
        "expected_mode": "published",
        "expected_producer": deepcopy(witness["producer"]),
        "expected_host_baseline_sha256": HOST_HASH,
        "expected_profile_sha256": PROFILE_HASH,
        "expected_services": ("ingress", "lifecycle-observer"),
        "sequence_floor": {
            (CANDIDATE, "ingress"): 0,
            (CANDIDATE, "lifecycle-observer"): 0,
        },
        "expected_sink_ids_sha256": (sink,),
    }
    return witness, retained, expected


def refresh(packet_value):
    witness, retained, _ = packet_value
    witness["witness_files"] = [
        {
            "path": path,
            "sha256": sha256(value),
            "size": len(value),
            "media_type": "application/x-ndjson" if path.endswith(".jsonl") else "application/json",
        }
        for path, value in sorted(retained.items())
    ]


def replace_event(packet_value, event):
    """Replace the sole event while preserving all dependent exact bindings."""
    _, retained, _ = packet_value
    event["event_id"] = event_id(event)
    retained[EVENTS] = jsonl([event])
    proof = json.loads(retained[DELIVERY_PROOF])
    proof["event_id"] = event["event_id"]
    retained[DELIVERY_PROOF] = canonical(proof)
    delivery = json.loads(retained[DELIVERIES].decode())
    delivery["event_id"] = event["event_id"]
    delivery["proof_sha256"] = sha256(retained[DELIVERY_PROOF])
    retained[DELIVERIES] = jsonl([delivery])


def validate(parser, packet_value, *, refresh_files=True):
    if refresh_files:
        refresh(packet_value)
    witness, retained, expected = packet_value
    return parser.validate_witness(canonical(witness), retained, **expected)


def assert_rejected(parser, packet_value, match: str | None = None):
    error = getattr(parser, "ContractError", ValueError)
    with pytest.raises(error, match=match):
        validate(parser, packet_value)


def test_every_log_sink_requires_an_effective_finite_bound(parser):
    required = {
        "ingress": ("stdout", "daemon"),
        "lifecycle-observer": ("stdout", "daemon", "application:/var/lib/observer/events.jsonl"),
    }
    effective = {
        service: {
            sink: {"max_bytes": 1_048_576, "max_files": 3}
            for sink in sinks
        }
        for service, sinks in required.items()
    }
    assert parser.validate_log_inventory(required, effective) is None
    for mutant in (
        lambda value: value["ingress"].pop("daemon"),
        lambda value: value["ingress"].update(
            {"unexpected.log": {"max_bytes": 10, "max_files": 1}}
        ),
        lambda value: value["ingress"]["stdout"].pop("max_bytes"),
        lambda value: value["ingress"]["stdout"].update(max_bytes=0),
        lambda value: value["ingress"]["stdout"].update(max_files=True),
    ):
        changed = deepcopy(effective)
        mutant(changed)
        with pytest.raises(parser.ContractError):
            parser.validate_log_inventory(required, changed)


def test_events_deduplicate_within_one_retained_stream(parser):
    value = packet()
    assert validate(parser, value) is None  # positive control prevents blanket rejection

    duplicate = packet()
    _, retained, _ = duplicate
    event = json.loads(retained[EVENTS].decode())
    retained[EVENTS] = jsonl([event, event])
    assert_rejected(parser, duplicate)

    next_transition = packet()
    _, retained, _ = next_transition
    first = json.loads(retained[EVENTS].decode())
    second = make_event(first["generation_sha256"], sequence=2, event_class="recovered", outcome="SUCCEEDED")
    retained[EVENTS] = jsonl([first, second])
    validate(parser, next_transition)


def test_zero_byte_event_and_delivery_streams_represent_no_attempt(parser):
    value = packet()
    value[1][EVENTS] = b""
    value[1][DELIVERIES] = b""
    value[1].pop(DELIVERY_PROOF)
    validate(parser, value)


def test_every_service_stream_requires_an_independent_sequence_floor(parser):
    missing = packet()
    missing[2]["sequence_floor"].pop((CANDIDATE, "lifecycle-observer"))
    assert_rejected(parser, missing, match="sequence-floor")

    undeclared = packet()
    undeclared[2]["sequence_floor"][(CANDIDATE, "mattermost")] = 0
    assert_rejected(parser, undeclared, match="sequence-floor")

    implicit_new_stream = packet()
    implicit_new_stream[2]["sequence_floor"].pop((CANDIDATE, "ingress"))
    assert_rejected(parser, implicit_new_stream, match="sequence-floor")


def test_supervision_evidence_requires_exact_frame_and_closed_events(parser):
    valid = packet()
    assert validate(parser, valid) is None
    outcomes = {item["id"]: item["outcome"] for item in valid[0]["observations"]}
    assert {row for row, outcome in outcomes.items() if outcome == "PASS"} == COVERED_ROWS
    assert {
        row for row, outcome in outcomes.items() if outcome == "NOT_VERIFIED"
    } == NOT_VERIFIED_ROWS
    proof_sets = {
        item["id"]: tuple(item["proof_sha256s"])
        for item in valid[0]["observations"]
        if item["id"] in COVERED_ROWS
    }
    assert all(len(proofs) == 1 for proofs in proof_sets.values())
    assert len({proofs[0] for proofs in proof_sets.values()}) == len(COVERED_ROWS)

    mutations = []
    wrong_contract = packet()
    wrong_contract[0]["contract_sha256"] = "8" * 64
    mutations.append(wrong_contract)
    wrong_mode = packet()
    wrong_mode[0]["mode"] = "source-build"
    mutations.append(wrong_mode)
    wrong_producer = packet()
    wrong_producer[0]["producer"]["run_id"] = "mixed-run"
    mutations.append(wrong_producer)

    wrong_manifest = packet()
    wrong_manifest[0]["candidate_manifest_sha256"] = "b" * 64
    mutations.append(wrong_manifest)
    wrong_host = packet()
    wrong_host[0]["host_baseline_sha256"] = "b" * 64
    mutations.append(wrong_host)
    wrong_profile = packet()
    wrong_profile[0]["profile_sha256"] = "b" * 64
    mutations.append(wrong_profile)
    wrong_candidate = packet()
    event = json.loads(wrong_candidate[1][EVENTS].decode())
    event["candidate_id"] = "sha256:" + "b" * 64
    replace_event(wrong_candidate, event)
    mutations.append(wrong_candidate)
    wrong_schema = packet()
    wrong_schema[0]["schema"] = "restricted-clinical-supervision-witness.v2"
    mutations.append(wrong_schema)
    wrong_scope = packet()
    wrong_scope[0]["scope"] = "PRODUCTION"
    mutations.append(wrong_scope)
    unknown_root = packet()
    unknown_root[0]["asserted_safe"] = True
    mutations.append(unknown_root)

    unknown_event_field = packet()
    event = json.loads(unknown_event_field[1][EVENTS].decode())
    event["detail"] = "must-not-exist"
    unknown_event_field[1][EVENTS] = jsonl([event])
    mutations.append(unknown_event_field)
    noncanonical = packet()
    noncanonical[1][EVENTS] = json.dumps(json.loads(noncanonical[1][EVENTS])).encode() + b"\n"
    mutations.append(noncanonical)
    for changed in mutations:
        assert_rejected(parser, changed)


def test_supervision_mode_enum_has_no_aliases(parser):
    assert validate(parser, packet()) is None
    for mode in ("source", "Published", "PUBLISHED", "unknown", ""):
        changed = packet()
        changed[0]["mode"] = mode
        changed[2]["expected_mode"] = mode
        assert_rejected(parser, changed)


def test_supervision_generation_bytes_and_parent_are_verified(parser):
    validate(parser, packet())
    removed = packet()
    removed[1].pop(AFTER)
    assert_rejected(parser, removed)
    rewritten = packet()
    after_value = generation(container="8" * 64)
    rewritten[1][AFTER] = canonical(after_value)
    rewritten[0]["generation"]["after_sha256"] = sha256(rewritten[1][AFTER])
    rewritten[2]["expected_after"] = rewritten[1][AFTER]
    assert_rejected(parser, rewritten)
    wrong_parent = packet()
    wrong_parent[0]["generation"].update(operation="restart", parent_sha256="9" * 64)
    assert_rejected(parser, wrong_parent)
    asserted_only = packet()
    asserted_only[0]["generation"]["before_sha256"] = "a" * 64
    assert_rejected(parser, asserted_only)

    failed_changed = packet()
    failed_changed[0]["generation"].update(
        operation="restart",
        parent_sha256=sha256(failed_changed[1][BEFORE]),
    )
    failed_changed[1][AFTER] = canonical(generation(container="8" * 64))
    failed_changed[0]["generation"]["after_sha256"] = sha256(
        failed_changed[1][AFTER]
    )
    failed_changed[2]["expected_after"] = failed_changed[1][AFTER]
    assert_rejected(parser, failed_changed)


def test_recovered_event_requires_linked_changed_workload_generation(parser):
    valid = packet()
    before_hash = sha256(valid[1][BEFORE])
    valid[1][AFTER] = canonical(
        generation(container="8" * 64, started="2026-09-07T12:02:00.123456789Z")
    )
    after_hash = sha256(valid[1][AFTER])
    valid[0]["generation"].update(
        operation="restart",
        before_sha256=before_hash,
        after_sha256=after_hash,
        parent_sha256=before_hash,
    )
    valid[2]["expected_after"] = valid[1][AFTER]
    recovered = make_event(
        after_hash,
        event_class="recovered",
        outcome="SUCCEEDED",
    )
    replace_event(valid, recovered)
    assert validate(parser, valid) is None

    unchanged = packet()
    unchanged_hash = sha256(unchanged[1][BEFORE])
    unchanged[0]["generation"].update(
        operation="restart",
        parent_sha256=unchanged_hash,
    )
    recovered = make_event(
        unchanged_hash,
        event_class="recovered",
        outcome="SUCCEEDED",
    )
    replace_event(unchanged, recovered)
    assert_rejected(parser, unchanged, match="restart-unchanged-generation")


def test_supervision_proofs_require_declared_bytes_and_status_cardinality(parser):
    validate(parser, packet())
    no_pass_proof = packet()
    sl19 = next(row for row in no_pass_proof[0]["observations"] if row["id"] == "SL19")
    sl19["proof_sha256s"] = []
    assert_rejected(parser, no_pass_proof)
    unresolved = packet()
    sl19 = next(row for row in unresolved[0]["observations"] if row["id"] == "SL19")
    sl19["proof_sha256s"] = ["f" * 64]
    assert_rejected(parser, unresolved)
    invented_missing = packet()
    sl11 = next(row for row in invented_missing[0]["observations"] if row["id"] == "SL11")
    sl11["outcome"] = "NOT_VERIFIED"
    sl11["diagnostic"] = "host-not-observed"
    sl11["proof_sha256s"] = [sha256(invented_missing[1][ROW_PROOFS["SL11"]])]
    assert_rejected(parser, invented_missing)
    duplicate = packet()
    sl19 = next(row for row in duplicate[0]["observations"] if row["id"] == "SL19")
    sl19["proof_sha256s"] *= 2
    assert_rejected(parser, duplicate)


def test_event_scalars_identity_and_persistent_sequence_are_closed(parser):
    validate(parser, packet())
    mutations = []
    for change in (
        lambda event: event.update(outcome="SUCCEEDED"),
        lambda event: event.update(event_id="0" * 64),
        lambda event: event.update(transition_sequence=True),
        lambda event: event.update(observed_at="2026-09-07T12:01:00Z"),
        lambda event: event.update(service="unowned-service"),
    ):
        changed = packet()
        event = json.loads(changed[1][EVENTS].decode())
        change(event)
        changed[1][EVENTS] = jsonl([event])
        mutations.append(changed)
    rollback = packet()
    rollback[2]["sequence_floor"] = {(CANDIDATE, "ingress"): 1}
    mutations.append(rollback)

    reused_sequence_with_valid_new_id = packet()
    first = json.loads(reused_sequence_with_valid_new_id[1][EVENTS].decode())
    second = make_event(
        first["generation_sha256"],
        sequence=first["transition_sequence"],
        event_class="recovered",
        outcome="SUCCEEDED",
        observed_at="2026-09-07T12:02:00.123Z",
    )
    assert second["event_id"] == event_id(second)
    assert second["event_id"] != first["event_id"]
    reused_sequence_with_valid_new_id[1][EVENTS] = jsonl([first, second])
    mutations.append(reused_sequence_with_valid_new_id)
    for changed in mutations:
        assert_rejected(parser, changed)


def test_acknowledgment_binds_exact_event_sink_attempt_result_and_proof(parser):
    validate(parser, packet())
    for field, value in (
        ("event_id", "0" * 64),
        ("sink_id_sha256", "1" * 64),
        ("attempt", 2),
        ("result", "TIMED_OUT"),
        ("proof_sha256", "2" * 64),
        ("completed_at", "2026-09-07T12:00:00.000Z"),
    ):
        changed = packet()
        delivery = json.loads(changed[1][DELIVERIES].decode())
        delivery[field] = value
        changed[1][DELIVERIES] = jsonl([delivery])
        assert_rejected(parser, changed)

    attempt_precedes_event = packet()
    delivery = json.loads(attempt_precedes_event[1][DELIVERIES].decode())
    delivery["attempted_at"] = "2026-09-07T12:00:59.999Z"
    attempt_precedes_event[1][DELIVERIES] = jsonl([delivery])
    assert_rejected(parser, attempt_precedes_event)

    proof_outside_attempt = packet()
    proof = json.loads(proof_outside_attempt[1][DELIVERY_PROOF])
    proof["observed_at"] = "2026-09-07T12:01:02.000Z"
    proof_outside_attempt[1][DELIVERY_PROOF] = canonical(proof)
    delivery = json.loads(proof_outside_attempt[1][DELIVERIES].decode())
    delivery["proof_sha256"] = sha256(proof_outside_attempt[1][DELIVERY_PROOF])
    proof_outside_attempt[1][DELIVERIES] = jsonl([delivery])
    assert_rejected(parser, proof_outside_attempt)

    sender_only = packet()
    proof = json.loads(sender_only[1][DELIVERY_PROOF])
    proof["evidence_class"] = "sender_enqueue"
    sender_only[1][DELIVERY_PROOF] = canonical(proof)
    delivery = json.loads(sender_only[1][DELIVERIES].decode())
    delivery["proof_sha256"] = sha256(sender_only[1][DELIVERY_PROOF])
    sender_only[1][DELIVERIES] = jsonl([delivery])
    assert_rejected(parser, sender_only)

    duplicate_attempt = packet()
    first = json.loads(duplicate_attempt[1][DELIVERIES].decode())
    second = deepcopy(first)
    second["completed_at"] = "2026-09-07T12:01:02.000Z"
    duplicate_attempt[1][DELIVERIES] = jsonl([first, second])
    assert_rejected(parser, duplicate_attempt)


def test_matched_delivery_and_proof_cannot_invent_an_unapproved_sink(parser):
    changed = packet()
    arbitrary_sink = "f" * 64
    proof = json.loads(changed[1][DELIVERY_PROOF])
    proof["sink_id_sha256"] = arbitrary_sink
    changed[1][DELIVERY_PROOF] = canonical(proof)
    delivery = json.loads(changed[1][DELIVERIES].decode())
    delivery["sink_id_sha256"] = arbitrary_sink
    delivery["proof_sha256"] = sha256(changed[1][DELIVERY_PROOF])
    changed[1][DELIVERIES] = jsonl([delivery])
    assert_rejected(parser, changed, match="delivery-sink")
