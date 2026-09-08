"""Validate retained clinical-supervision bytes without claiming host effects.

This module has no collector, CLI, Docker, filesystem, environment, or network
access.  Generation documents are delegated to the shared egress grammar;
successful return proves only closed byte structure and caller-supplied frame
bindings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from tools.clinical_host_egress_contract import (
    ContractError as GenerationContractError,
    validate_generation_bytes,
)


BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
EVENTS = "platform/supervision-events.v1.jsonl"
DELIVERIES = "platform/supervision-deliveries.v1.jsonl"
WITNESS = "platform/supervision-witness.v1.json"
ROWS = tuple(f"SL{index:02}" for index in range(1, 22)) + tuple(
    f"SH{index:02}" for index in range(1, 6)
)
_ROOT_KEYS = {
    "schema",
    "scope",
    "contract_sha256",
    "candidate_manifest_sha256",
    "mode",
    "producer",
    "host_baseline_sha256",
    "generation",
    "profile_sha256",
    "observations",
    "witness_files",
}
_PRODUCER_KEYS = {"id", "run_id", "engine", "toolchain_sha256"}
_EVENT_KEYS = {
    "schema",
    "event_id",
    "candidate_id",
    "generation_sha256",
    "service",
    "transition_sequence",
    "event_class",
    "observed_at",
    "outcome",
}
_DELIVERY_KEYS = {
    "schema",
    "event_id",
    "sink_id_sha256",
    "attempt",
    "attempted_at",
    "completed_at",
    "result",
    "proof_sha256",
}
_PROOF_KEYS = {
    "schema",
    "event_id",
    "sink_id_sha256",
    "attempt",
    "result",
    "observed_at",
    "evidence_class",
}
_EVENT_OUTCOMES = {
    "recovery_started": "PENDING",
    "recovered": "SUCCEEDED",
    "terminal_failure": "FAILED",
    "recovery_exhausted": "FAILED",
    "health_degraded": "DEGRADED",
    "cold_fence_held": "BLOCKED",
    "logging_failed": "FAILED",
    "alert_delivery_failed": "FAILED",
}
_PROOF_CLASSES = {
    "DELIVERED": "receiver_readback",
    "REJECTED": "receiver_rejection",
    "TIMED_OUT": "deadline_observed",
    "TRANSPORT_ERROR": "transport_failure",
}
_SERVICES = {
    "mattermost-postgres",
    "mattermost",
    "hrh-postgres",
    "hrh",
    "hrh-tls",
    "clinical-adapter",
    "ingress",
    "operator-proxy",
    "hrh-migrate",
    "clinical-socket-init",
    "controller",
    "lifecycle-observer",
}
_MISSING = {"witness-unavailable", "host-not-observed"}
_DIAGNOSTICS = _MISSING | {
    "none",
    "identity-mismatch",
    "cold-fence",
    "recovery-budget-exhausted",
    "dependency-unready",
    "stale-health",
    "terminal-rejection",
    "delivery-safety-failed",
    "log-bound-unverified",
    "content-leak",
    "alert-unconfirmed",
}
_SHA = re.compile(r"[a-f0-9]{64}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_STAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z",
    re.ASCII,
)
_HASH_TOKEN = re.compile(rb"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")
_MAX_INTEGER = 9_007_199_254_740_991


class ContractError(ValueError):
    """Content-free supervision-contract failure."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _closed(value: object, fields: set[str], code: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == fields, code)
    return value


def _text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _integer(value: object, *, minimum: int = 1) -> bool:
    return type(value) is int and minimum <= value <= _MAX_INTEGER


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        _require(name not in result, "json-duplicate-key")
        result[name] = value
    return result


def _no_number(value: str) -> None:
    raise ContractError("json-noninteger-number")


def _canonical_object(raw: bytes) -> dict[str, Any]:
    _require(isinstance(raw, bytes) and bool(raw), "json-bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
        _require(isinstance(value, dict), "json-object")
        encoded = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("json-canonical") from None
    _require(encoded == raw, "json-canonical")
    return value


def _jsonl(raw: bytes, code: str, *, allow_empty: bool = False) -> list[dict[str, Any]]:
    _require(isinstance(raw, bytes), code)
    if raw == b"":
        _require(allow_empty, code)
        return []
    _require(raw.endswith(b"\n"), code)
    lines = raw.splitlines(keepends=True)
    _require(bool(lines) and all(line != b"\n" for line in lines), code)
    return [_canonical_object(line) for line in lines]


def _timestamp(value: object) -> datetime | None:
    match = _STAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    parts = [int(part) for part in match.groups()]
    if parts[0] < 1970:
        return None
    try:
        return datetime(*parts[:6], microsecond=parts[6] * 1000)
    except ValueError:
        return None


def _sorted_unique(values: list[str], code: str) -> None:
    _require(values == sorted(set(values)), code)


def _relative_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value != WITNESS
        and not value.startswith("/")
        and not any(character in value for character in ("\\", ":"))
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _producer(value: object) -> dict[str, Any]:
    row = _closed(value, _PRODUCER_KEYS, "producer-fields")
    _require(
        all(_text(row[field]) for field in ("id", "run_id", "engine"))
        and _sha(row["toolchain_sha256"]),
        "producer-values",
    )
    return row


def validate_log_inventory(
    required: Mapping[str, Iterable[str]],
    effective: Mapping[str, Mapping[str, Mapping[str, int]]],
) -> None:
    """Require one finite effective cap for every and only declared log sink."""
    _require(isinstance(required, Mapping), "log-required-mapping")
    _require(isinstance(effective, Mapping), "log-effective-mapping")
    _require(set(required) == set(effective), "log-service-inventory")
    for service, sinks_value in required.items():
        _require(_text(service), "log-service")
        _require(not isinstance(sinks_value, (str, bytes)), "log-sink-inventory")
        try:
            sinks = list(sinks_value)
        except TypeError:
            raise ContractError("log-sink-inventory") from None
        _require(bool(sinks) and all(_text(sink) for sink in sinks), "log-sink-inventory")
        _require(len(sinks) == len(set(sinks)), "log-sink-inventory")
        configured = effective[service]
        _require(isinstance(configured, Mapping), "log-effective-service")
        _require(set(configured) == set(sinks), "log-sink-inventory")
        for limits in configured.values():
            row = _closed(limits, {"max_bytes", "max_files"}, "log-limit-fields")
            _require(
                _integer(row["max_bytes"]) and _integer(row["max_files"]),
                "log-limit-values",
            )


def _file_inventory(
    witness: dict[str, Any], retained: Mapping[str, bytes], witness_hash: str
) -> tuple[set[str], dict[str, bytes]]:
    _require(isinstance(retained, Mapping), "retained-bytes-mapping")
    entries = witness["witness_files"]
    _require(isinstance(entries, list), "witness-file-list")
    paths: list[str] = []
    hashes: set[str] = set()
    by_hash: dict[str, bytes] = {}
    for item in entries:
        row = _closed(
            item,
            {"path", "sha256", "size", "media_type"},
            "witness-file-fields",
        )
        path = row["path"]
        _require(_relative_path(path), "witness-file-path")
        _require(
            _sha(row["sha256"])
            and _integer(row["size"], minimum=0 if path in {EVENTS, DELIVERIES} else 1)
            and row["size"] <= 1_048_576
            and _text(row["media_type"]),
            "witness-file-values",
        )
        raw = retained.get(path)
        _require(
            isinstance(raw, bytes)
            and len(raw) == row["size"]
            and _hash(raw) == row["sha256"],
            "witness-file-bytes",
        )
        _require(witness_hash.encode() not in raw, "witness-self-reference")
        expected_media = (
            "application/x-ndjson" if path in {EVENTS, DELIVERIES} else "application/json"
        )
        _require(row["media_type"] == expected_media, "witness-file-media-type")
        paths.append(path)
        hashes.add(row["sha256"])
        by_hash[row["sha256"]] = raw
    _sorted_unique(paths, "witness-file-order")
    _require(
        set(paths) == set(retained)
        and {BEFORE, AFTER, EVENTS, DELIVERIES} <= set(paths),
        "witness-file-inventory",
    )
    graph = {
        _hash(raw): {
            token.decode() for token in _HASH_TOKEN.findall(raw)
        }
        & hashes
        for raw in retained.values()
    }
    pending: set[str] = set()
    complete: set[str] = set()

    def visit(node: str) -> None:
        _require(node not in pending, "witness-reference-cycle")
        if node in complete:
            return
        pending.add(node)
        for child in graph[node]:
            visit(child)
        pending.remove(node)
        complete.add(node)

    try:
        for node in graph:
            visit(node)
    except RecursionError:
        raise ContractError("witness-reference-depth") from None
    return hashes, by_hash


def _observations(
    value: object, retained_hashes: set[str], generation_hashes: set[str]
) -> None:
    _require(isinstance(value, list), "observation-list")
    identifiers = []
    for item in value:
        row = _closed(
            item,
            {"id", "outcome", "diagnostic", "proof_sha256s"},
            "observation-fields",
        )
        identifier = row["id"]
        _require(isinstance(identifier, str) and identifier in ROWS, "observation-id")
        identifiers.append(identifier)
        _require(
            isinstance(row["diagnostic"], str)
            and row["diagnostic"] in _DIAGNOSTICS,
            "observation-diagnostic",
        )
        proofs = row["proof_sha256s"]
        _require(
            isinstance(proofs, list) and all(_sha(proof) for proof in proofs),
            "observation-proof-list",
        )
        _sorted_unique(proofs, "observation-proof-order")
        _require(set(proofs) <= retained_hashes, "observation-proof-unresolved")
        if row["outcome"] == "NOT_VERIFIED":
            _require(
                proofs == [] and row["diagnostic"] in _MISSING,
                "observation-unverified",
            )
        elif row["outcome"] in {"PASS", "FAIL"}:
            _require(
                1 <= len(proofs) <= 64
                and bool(set(proofs) - generation_hashes),
                "observation-proof-cardinality",
            )
            _require(
                (row["diagnostic"] == "none")
                if row["outcome"] == "PASS"
                else row["diagnostic"] not in _MISSING | {"none"},
                "observation-outcome-diagnostic",
            )
        else:
            raise ContractError("observation-outcome")
    _require(tuple(identifiers) == ROWS, "observation-inventory")


def _event_identifier(event: Mapping[str, Any]) -> str:
    identity = {
        field: event[field]
        for field in (
            "candidate_id",
            "generation_sha256",
            "service",
            "transition_sequence",
            "event_class",
        )
    }
    encoded = (
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    return _hash(b"restricted-clinical-supervision-event.v1\n" + encoded)


def _events(
    raw: bytes,
    *,
    candidate_id: str,
    services: list[str],
    generation_hashes: set[str],
    sequence_floor: Mapping[tuple[str, str], int],
) -> dict[str, dict[str, Any]]:
    _require(isinstance(sequence_floor, Mapping), "sequence-floor")
    floors: dict[tuple[str, str], int] = {}
    for key, value in sequence_floor.items():
        _require(
            isinstance(key, tuple)
            and len(key) == 2
            and key[0] == candidate_id
            and key[1] in services
            and _integer(value, minimum=0),
            "sequence-floor",
        )
        floors[key] = value
    _require(
        set(floors) == {(candidate_id, service) for service in services},
        "sequence-floor",
    )
    events: dict[str, dict[str, Any]] = {}
    last = dict(floors)
    for item in _jsonl(raw, "event-stream", allow_empty=True):
        event = _closed(item, _EVENT_KEYS, "event-fields")
        _require(
            event["schema"] == "restricted-clinical-supervision-event.v1",
            "event-schema",
        )
        _require(event["candidate_id"] == candidate_id, "event-candidate")
        _require(event["generation_sha256"] in generation_hashes, "event-generation")
        _require(
            isinstance(event["service"], str) and event["service"] in services,
            "event-service",
        )
        _require(_integer(event["transition_sequence"]), "event-sequence")
        _require(_timestamp(event["observed_at"]) is not None, "event-timestamp")
        _require(
            isinstance(event["event_class"], str)
            and event["event_class"] in _EVENT_OUTCOMES
            and event["outcome"] == _EVENT_OUTCOMES[event["event_class"]],
            "event-outcome",
        )
        _require(
            _sha(event["event_id"]) and event["event_id"] == _event_identifier(event),
            "event-id",
        )
        key = (candidate_id, event["service"])
        _require(event["transition_sequence"] > last[key], "event-sequence-order")
        last[key] = event["transition_sequence"]
        _require(event["event_id"] not in events, "event-duplicate")
        events[event["event_id"]] = event
    return events


def _deliveries(
    raw: bytes,
    *,
    events: Mapping[str, dict[str, Any]],
    retained_by_hash: Mapping[str, bytes],
    expected_sink_ids_sha256: set[str],
) -> None:
    attempts: dict[tuple[str, str, int], dict[str, Any]] = {}
    highest: dict[tuple[str, str], int] = {}
    for item in _jsonl(raw, "delivery-stream", allow_empty=True):
        delivery = _closed(item, _DELIVERY_KEYS, "delivery-fields")
        _require(
            delivery["schema"] == "restricted-clinical-supervision-delivery.v1",
            "delivery-schema",
        )
        _require(_sha(delivery["event_id"]), "delivery-event")
        event = events.get(delivery["event_id"])
        _require(event is not None, "delivery-event")
        _require(
            _sha(delivery["sink_id_sha256"])
            and delivery["sink_id_sha256"] in expected_sink_ids_sha256,
            "delivery-sink",
        )
        _require(_integer(delivery["attempt"]), "delivery-attempt")
        attempted = _timestamp(delivery["attempted_at"])
        completed = _timestamp(delivery["completed_at"])
        observed = _timestamp(event["observed_at"])
        _require(
            attempted is not None
            and completed is not None
            and observed is not None
            and completed >= attempted >= observed,
            "delivery-time",
        )
        _require(
            isinstance(delivery["result"], str)
            and delivery["result"] in _PROOF_CLASSES,
            "delivery-result",
        )
        _require(_sha(delivery["proof_sha256"]), "delivery-proof-hash")
        proof_raw = retained_by_hash.get(delivery["proof_sha256"])
        _require(proof_raw is not None, "delivery-proof-unresolved")
        proof = _closed(_canonical_object(proof_raw), _PROOF_KEYS, "delivery-proof-fields")
        proof_time = _timestamp(proof["observed_at"])
        _require(
            proof["schema"]
            == "restricted-clinical-supervision-delivery-proof.v1",
            "delivery-proof-schema",
        )
        for field in ("event_id", "sink_id_sha256", "attempt", "result"):
            _require(proof[field] == delivery[field], "delivery-proof-binding")
        _require(
            proof["evidence_class"] == _PROOF_CLASSES[delivery["result"]],
            "delivery-proof-class",
        )
        _require(
            proof_time is not None and attempted <= proof_time <= completed,
            "delivery-proof-time",
        )
        pair = (delivery["event_id"], delivery["sink_id_sha256"])
        key = (*pair, delivery["attempt"])
        if key in attempts:
            _require(attempts[key] == delivery, "delivery-attempt-reused")
            continue
        _require(delivery["attempt"] > highest.get(pair, 0), "delivery-attempt-order")
        attempts[key] = delivery
        highest[pair] = delivery["attempt"]


def _transition(
    before: dict[str, Any],
    after: dict[str, Any],
    operation: str,
    events: Mapping[str, dict[str, Any]],
    after_hash: str,
) -> None:
    if operation == "observe":
        _require(before == after, "observe-generation-binding")
        return
    _require(operation == "restart", "generation-operation")
    for field in set(before) - {"workloads"}:
        _require(before[field] == after[field], "restart-profile-binding")
    old = {row["service"]: row for row in before["workloads"]}
    new = {row["service"]: row for row in after["workloads"]}
    _require(set(old) == set(new), "restart-workload-inventory")
    stable = set(next(iter(old.values()))) - {"container_id", "started_at"}
    for service, row in old.items():
        _require(
            all(row[field] == new[service][field] for field in stable),
            "restart-workload-binding",
        )
    recovered = {
        event["service"]
        for event in events.values()
        if event["event_class"] == "recovered"
        and event["generation_sha256"] == after_hash
    }
    if recovered:
        _require(before != after, "restart-unchanged-generation")
        for service in recovered:
            _require(
                old[service]["container_id"] != new[service]["container_id"]
                or old[service]["started_at"] != new[service]["started_at"],
                "restart-unchanged-workload",
            )
    else:
        _require(before == after, "failed-restart-generation-change")


def validate_witness(
    witness_bytes: bytes,
    retained_files: Mapping[str, bytes],
    *,
    expected_before: bytes,
    expected_after: bytes,
    expected_contract_sha256: str,
    expected_candidate_manifest_sha256: str,
    expected_mode: str,
    expected_producer: Mapping[str, Any],
    expected_host_baseline_sha256: str,
    expected_profile_sha256: str,
    expected_services: Iterable[str],
    sequence_floor: Mapping[tuple[str, str], int],
    expected_sink_ids_sha256: Iterable[str],
) -> None:
    """Validate a supervision witness against independently supplied bytes."""
    _require(not isinstance(expected_services, (str, bytes)), "expected-services")
    try:
        services = list(expected_services)
    except TypeError:
        raise ContractError("expected-services") from None
    _require(
        bool(services)
        and all(
            isinstance(service, str) and service in _SERVICES for service in services
        ),
        "expected-services",
    )
    _sorted_unique(services, "expected-service-order")
    _require(
        not isinstance(expected_sink_ids_sha256, (str, bytes)),
        "expected-sinks",
    )
    try:
        sink_ids = list(expected_sink_ids_sha256)
    except TypeError:
        raise ContractError("expected-sinks") from None
    _require(bool(sink_ids) and all(_sha(value) for value in sink_ids), "expected-sinks")
    _sorted_unique(sink_ids, "expected-sinks")
    expected_old = _canonical_object(expected_before)
    expected_new = _canonical_object(expected_after)
    candidate_id = expected_old.get("candidate_id")
    _require(_digest(candidate_id), "expected-candidate")
    try:
        validate_generation_bytes(
            expected_before,
            expected_mode=expected_mode,
            expected_candidate_id=candidate_id,
            expected_services=services,
        )
        validate_generation_bytes(
            expected_after,
            expected_mode=expected_mode,
            expected_candidate_id=candidate_id,
            expected_services=services,
        )
    except GenerationContractError as error:
        raise ContractError(str(error)) from None
    root = _closed(_canonical_object(witness_bytes), _ROOT_KEYS, "witness-fields")
    _require(
        root["schema"] == "restricted-clinical-supervision-witness.v1"
        and root["scope"] == "SYNTHETIC_NON_PHI_ONLY",
        "witness-schema",
    )
    _require(
        _sha(expected_contract_sha256)
        and _sha(expected_candidate_manifest_sha256)
        and _sha(expected_host_baseline_sha256)
        and _sha(expected_profile_sha256),
        "expected-frame-hashes",
    )
    _require(
        root["contract_sha256"] == expected_contract_sha256
        and root["candidate_manifest_sha256"] == expected_candidate_manifest_sha256
        and root["mode"] == expected_mode
        and root["host_baseline_sha256"] == expected_host_baseline_sha256
        and root["profile_sha256"] == expected_profile_sha256,
        "witness-frame-binding",
    )
    _require(isinstance(expected_producer, Mapping), "expected-producer")
    _require(
        _producer(root["producer"]) == _producer(dict(expected_producer)),
        "producer-binding",
    )
    _require(
        expected_old["host_baseline_sha256"] == expected_host_baseline_sha256
        and expected_new["host_baseline_sha256"] == expected_host_baseline_sha256,
        "generation-host-binding",
    )
    hashes, by_hash = _file_inventory(root, retained_files, _hash(witness_bytes))
    _require(
        retained_files[BEFORE] == expected_before
        and retained_files[AFTER] == expected_after,
        "generation-readback-binding",
    )
    before_hash = _hash(expected_before)
    after_hash = _hash(expected_after)
    generation = _closed(
        root["generation"],
        {"operation", "before_sha256", "after_sha256", "parent_sha256"},
        "generation-link-fields",
    )
    _require(
        generation["before_sha256"] == before_hash
        and generation["after_sha256"] == after_hash,
        "generation-link-hashes",
    )
    operation = generation["operation"]
    if operation == "observe":
        _require(generation["parent_sha256"] is None, "observe-parent")
    elif operation == "restart":
        _require(generation["parent_sha256"] == before_hash, "restart-parent")
    else:
        raise ContractError("generation-operation")
    _observations(root["observations"], hashes, {before_hash, after_hash})
    events = _events(
        retained_files[EVENTS],
        candidate_id=candidate_id,
        services=services,
        generation_hashes={before_hash, after_hash},
        sequence_floor=sequence_floor,
    )
    _transition(expected_old, expected_new, operation, events, after_hash)
    _deliveries(
        retained_files[DELIVERIES], events=events, retained_by_hash=by_hash,
        expected_sink_ids_sha256=set(sink_ids),
    )
