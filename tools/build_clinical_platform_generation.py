"""Build canonical platform-generation bytes from independent supplied facts.

This module is deliberately pure: it performs no Docker, filesystem, network,
or environment discovery.  Callers remain responsible for acquiring every
input independently and for retaining the returned bytes.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any

from tools.clinical_host_egress_contract import (
    ContractError,
    GENERATION_SCHEMA,
    validate_generation_bytes,
)


BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
_INPUT_KEYS = {
    "mode",
    "candidate_id",
    "policy",
    "compose_bytes",
    "resolver_sha",
    "project",
    "state_id",
    "host_baseline_bytes",
    "enforcement_bytes",
    "approved_subjects",
    "workloads",
}
_WORKLOAD_KEYS = {
    "service",
    "container_id",
    "image_id",
    "image_digest",
    "started_at",
    "networks",
}
_NETWORK_KEYS = {"network_id", "name", "internal"}
_MODES = {"source-build", "published"}
_SHA = re.compile(r"[a-f0-9]{64}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_SUBJECT = re.compile(r"[^\s@]+@sha256:[a-f0-9]{64}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_STAMP = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.\d{9}Z",
    re.ASCII,
)


class GenerationError(ValueError):
    """Content-free invalid-construction error."""


def _fail(code: str) -> None:
    raise GenerationError(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        _fail(code)


def _closed(value: object, keys: set[str], code: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == keys, code)
    return value


def _text(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(ord(character) < 32 for character in value)
    )


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bytes(value: object, code: str) -> bytes:
    _require(isinstance(value, bytes) and bool(value), code)
    return value


def _timestamp(value: object) -> bool:
    match = _STAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return False
    try:
        # The platform parser is the final schema authority; construction
        # still rejects impossible calendar values before encoding.
        from datetime import datetime

        datetime(*(int(part) for part in match.groups()))
    except ValueError:
        return False
    return True


def _canonical(value: object) -> bytes:
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


def _network(value: object) -> dict[str, object]:
    row = _closed(value, _NETWORK_KEYS, "network-fields")
    _require(_sha(row["network_id"]), "network-id")
    _require(_text(row["name"]), "network-name")
    _require(type(row["internal"]) is bool, "network-internal")
    return {
        "network_id": row["network_id"],
        "name_sha256": _hash(row["name"].encode("utf-8")),
        "internal": row["internal"],
    }


def _workloads(
    values: object,
    *,
    mode: str,
    approved_subjects: Mapping[str, object],
) -> list[dict[str, object]]:
    _require(isinstance(values, list) and bool(values), "workload-list")
    built = []
    seen_services: set[str] = set()
    for value in values:
        row = _closed(value, _WORKLOAD_KEYS, "workload-fields")
        service = row["service"]
        _require(
            isinstance(service, str)
            and _ID.fullmatch(service) is not None
            and service not in seen_services,
            "workload-service",
        )
        seen_services.add(service)
        _require(_sha(row["container_id"]), "workload-container")
        _require(_digest(row["image_id"]), "workload-image-id")
        _require(_timestamp(row["started_at"]), "workload-started-at")
        networks = row["networks"]
        _require(isinstance(networks, list), "network-list")
        retained = [_network(network) for network in networks]
        retained.sort(key=lambda network: network["network_id"])
        _require(
            len({network["network_id"] for network in retained}) == len(retained),
            "network-duplicate",
        )
        image_digest = row["image_digest"]
        if mode == "published":
            subject = approved_subjects.get(service)
            _require(
                isinstance(subject, str) and _SUBJECT.fullmatch(subject) is not None,
                "approved-subject",
            )
            _require(
                _digest(image_digest) and subject.rsplit("@", 1)[1] == image_digest,
                "workload-subject-binding",
            )
        else:
            _require(image_digest is None, "source-build-subject")
        built.append(
            {
                "service": service,
                "container_id": row["container_id"],
                "image_id": row["image_id"],
                "image_digest": image_digest,
                "started_at": row["started_at"],
                "networks": retained,
            }
        )
    built.sort(key=lambda workload: workload["service"])
    return built


def _generation(inputs: object) -> tuple[dict[str, object], bytes]:
    source = _closed(inputs, _INPUT_KEYS, "generation-input-fields")
    mode = source["mode"]
    _require(isinstance(mode, str) and mode in _MODES, "generation-mode")
    _require(_digest(source["candidate_id"]), "candidate-id")
    policy = _closed(source["policy"], {"epoch", "digest"}, "policy-fields")
    _require(_text(policy["epoch"]) and _sha(policy["digest"]), "policy-values")
    _require(
        isinstance(source["resolver_sha"], str)
        and re.fullmatch(r"[a-f0-9]{40}", source["resolver_sha"]) is not None,
        "resolver-sha",
    )
    for field in ("project", "state_id"):
        _require(
            isinstance(source[field], str) and _ID.fullmatch(source[field]) is not None,
            "generation-id",
        )
    approved = source["approved_subjects"]
    _require(isinstance(approved, Mapping), "approved-subjects")
    compose = _bytes(source["compose_bytes"], "compose-bytes")
    baseline = _bytes(source["host_baseline_bytes"], "host-baseline-bytes")
    enforcement = _bytes(source["enforcement_bytes"], "enforcement-bytes")
    workloads = _workloads(
        source["workloads"], mode=mode, approved_subjects=approved
    )
    services = [workload["service"] for workload in workloads]
    if mode == "published":
        _require(set(approved) == set(services), "approved-subject-inventory")
    else:
        _require(not approved, "source-build-approved-subjects")
    value = {
        "schema": GENERATION_SCHEMA,
        "mode": mode,
        "candidate_id": source["candidate_id"],
        "policy": dict(policy),
        "compose_sha256": _hash(compose),
        "resolver_sha": source["resolver_sha"],
        "project": source["project"],
        "state_id": source["state_id"],
        "host_baseline_sha256": _hash(baseline),
        "enforcement_sha256": _hash(enforcement),
        "workloads": workloads,
    }
    raw = _canonical(value)
    try:
        validate_generation_bytes(
            raw,
            expected_mode=mode,
            expected_candidate_id=source["candidate_id"],
            expected_services=services,
        )
    except ContractError as error:
        raise GenerationError(str(error)) from None
    return value, raw


def build_generation_pair(
    *, before: Mapping[str, object], after: Mapping[str, object]
) -> dict[str, bytes]:
    """Return the closed before/after generation inventory byte pair."""
    old, old_raw = _generation(before)
    new, new_raw = _generation(after)
    static = set(old) - {"workloads"}
    _require(all(old[field] == new[field] for field in static), "generation-drift")
    old_rows = {row["service"]: row for row in old["workloads"]}
    new_rows = {row["service"]: row for row in new["workloads"]}
    _require(set(old_rows) == set(new_rows), "workload-inventory-drift")
    stable = _WORKLOAD_KEYS - {"container_id", "started_at"}
    for service, old_row in old_rows.items():
        _require(
            all(old_row[field] == new_rows[service][field] for field in stable),
            "workload-identity-drift",
        )
    return {BEFORE: old_raw, AFTER: new_raw}
