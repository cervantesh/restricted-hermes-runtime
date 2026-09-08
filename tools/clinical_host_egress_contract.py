"""Validate retained egress-document structure without producing a PASS.

Contract: docs/design/clinical-host-egress-contract.v1.md at 3810cc1c.
Expected frames must come from independently verified candidate/readback inputs,
not be derived from the witness being checked. This module has no I/O or CLI.

Successful return means only byte/schema/binding consistency. Proof contents,
host attribution, loader/symlink custody, and enforcement are NOT verified.
EL10, full EL13, deployment effects and host rows remain MISSING. No new
row-result schema, collector, admission hook, or certification claim is implied.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Iterable


BEFORE = "platform/generation.before.json"
AFTER = "platform/generation.after.json"
WITNESS = "platform/egress-witness.v1.json"
ROWS = tuple(f"EL{index:02}" for index in range(1, 18))
_MODES = {"source-build", "published"}
_MISSING = {"witness-unavailable", "host-not-observed"}
_DIAGNOSTICS = _MISSING | {
    "none", "identity-mismatch", "approved-route-failed", "unexpected-route",
    "ambiguous-denial", "proxy-route", "metadata-route", "enforcement-incomplete",
}
_ROOT_KEYS = {
    "schema", "scope", "contract_sha256", "candidate_manifest_sha256", "mode",
    "producer", "host_baseline_sha256", "generation", "observations", "witness_files",
}
_GENERATION_KEYS = {
    "schema", "mode", "candidate_id", "policy", "compose_sha256", "resolver_sha",
    "project", "state_id", "host_baseline_sha256", "enforcement_sha256", "workloads",
}
_WORKLOAD_KEYS = {"service", "container_id", "image_id", "image_digest", "started_at", "networks"}
_PRODUCER_KEYS = {"id", "run_id", "engine", "toolchain_sha256"}
_SHA = re.compile(r"[a-f0-9]{64}")
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_STAMP = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.\d{9}Z", re.ASCII)
_HASH_TOKEN = re.compile(rb"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")


class ContractError(ValueError):
    """Content-free contract failure."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _closed(value: object, fields: set[str], code: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == fields, code)
    return value


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not any(ord(char) < 32 for char in value)


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _sha(value[7:])


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
            parse_float=_no_number, parse_constant=_no_number)
        _require(isinstance(value, dict), "json-object")
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("json-canonical") from None
    _require(encoded == raw, "json-canonical")
    return value


def _sorted_unique(values: list[str], code: str) -> None:
    _require(values == sorted(set(values)), code)


def _timestamp(value: object) -> bool:
    match = _STAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return False
    try:
        datetime(*(int(part) for part in match.groups()))
    except ValueError:
        return False
    return True


def _generation(raw: bytes) -> dict[str, Any]:
    _require(isinstance(raw, bytes) and 1 <= len(raw) <= 1_048_576, "generation-size")
    value = _closed(_canonical_object(raw), _GENERATION_KEYS, "generation-fields")
    _require(value["schema"] == "restricted-clinical-platform-generation.v1", "generation-schema")
    _require(isinstance(value["mode"], str) and value["mode"] in _MODES, "generation-mode")
    _require(_digest(value["candidate_id"]), "candidate-id")
    policy = _closed(value["policy"], {"epoch", "digest"}, "policy-fields")
    _require(_text(policy["epoch"]) and _sha(policy["digest"]), "policy-values")
    for field in ("compose_sha256", "host_baseline_sha256", "enforcement_sha256"):
        _require(_sha(value[field]), "generation-hash")
    _require(isinstance(value["resolver_sha"], str) and re.fullmatch(r"[a-f0-9]{40}", value["resolver_sha"]) is not None, "resolver-sha")
    for field in ("project", "state_id"):
        _require(isinstance(value[field], str) and _ID.fullmatch(value[field]) is not None, "generation-id")
    workloads = value["workloads"]
    _require(isinstance(workloads, list) and bool(workloads), "workload-list")
    services = []
    for item in workloads:
        row = _closed(item, _WORKLOAD_KEYS, "workload-fields")
        _require(_text(row["service"]), "service-id")
        services.append(row["service"])
        _require(_sha(row["container_id"]) and _digest(row["image_id"]), "workload-id")
        _require(_digest(row["image_digest"]) or (value["mode"] == "source-build" and row["image_digest"] is None), "workload-subject")
        _require(_timestamp(row["started_at"]), "workload-timestamp")
        _require(isinstance(row["networks"], list), "network-list")
        network_ids = []
        for item in row["networks"]:
            network = _closed(item, {"network_id", "name_sha256", "internal"}, "network-fields")
            _require(_sha(network["network_id"]) and _sha(network["name_sha256"])
                and type(network["internal"]) is bool, "network-values")
            network_ids.append(network["network_id"])
        _sorted_unique(network_ids, "network-order")
    _sorted_unique(services, "workload-order")
    return value


def _producer(value: object) -> dict[str, Any]:
    producer = _closed(value, _PRODUCER_KEYS, "producer-fields")
    _require(all(_text(producer[field]) for field in ("id", "run_id", "engine"))
        and _sha(producer["toolchain_sha256"]), "producer-values")
    return producer


def _relative_path(value: object) -> bool:
    return (isinstance(value, str) and bool(value) and value != WITNESS
        and not value.startswith("/") and not any(char in value for char in ("\\", ":"))
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _files(witness: dict[str, Any], retained: Mapping[str, bytes], witness_hash: str) -> set[str]:
    _require(isinstance(retained, Mapping), "retained-bytes-mapping")
    entries = witness["witness_files"]
    _require(isinstance(entries, list), "witness-file-list")
    paths, hashes = [], set()
    for item in entries:
        row = _closed(item, {"path", "sha256", "size", "media_type"}, "witness-file-fields")
        _require(_relative_path(row["path"]), "witness-file-path")
        _require(_sha(row["sha256"]) and type(row["size"]) is int
            and 1 <= row["size"] <= 1_048_576 and _text(row["media_type"]), "witness-file-values")
        paths.append(row["path"])
        data = retained.get(row["path"])
        _require(isinstance(data, bytes) and len(data) == row["size"]
            and _hash(data) == row["sha256"], "witness-file-bytes")
        _require(witness_hash.encode() not in data, "witness-self-reference")
        if row["path"] in {BEFORE, AFTER}:
            _require(row["media_type"] == "application/json", "generation-media-type")
        hashes.add(row["sha256"])
    _sorted_unique(paths, "witness-file-order")
    _require(set(paths) == set(retained) and {BEFORE, AFTER} <= set(paths), "witness-file-inventory")
    # Known retained-hash references form the only byte-level graph recognized
    # here. Opaque proof semantics are intentionally left to the future reader.
    graph = {_hash(data): {token.decode() for token in _HASH_TOKEN.findall(data)} & hashes
        for data in retained.values()}
    pending, completed = set(), set()
    def visit(node: str) -> None:
        _require(node not in pending, "witness-reference-cycle")
        if node in completed:
            return
        pending.add(node)
        for child in graph[node]:
            visit(child)
        pending.remove(node)
        completed.add(node)
    try:
        for node in graph:
            visit(node)
    except RecursionError:
        raise ContractError("witness-reference-depth") from None
    return hashes


def _observations(value: object, hashes: set[str], generation_hashes: set[str]) -> dict[str, dict[str, Any]]:
    _require(isinstance(value, list), "observation-list")
    rows = {}
    ids = []
    for item in value:
        row = _closed(item, {"id", "outcome", "diagnostic", "proof_sha256s"}, "observation-fields")
        _require(isinstance(row["id"], str) and row["id"] in ROWS, "observation-id")
        ids.append(row["id"])
        _require(isinstance(row["diagnostic"], str) and row["diagnostic"] in _DIAGNOSTICS, "observation-diagnostic")
        proof = row["proof_sha256s"]
        _require(isinstance(proof, list) and all(_sha(item) for item in proof), "observation-proof-list")
        _sorted_unique(proof, "observation-proof-order")
        _require(set(proof) <= hashes, "observation-proof-unresolved")
        if row["outcome"] == "NOT_VERIFIED":
            _require(proof == [] and row["diagnostic"] in _MISSING, "observation-unverified")
        elif row["outcome"] in ("PASS", "FAIL"):
            _require(1 <= len(proof) <= 64 and bool(set(proof) - generation_hashes), "observation-proof-cardinality")
            _require((row["diagnostic"] == "none") if row["outcome"] == "PASS"
                else row["diagnostic"] not in _MISSING | {"none"}, "observation-outcome-diagnostic")
        else:
            raise ContractError("observation-outcome")
        rows[row["id"]] = row
    _require(tuple(ids) == ROWS, "observation-inventory")
    return rows


def _transition(before: dict[str, Any], after: dict[str, Any], operation: str,
    restarted_services: Iterable[str], successful_restart: bool) -> None:
    _require(not isinstance(restarted_services, (str, bytes)), "restart-inventory")
    try:
        requested = list(restarted_services)
    except TypeError:
        raise ContractError("restart-inventory") from None
    _require(all(_text(name) for name in requested), "restart-inventory")
    _sorted_unique(requested, "restart-inventory")
    if operation == "observe":
        _require(not requested and not successful_restart, "observe-restart-claim")
        return
    static = _GENERATION_KEYS - {"workloads"}
    _require(all(before[name] == after[name] for name in static), "restart-profile-binding")
    old = {row["service"]: row for row in before["workloads"]}
    new = {row["service"]: row for row in after["workloads"]}
    _require(bool(requested) and set(requested) <= set(old) and set(old) == set(new), "restart-inventory")
    for service, row in old.items():
        if service not in requested:
            _require(row == new[service], "unrequested-workload-change")
            continue
        _require(all(row[name] == new[service][name] for name in _WORKLOAD_KEYS - {"container_id", "started_at"}), "restart-workload-binding")
        if successful_restart:
            _require(row["container_id"] != new[service]["container_id"]
                or row["started_at"] != new[service]["started_at"], "restart-unchanged-workload")


def validate_witness(
    witness_bytes: bytes,
    retained_files: Mapping[str, bytes],
    *,
    expected_before: bytes,
    expected_after: bytes,
    expected_contract_sha256: str,
    expected_candidate_manifest_sha256: str,
    expected_producer: Mapping[str, Any],
    expected_operation: str,
    restarted_services: Iterable[str],
) -> None:
    """Raise content-free ContractError on inconsistent bytes; return no verdict.

    The expected generation bytes represent independently bound candidate and
    readback inventories. This function cannot establish their external origin
    or recompute an unspecified candidate-manifest schema. The future loader
    must establish regular-file/no-symlink custody before constructing the
    byte mapping; Path objects or substitute hashes are not accepted here.
    """
    expected_old, expected_new = _generation(expected_before), _generation(expected_after)
    root = _closed(_canonical_object(witness_bytes), _ROOT_KEYS, "witness-fields")
    _require(root["schema"] == "restricted-clinical-egress-witness.v1"
        and root["scope"] == "SYNTHETIC_NON_PHI_ONLY", "witness-schema")
    _require(_sha(expected_contract_sha256) and _sha(expected_candidate_manifest_sha256), "expected-frame-hashes")
    _require(root["contract_sha256"] == expected_contract_sha256
        and root["candidate_manifest_sha256"] == expected_candidate_manifest_sha256, "witness-frame-binding")
    _require(isinstance(expected_producer, Mapping), "expected-producer")
    _require(_producer(root["producer"]) == _producer(dict(expected_producer)), "producer-binding")
    _require(root["mode"] == expected_old["mode"] == expected_new["mode"]
        and root["host_baseline_sha256"] == expected_old["host_baseline_sha256"] == expected_new["host_baseline_sha256"], "witness-generation-binding")
    hashes = _files(root, retained_files, _hash(witness_bytes))
    old_raw, new_raw = retained_files[BEFORE], retained_files[AFTER]
    before, after = _generation(old_raw), _generation(new_raw)
    _require(old_raw == expected_before and new_raw == expected_after, "generation-readback-binding")
    old_hash, new_hash = _hash(old_raw), _hash(new_raw)
    generation = _closed(root["generation"], {"operation", "before_sha256", "after_sha256", "parent_sha256"}, "generation-link-fields")
    operation = generation["operation"]
    _require(isinstance(expected_operation, str) and expected_operation in {"observe", "restart"}
        and operation == expected_operation, "generation-operation")
    _require(generation["before_sha256"] == old_hash and generation["after_sha256"] == new_hash, "generation-link-hashes")
    if operation == "observe":
        _require(old_raw == new_raw and generation["parent_sha256"] is None, "observe-generation-binding")
    else:
        _require(generation["parent_sha256"] == old_hash, "restart-parent-binding")
    observations = _observations(root["observations"], hashes, {old_hash, new_hash})
    successful_restart = observations["EL12"]["outcome"] == "PASS"
    if successful_restart:
        _require(old_hash != new_hash, "restart-unchanged-generation")
    _transition(before, after, operation, restarted_services, successful_restart)
