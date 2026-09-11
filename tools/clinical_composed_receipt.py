#!/usr/bin/env python3
"""Build and verify content-safe receipts for the composed clinical E2E.

The deployment harness can inspect synthetic state while it runs.  This module
reduces that state to a closed, canonical receipt suitable for public evidence:
it retains assertions and immutable subjects, never controller output, seed
material, endpoint values, logs, or record identifiers.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "restricted-runtime-composed-e2e-receipt.v1"
SERVICES = ("clinical-adapter", "ingress")
_SHA = re.compile(r"[a-f0-9]{40}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_SOURCE_KEYS = {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}
_BOUNDARIES = {
    "adapter_cannot_resolve_mattermost",
    "adapter_resolves_only_hrh_boundary",
    "edge_cannot_resolve_hrh",
    "zero model/conversation/provider calls",
}
_SCENARIOS = {
    "valid": "pass", "actor_cross": "deny", "channel_cross": "deny",
    "patient_cross": "deny", "unbound": "deny", "disabled": "deny",
    "missing_each_permission": "deny", "revoked_before_delivery": "zero-post",
    "source_deleted_before_delivery": "blocked-zero-post", "swapped_digest": "deny",
    "crash_retry": "stable-result", "logs": "no synthetic identifiers",
}
_POST_COUNTS = {
    "valid": 1, "recovered": 0, "source_deleted": 0, "actor-cross": 0,
    "channel-cross": 0, "disabled": 0, "missing-appointments": 0,
    "missing-patients": 0, "revoked": 0, "unbound": 0,
}
_CRASH = {
    "response_digest_equal": True, "read_authorized": 1,
    "read_completed": 1, "delivery_reauthorized": 1,
}


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def write_new(path: Path, value: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value))
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _strict_equal(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(_strict_equal(observed[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(_strict_equal(left, right) for left, right in zip(observed, expected))
    return observed == expected


def _source(evidence: object) -> dict[str, str] | None:
    if not isinstance(evidence, dict):
        return None
    source = {key: evidence.get(key) for key in _SOURCE_KEYS}
    if set(source) != _SOURCE_KEYS or not all(isinstance(value, str) and _SHA.fullmatch(value) for value in source.values()):
        return None
    return source


def _image_subjects(evidence: object) -> dict[str, str] | None:
    if not isinstance(evidence, dict) or not isinstance(evidence.get("built_images"), dict):
        return None
    subjects = evidence["built_images"]
    if not set(SERVICES).issubset(subjects):
        return None
    result: dict[str, str] = {}
    for service in SERVICES:
        subject = subjects[service]
        image_id = subject.get("image_id") if isinstance(subject, dict) else None
        if not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id):
            return None
        result[service] = image_id
    return result


def _source_deletion(evidence: object) -> dict[str, Any] | None:
    if not isinstance(evidence, dict) or not isinstance(evidence.get("source_deletion"), dict):
        return None
    value = evidence["source_deletion"]
    before, after = value.get("before"), value.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    expected_before = {"state": "IN_FLIGHT", "reason": "", "nonce_erased": False, "ciphertext_erased": False}
    expected_after = {"state": "BLOCKED", "reason": "post_authorization_source_rejected", "nonce_erased": True, "ciphertext_erased": True}
    if not all(before.get(key) == item for key, item in expected_before.items()):
        return None
    if not all(after.get(key) == item for key, item in expected_after.items()):
        return None
    if value.get("delivery_count") != 0 or value.get("delete_accepted") is not True:
        return None
    return {"before": expected_before, "after": expected_after, "delivery_count": 0}


def build_receipt(evidence: Mapping[str, Any], *, cleanup_complete: bool) -> dict[str, Any]:
    source = _source(evidence)
    images = _image_subjects(evidence)
    deletion = _source_deletion(evidence)
    boundaries = evidence.get("boundaries")
    if source is None or images is None or deletion is None:
        raise ValueError("E2E evidence lacks an admissible source, image, or deletion subject")
    if not isinstance(boundaries, dict) or set(boundaries) != _BOUNDARIES or not all(value is True for value in boundaries.values()):
        raise ValueError("E2E boundary controls are incomplete")
    if not _strict_equal(evidence.get("scenarios"), _SCENARIOS) or not _strict_equal(evidence.get("post_counts"), _POST_COUNTS):
        raise ValueError("E2E scenario controls are incomplete")
    if not _strict_equal(evidence.get("crash_invariants"), _CRASH):
        raise ValueError("E2E crash controls are incomplete")
    product = evidence.get("runtime_product_sha")
    if not isinstance(product, str) or not _SHA.fullmatch(product) or cleanup_complete is not True:
        raise ValueError("E2E product or cleanup evidence is incomplete")
    receipt = {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "source": source,
        "runtime_product_sha": product,
        "edge_image_subjects": images,
        "boundaries": boundaries,
        "scenarios": _SCENARIOS,
        "post_counts": _POST_COUNTS,
        "crash_invariants": _CRASH,
        "source_deletion": deletion,
        "cleanup": {"completed": True},
    }
    if verify_receipt(canonical_bytes(receipt), expected_source=source, expected_images=images, expected_product=product):
        raise ValueError("composed E2E receipt is not admissible")
    return receipt


def verify_receipt(raw: bytes, *, expected_source: Mapping[str, str], expected_images: Mapping[str, str], expected_product: str) -> list[str]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return ["canonical"]
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return ["canonical"]
    required = {"schema", "synthetic_non_phi_only", "source", "runtime_product_sha", "edge_image_subjects", "boundaries", "scenarios", "post_counts", "crash_invariants", "source_deletion", "cleanup"}
    if set(value) != required:
        return ["fields"]
    if value["schema"] != SCHEMA or value["synthetic_non_phi_only"] is not True:
        return ["schema"]
    source = _source(value["source"])
    if source is None or not _strict_equal(source, expected_source):
        return ["source"]
    if not isinstance(value["runtime_product_sha"], str) or not _SHA.fullmatch(value["runtime_product_sha"]) or value["runtime_product_sha"] != expected_product:
        return ["product"]
    images = value["edge_image_subjects"]
    if not isinstance(images, dict) or set(images) != set(SERVICES) or not all(isinstance(image, str) and _DIGEST.fullmatch(image) for image in images.values()) or not _strict_equal(images, expected_images):
        return ["images"]
    if not isinstance(value["boundaries"], dict) or set(value["boundaries"]) != _BOUNDARIES or not all(item is True for item in value["boundaries"].values()):
        return ["boundaries"]
    if not _strict_equal(value["scenarios"], _SCENARIOS) or not _strict_equal(value["post_counts"], _POST_COUNTS):
        return ["scenarios"]
    if not _strict_equal(value["crash_invariants"], _CRASH):
        return ["crash"]
    deletion = value["source_deletion"]
    if not isinstance(deletion, dict) or not _strict_equal(deletion, {"before": {"state": "IN_FLIGHT", "reason": "", "nonce_erased": False, "ciphertext_erased": False}, "after": {"state": "BLOCKED", "reason": "post_authorization_source_rejected", "nonce_erased": True, "ciphertext_erased": True}, "delivery_count": 0}):
        return ["source-deletion"]
    if not _strict_equal(value["cleanup"], {"completed": True}):
        return ["cleanup"]
    return []
