"""Validate a content-safe P2 representative-host conformance receipt.

This is deliberately a receipt contract, not a host collector or an admission
controller. A successful result proves only that independently captured,
content-safe evidence has the expected exact frame and closed schema. It does
not prove the origin of that evidence, host enforcement, PHI authorization, or
deployment conformance.
"""
from __future__ import annotations

import json
import re
from typing import Any


SCHEMA = "restricted-runtime-p2-host-conformance.v1"
CLAIM_IDS = (
    "candidate_identity",
    "host_principal",
    "secret_generation",
    "effective_egress",
    "trust_audit_retention",
    "patch_time",
    "recovery_cleanup",
)
_SHA256 = re.compile(r"[a-f0-9]{64}")
_GIT_SHA = re.compile(r"[a-f0-9]{40}")
_HOST_CLASSES = frozenset({"ubuntu-24.04-lts-x86_64"})
_OUTCOMES = frozenset({"PASS", "FAIL"})
_ROOT_FIELDS = {
    "schema",
    "synthetic_non_phi_only",
    "nonclaims",
    "candidate",
    "inputs",
    "host",
    "claims",
    "verifier",
    "outcome",
}


def canonical_bytes(value: dict[str, Any]) -> bytes:
    """Return the sole accepted JSON representation for a receipt."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _no_number(value: str) -> None:
    raise ValueError("number")


def _parse_canonical(raw: object) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(raw, bytes) or not raw:
        return None, "canonical"
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None, "canonical"
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return None, "canonical"
    return value, None


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _closed(value: object, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


def verify_receipt(
    raw: bytes,
    *,
    expected_runtime_head: str,
    expected_runtime_tree: str,
    expected_candidate_manifest_sha256: str,
    expected_subject_set_sha256: str,
    expected_egress_receipt_sha256: str,
    expected_outcome: str,
) -> list[str]:
    """Return stable content-free errors; an empty list is structural success."""
    value, parse_error = _parse_canonical(raw)
    if parse_error is not None:
        return [parse_error]
    assert value is not None
    errors: list[str] = []
    if set(value) != _ROOT_FIELDS:
        return ["fields"]
    if value["schema"] != SCHEMA or value["synthetic_non_phi_only"] is not True:
        errors.append("schema")
    nonclaims = value["nonclaims"]
    if not _closed(nonclaims, {"phi_authorized", "deployment_conformant", "independent_assessment"}) or nonclaims != {
        "phi_authorized": False,
        "deployment_conformant": False,
        "independent_assessment": False,
    }:
        errors.append("nonclaims")
    candidate = value["candidate"]
    if not _closed(candidate, {"runtime_head", "runtime_tree", "candidate_manifest_sha256", "subject_set_sha256"}) or not all(
        isinstance(candidate.get(name), str)
        for name in ("runtime_head", "runtime_tree", "candidate_manifest_sha256", "subject_set_sha256")
    ):
        errors.append("candidate")
    else:
        if _GIT_SHA.fullmatch(candidate["runtime_head"]) is None or _GIT_SHA.fullmatch(candidate["runtime_tree"]) is None or not _sha256(candidate["candidate_manifest_sha256"]) or not _sha256(candidate["subject_set_sha256"]):
            errors.append("candidate")
        if candidate["runtime_head"] != expected_runtime_head:
            errors.append("runtime-head")
        if candidate["runtime_tree"] != expected_runtime_tree:
            errors.append("runtime-tree")
        if candidate["candidate_manifest_sha256"] != expected_candidate_manifest_sha256:
            errors.append("manifest")
        if candidate["subject_set_sha256"] != expected_subject_set_sha256:
            errors.append("subject-set")
    inputs = value["inputs"]
    if not _closed(inputs, {"container_egress_receipt_sha256"}) or not _sha256(inputs.get("container_egress_receipt_sha256")) or inputs.get("container_egress_receipt_sha256") != expected_egress_receipt_sha256:
        errors.append("egress")
    host = value["host"]
    if not _closed(host, {"class", "toolchain_sha256"}) or host.get("class") not in _HOST_CLASSES or not _sha256(host.get("toolchain_sha256")):
        errors.append("host")
    verifier = value["verifier"]
    if not _closed(verifier, {"version", "command_set_sha256"}) or verifier.get("version") != "p2-host-conformance-v1" or not _sha256(verifier.get("command_set_sha256")):
        errors.append("verifier")
    outcome = value["outcome"]
    if outcome not in _OUTCOMES or outcome != expected_outcome:
        errors.append("outcome")
    claims = value["claims"]
    if not isinstance(claims, list) or len(claims) != len(CLAIM_IDS):
        errors.append("claims")
    else:
        claim_ids: list[str] = []
        for claim in claims:
            if not _closed(claim, {"id", "outcome", "proof_sha256", "diagnostic"}):
                errors.append("claims")
                break
            claim_id, claim_outcome = claim["id"], claim["outcome"]
            claim_ids.append(claim_id)
            if claim_outcome != outcome or not _sha256(claim["proof_sha256"]):
                errors.append("claims")
                break
            if (claim_outcome == "PASS" and claim["diagnostic"] != "none") or (
                claim_outcome == "FAIL" and claim["diagnostic"] != "controlled-negative"
            ):
                errors.append("claims")
                break
        if tuple(claim_ids) != CLAIM_IDS:
            errors.append("claims")
    return list(dict.fromkeys(errors))
