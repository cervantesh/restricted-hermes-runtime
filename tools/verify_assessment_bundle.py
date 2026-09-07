#!/usr/bin/env python3
"""Verify a clean-room, content-safe restricted clinical assessment bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any


SCHEMA = "restricted-clinical-assessment-bundle.v1"
SCOPE = "SYNTHETIC_NON_PHI_ONLY"
STATUS_VALUES = frozenset({"PASS", "FAIL", "NOT_APPLICABLE", "NOT_VERIFIED", "EXTERNALLY_ACCEPTED"})
SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}$")
OCI_REFERENCE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}$")
SAFE_FILE = re.compile(r"(?:subjects|contracts|evidence|governance|independent-review)/[a-z0-9][a-z0-9._-]{0,127}\.(?:json|md)$")
MEDIA_TYPES = {".json": "application/json", ".md": "text/markdown", ".py": "text/x-python"}
MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 5_242_880
MAX_FILES = 64
SECRET_PATTERNS = (
    re.compile(rb"(?i)(?:password|api[_-]?key|token|secret)[_-]?secret[_-]?canary"),
    re.compile(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)[\"'](?:password|passwd|secret|token|api[_-]?key)[\"']\s*:\s*[\"'](?!redacted[\"']|not[ _-]?present[\"']|none[\"']|n/?a[\"']|<redacted>[\"'])[^\"'\r\n]{8,}[\"']"),
    # This is deliberately a narrow synthetic-canary detector, not a claim
    # to identify arbitrary PHI in unstructured evidence.
    re.compile(rb"(?i)(?:phi|patient(?:[_-]?id)?|mrn)[_-]?(?:secret[_-]?)?canary[_-]?[0-9]+"),
)
ROOT_KEYS = frozenset({"schema_version", "scope", "candidate_id", "sources", "subjects", "producer", "policy", "controls", "dependencies", "nonclaims", "files"})
SPECIAL_FILES = frozenset({"README.md", "assessment.manifest.json", "verify_assessment_bundle.py"})
PROFILE = "restricted-clinical-candidate.v1"
BOUND_REVIEW_PROFILE = "restricted-clinical-candidate.v2"
PREREVIEW_MANIFEST_PATH = "independent-review/prereview.manifest.json"
REVIEW_PATH = "independent-review/findings.json"
REQUIRED_SOURCES = frozenset({"governance-contract", "health-record-hub-contract", "health-record-hub-publication", "restricted-edge", "restricted-runtime"})
REQUIRED_SUBJECTS = frozenset({"health-record-hub-migration", "health-record-hub-web", "restricted-clinical-adapter", "restricted-mattermost-ingress"})
REQUIRED_DEPENDENCIES = frozenset({"immutable-images", "representative-host-input"})
REQUIRED_GATES = frozenset({"bounded-inputs", "clinical-composition", "cold-recovery", "governance-decision", "hrh-publication", "immutable-application-subjects", "independent-review", "representative-host"})
GATE_EVIDENCE = {
    "bounded-inputs": ("evidence/bounded-inputs.json",),
    "clinical-composition": ("contracts/clinical-composition.json", "evidence/clinical-receipt.json"),
    "cold-recovery": ("evidence/cold-recovery.json",),
    "governance-decision": ("governance/risk-map.json",),
    "hrh-publication": ("evidence/hrh-publication.json",),
    "immutable-application-subjects": ("subjects/images.json",),
    "independent-review": ("independent-review/findings.json",),
    "representative-host": ("evidence/representative-host.json",),
}
GATE_DEPENDENCIES = {
    "bounded-inputs": (),
    "clinical-composition": ("immutable-images",),
    "cold-recovery": (),
    "governance-decision": (),
    "hrh-publication": (),
    "immutable-application-subjects": ("immutable-images",),
    "independent-review": (),
    "representative-host": ("representative-host-input",),
}
PROFILE_FILES = frozenset({path for paths in GATE_EVIDENCE.values() for path in paths})


def profile_files(manifest: dict[str, Any]) -> frozenset[str]:
    """v2 retains A10P only for a completed technical review (including FAIL)."""
    controls = manifest.get("controls")
    review = next((item for item in controls if isinstance(item, dict) and item.get("id") == "independent-review"), {}) if isinstance(controls, list) else {}
    status = review.get("status")
    if status == "EXTERNALLY_ACCEPTED" and isinstance(review.get("acceptance"), dict):
        status = review["acceptance"].get("technical_status")
    if manifest.get("profile") == BOUND_REVIEW_PROFILE and status in {"PASS", "FAIL"}:
        return PROFILE_FILES | {PREREVIEW_MANIFEST_PATH}
    return PROFILE_FILES


HOST_OBSERVATIONS = ("backup-recovery", "dns", "effective-host-runtime", "ingress-ports", "ipv4", "ipv6", "logging-audit-sinks", "metadata-endpoints", "mounts", "patch-baseline", "principals-iam-denials", "proxy-env", "secret-mounts-rotation", "time-source", "trust-roots")
BOUNDED_INPUT_CLASSIFICATIONS = {
    "delivery-reauthorization-pr18": "bounded-delivery-reauthorization",
    "representative-container-egress-pr19": "bounded-synthetic-container",
    "secret-boundary-pr15": "bounded-secret-boundary",
}
BOUNDED_INPUT_CI_RUN_URLS = {
    "delivery-reauthorization-pr18": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34104221878",
    "representative-container-egress-pr19": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34109706405",
    "secret-boundary-pr15": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34101476120",
}
README_CONTENT = "# Restricted clinical assessment bundle\n\nSYNTHETIC_NON_PHI_ONLY. Machine evidence determines verification; this README cannot determine readiness.\n"
ROOT_KEYS = ROOT_KEYS | {"profile"}


class VerificationResult:
    def __init__(self, errors: list[str], statuses: dict[str, str], ready_for_technical_go: bool) -> None:
        self.errors = errors
        self.statuses = statuses
        self.ready_for_technical_go = ready_for_technical_go


def canonical_json(value: object) -> bytes:
    """The sole byte representation accepted for a bundle manifest."""
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _mapping(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _error(errors: list[str], message: str) -> None:
    errors.append(message)


def _regular(path: Path, errors: list[str], context: str) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        _error(errors, f"{context}: unavailable: {exc}")
        return False
    if stat.S_ISLNK(mode):
        _error(errors, f"{context}: symlink is forbidden")
        return False
    if not stat.S_ISREG(mode):
        _error(errors, f"{context}: regular file required")
        return False
    return True


def _safe_relative(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        return None
    return path.as_posix()


def _allowed_path(path: str) -> bool:
    return path in SPECIAL_FILES or bool(SAFE_FILE.fullmatch(path))


def _secret_bearing(raw: bytes) -> bool:
    return any(pattern.search(raw) is not None for pattern in SECRET_PATTERNS)


def _bounded_read(path: Path, errors: list[str], context: str) -> bytes | None:
    """Read at most one allowed member, including if a file grows mid-read."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        _error(errors, f"{context}: unreadable: {exc}")
        return None
    if len(raw) > MAX_FILE_BYTES:
        _error(errors, f"{context}: file limit exceeded")
        return None
    return raw


def _ordered_records(value: object, *, field: str, errors: list[str], context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _error(errors, f"{context}: non-empty list required")
        return []
    records = [_mapping(item) for item in value]
    if any(record is None for record in records):
        _error(errors, f"{context}: records must be objects")
        return []
    result = [record for record in records if record is not None]
    identifiers = [record.get(field) for record in result]
    if any(not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier) for identifier in identifiers):
        _error(errors, f"{context}: invalid {field}")
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
        _error(errors, f"{context}: records must be uniquely sorted by {field}")
    return result


def _verify_metadata(manifest: dict[str, Any], errors: list[str]) -> dict[str, str]:
    if set(manifest) != ROOT_KEYS:
        _error(errors, "manifest: closed schema keys mismatch")
    if manifest.get("schema_version") != SCHEMA or manifest.get("scope") != SCOPE:
        _error(errors, "manifest: schema or synthetic non-PHI scope mismatch")
    if manifest.get("profile") not in {PROFILE, BOUND_REVIEW_PROFILE}:
        _error(errors, f"manifest: required profile is {PROFILE} or {BOUND_REVIEW_PROFILE}")
    candidate_id = manifest.get("candidate_id")
    payload = dict(manifest)
    payload.pop("candidate_id", None)
    expected_candidate = "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()
    if candidate_id != expected_candidate:
        _error(errors, "manifest: candidate_id is not the canonical payload digest")

    sources = _ordered_records(manifest.get("sources"), field="name", errors=errors, context="sources")
    if {record.get("name") for record in sources} != REQUIRED_SOURCES:
        _error(errors, "sources: closed candidate source inventory mismatch")
    for record in sources:
        if set(record) != {"name", "revision", "tree"} or not GIT_OBJECT.fullmatch(str(record.get("revision"))) or not GIT_OBJECT.fullmatch(str(record.get("tree"))):
            _error(errors, f"source {record.get('name')!r}: exact revision and tree required")
    subjects = _ordered_records(manifest.get("subjects"), field="name", errors=errors, context="subjects")
    if {record.get("name") for record in subjects} != REQUIRED_SUBJECTS:
        _error(errors, "subjects: exact four-application inventory mismatch")
    for record in subjects:
        reference = record.get("reference")
        if record.get("status") == "PASS" and (set(record) != {"name", "status", "kind", "reference"} or record.get("kind") != "oci-image" or not isinstance(reference, str)):
            _error(errors, f"subject {record.get('name')!r}: invalid subject")
        elif record.get("status") == "PASS" and not OCI_REFERENCE.fullmatch(reference):
            _error(errors, f"subject {record.get('name')!r}: OCI subject must be immutable by digest")
        elif record.get("status") == "NOT_VERIFIED" and (set(record) != {"name", "status", "reason"} or not isinstance(record.get("reason"), str) or not IDENTIFIER.fullmatch(record["reason"])):
            _error(errors, f"subject {record.get('name')!r}: NOT_VERIFIED needs a closed reason and no reference")
        elif record.get("status") not in {"PASS", "NOT_VERIFIED"}:
            _error(errors, f"subject {record.get('name')!r}: invalid status")

    producer = _mapping(manifest.get("producer"))
    if producer is None or set(producer) != {"producer_id", "run_id", "toolchain_id", "host_id"} or any(not isinstance(producer.get(key), str) or not producer[key] for key in ("producer_id", "run_id", "toolchain_id", "host_id")):
        _error(errors, "producer: producer/run/toolchain/host identifiers required")
    policy = _mapping(manifest.get("policy"))
    if policy is None or set(policy) != {"epoch", "digest"} or not isinstance(policy.get("epoch"), str) or not policy["epoch"] or not isinstance(policy.get("digest"), str) or not SHA256.fullmatch(policy["digest"]):
        _error(errors, "policy: epoch and sha256 digest required")

    dependency_statuses: dict[str, str] = {}
    dependency_records = _ordered_records(manifest.get("dependencies"), field="id", errors=errors, context="dependencies")
    if {record.get("id") for record in dependency_records} != REQUIRED_DEPENDENCIES:
        _error(errors, "dependencies: closed dependency inventory mismatch")
    for record in dependency_records:
        status_value = record.get("status")
        allowed = {"id", "status"}
        if status_value == "EXTERNALLY_ACCEPTED":
            allowed.add("acceptance")
        if status_value == "NOT_APPLICABLE":
            allowed.add("rationale")
        if set(record) != allowed or status_value not in STATUS_VALUES:
            _error(errors, f"dependency {record.get('id')!r}: invalid status")
        else:
            if status_value == "NOT_APPLICABLE" and (not isinstance(record.get("rationale"), str) or not record["rationale"]):
                _error(errors, f"dependency {record.get('id')!r}: NOT_APPLICABLE needs rationale")
            if status_value == "EXTERNALLY_ACCEPTED":
                acceptance = _mapping(record.get("acceptance"))
                if acceptance is None or set(acceptance) != {"owner", "authority", "evidence_path", "technical_status"} or any(not isinstance(acceptance.get(key), str) or not acceptance[key] for key in ("owner", "authority", "evidence_path")) or acceptance.get("technical_status") not in {"FAIL", "NOT_VERIFIED"}:
                    _error(errors, f"dependency {record.get('id')!r}: external acceptance needs owner, authority, evidence, and non-PASS technical status")
            dependency_statuses[str(record["id"])] = str(status_value)
    statuses = dict(dependency_statuses)
    controls = _ordered_records(manifest.get("controls"), field="id", errors=errors, context="controls")
    if {record.get("id") for record in controls} != REQUIRED_GATES:
        _error(errors, "controls: required readiness gate inventory mismatch")
    if set(dependency_statuses).intersection(record.get("id") for record in controls):
        _error(errors, "controls: dependency and control identifiers must not collide")
    for record in controls:
        status_value = record.get("status")
        dependencies = record.get("dependencies")
        allowed = {"id", "status", "dependencies", "evidence_paths"}
        if status_value == "EXTERNALLY_ACCEPTED":
            allowed.add("acceptance")
        if status_value == "NOT_APPLICABLE":
            allowed.add("rationale")
        if status_value == "EXTERNALLY_ACCEPTED" and set(record) != allowed:
            _error(errors, f"control {record.get('id')!r}: external acceptance needs owner, authority, evidence, and non-PASS technical status")
            continue
        evidence_paths = record.get("evidence_paths")
        if set(record) != allowed or status_value not in STATUS_VALUES or not isinstance(dependencies, list) or tuple(dependencies) != GATE_DEPENDENCIES.get(record.get("id")) or not isinstance(evidence_paths, list) or tuple(evidence_paths) != GATE_EVIDENCE.get(record.get("id")):
            _error(errors, f"control {record.get('id')!r}: invalid status or dependency")
            continue
        if dependencies != sorted(dependencies) or len(set(dependencies)) != len(dependencies):
            _error(errors, f"control {record.get('id')!r}: dependencies must be uniquely sorted")
        if status_value == "NOT_APPLICABLE" and (not isinstance(record.get("rationale"), str) or not record["rationale"]):
            _error(errors, f"control {record.get('id')!r}: NOT_APPLICABLE needs rationale")
        if status_value == "EXTERNALLY_ACCEPTED":
            acceptance = _mapping(record.get("acceptance"))
            if acceptance is None or set(acceptance) != {"owner", "authority", "evidence_path", "technical_status"} or any(not isinstance(acceptance.get(key), str) or not acceptance[key] for key in ("owner", "authority", "evidence_path")) or acceptance.get("technical_status") not in {"FAIL", "NOT_VERIFIED"}:
                _error(errors, f"control {record.get('id')!r}: external acceptance needs owner, authority, evidence, and non-PASS technical status")
        statuses[str(record["id"])] = str(status_value)
    nonclaims = manifest.get("nonclaims")
    if not isinstance(nonclaims, list) or not nonclaims or any(not isinstance(item, str) or not item for item in nonclaims) or nonclaims != sorted(nonclaims) or len(set(nonclaims)) != len(nonclaims):
        _error(errors, "nonclaims: non-empty uniquely sorted explicit nonclaims required")
    return statuses


def _aggregate_outcomes(outcomes: list[object]) -> str | None:
    """Return the only valid closed aggregate for a non-empty outcome set."""
    if not outcomes or any(outcome not in {"PASS", "FAIL", "NOT_VERIFIED", "NOT_APPLICABLE"} for outcome in outcomes):
        return None
    if "FAIL" in outcomes:
        return "FAIL"
    if "NOT_VERIFIED" in outcomes:
        return "NOT_VERIFIED"
    if all(outcome == "NOT_APPLICABLE" for outcome in outcomes):
        return "NOT_APPLICABLE"
    if "PASS" in outcomes:
        return "PASS"
    return None


def _verify_profile_evidence(manifest: dict[str, Any], json_records: dict[str, dict[str, Any]], declared: set[str], errors: list[str]) -> None:
    if declared != profile_files(manifest) | {"README.md", "verify_assessment_bundle.py"}:
        _error(errors, "evidence: closed profile file inventory mismatch")
    sources = manifest.get("sources") if isinstance(manifest.get("sources"), list) else []
    subjects = manifest.get("subjects") if isinstance(manifest.get("subjects"), list) else []
    producer = _mapping(manifest.get("producer")) or {}
    policy = _mapping(manifest.get("policy")) or {}
    core = {"scope", "outcome", "sources", "subjects", "producer", "policy"}
    required_fields = {
        "contracts/clinical-composition.json": core | {"claim_id"},
        "evidence/bounded-inputs.json": core | {"inputs"},
        "evidence/clinical-receipt.json": core | {"negative_controls"},
        "evidence/cold-recovery.json": core | {"manifest_sha256", "recovery_receipt_sha256"},
        "evidence/hrh-publication.json": core | {"publication_receipt_sha256", "verification_receipt_sha256"},
        "evidence/representative-host.json": core | {"observations"},
        "governance/risk-map.json": core | {"risk_owner", "risks"},
        "independent-review/findings.json": core | {"reviewer_id", "authority", "conflict_statement", "findings", "technical_go_no_go"},
        "subjects/images.json": core | {"edge_candidate_manifest_sha256"},
    }
    if manifest.get("profile") == BOUND_REVIEW_PROFILE:
        required_fields[REVIEW_PATH] = required_fields[REVIEW_PATH] | {"reviewed_manifest_sha256"}
    for path, required in required_fields.items():
        evidence = json_records.get(path)
        if not isinstance(evidence, dict):
            _error(errors, f"evidence {path}: profile content binding is incomplete")
            continue
        outcome = evidence.get("outcome")
        common_is_bound = (
            evidence.get("scope") == SCOPE
            and evidence.get("sources") == sources
            and evidence.get("subjects") == subjects
            and evidence.get("producer") == producer
            and evidence.get("policy") == policy
        )
        if outcome == "NOT_VERIFIED":
            if path == "evidence/representative-host.json":
                expected = core | {"observations"}
            elif path == "subjects/images.json":
                expected = core | {"reason", "edge_candidate_manifest_sha256"}
            else:
                expected = core | {"reason"}
            if set(evidence) != expected or not common_is_bound:
                _error(errors, f"evidence {path}: NOT_VERIFIED must contain only the closed binding")
            if path != "evidence/representative-host.json" and (
                not isinstance(evidence.get("reason"), str)
                or not IDENTIFIER.fullmatch(evidence["reason"])
            ):
                _error(errors, f"evidence {path}: NOT_VERIFIED needs a closed reason")
        elif outcome == "NOT_APPLICABLE":
            if path == "evidence/representative-host.json":
                expected = core | {"observations"}
            elif path == "subjects/images.json":
                expected = core | {"rationale", "edge_candidate_manifest_sha256"}
            else:
                expected = core | {"rationale"}
            rationale_is_closed = path == "evidence/representative-host.json" or (isinstance(evidence.get("rationale"), str) and IDENTIFIER.fullmatch(evidence["rationale"]))
            if set(evidence) != expected or not common_is_bound or not rationale_is_closed:
                _error(errors, f"evidence {path}: NOT_APPLICABLE needs only a closed rationale")
        elif outcome in {"PASS", "FAIL"}:
            if set(evidence) != required or not common_is_bound:
                _error(errors, f"evidence {path}: {outcome} proof binding is incomplete")
        else:
            _error(errors, f"evidence {path}: technical outcome must be PASS, FAIL, NOT_APPLICABLE, or NOT_VERIFIED")
    clinical = json_records.get("evidence/clinical-receipt.json", {})
    if clinical.get("outcome") in {"PASS", "FAIL"} and (not isinstance(clinical.get("negative_controls"), list) or not clinical["negative_controls"]):
        _error(errors, "evidence clinical receipt: exact source/subject/negative-control binding required")
    images = json_records.get("subjects/images.json", {})
    if images.get("outcome") in {"PASS", "FAIL"} and images.get("subjects") != subjects:
        _error(errors, "evidence subject inventory: exact four-subject binding required")
    if images.get("outcome") in {"PASS", "FAIL", "NOT_VERIFIED", "NOT_APPLICABLE"} and (
        not isinstance(images.get("edge_candidate_manifest_sha256"), str)
        or not SHA256.fullmatch(images["edge_candidate_manifest_sha256"])
    ):
        _error(errors, "evidence subject inventory: edge candidate manifest sha256 required")
    bounded = json_records.get("evidence/bounded-inputs.json", {})
    if bounded.get("outcome") in {"PASS", "FAIL"}:
        inputs = _ordered_records(bounded.get("inputs"), field="id", errors=errors, context="evidence bounded inputs")
        if {item.get("id") for item in inputs} != set(BOUNDED_INPUT_CLASSIFICATIONS):
            _error(errors, "evidence bounded inputs: exact three-input inventory required")
        for item in inputs:
            identifier = item.get("id")
            hosted_ci = _mapping(item.get("hosted_ci"))
            if (
                set(item) != {"id", "source_revision", "source_tree", "evidence_artifact_sha256", "hosted_ci", "classification"}
                or not isinstance(item.get("source_revision"), str)
                or not GIT_OBJECT.fullmatch(item["source_revision"])
                or not isinstance(item.get("source_tree"), str)
                or not GIT_OBJECT.fullmatch(item["source_tree"])
                or not isinstance(item.get("evidence_artifact_sha256"), str)
                or not SHA256.fullmatch(item["evidence_artifact_sha256"])
                or item.get("classification") != BOUNDED_INPUT_CLASSIFICATIONS.get(identifier)
                or hosted_ci is None
                or set(hosted_ci) != {"run_url", "head_sha", "receipt_sha256", "conclusion"}
                or hosted_ci.get("run_url") != BOUNDED_INPUT_CI_RUN_URLS.get(identifier)
                or hosted_ci.get("head_sha") != item.get("source_revision")
                or not isinstance(hosted_ci.get("receipt_sha256"), str)
                or not SHA256.fullmatch(hosted_ci["receipt_sha256"])
                or hosted_ci.get("conclusion") != "PASS"
            ):
                _error(errors, f"evidence bounded input {identifier!r}: closed provenance or classification mismatch")
    host = json_records.get("evidence/representative-host.json", {})
    observations = host.get("observations")
    exact_host_inventory = (
        isinstance(observations, list)
        and [item.get("id") if isinstance(item, dict) else None for item in observations] == list(HOST_OBSERVATIONS)
    )
    observation_shapes_valid = exact_host_inventory
    observation_outcomes: list[object] = []
    for item in observations if isinstance(observations, list) else []:
        if not isinstance(item, dict):
            observation_shapes_valid = False
            continue
        item_outcome = item.get("outcome")
        observation_outcomes.append(item_outcome)
        if item_outcome in {"PASS", "FAIL"}:
            valid = set(item) == {"id", "outcome", "witness_sha256"} and isinstance(item.get("witness_sha256"), str) and SHA256.fullmatch(item["witness_sha256"])
        elif item_outcome == "NOT_VERIFIED":
            valid = set(item) == {"id", "outcome", "reason"} and isinstance(item.get("reason"), str) and IDENTIFIER.fullmatch(item["reason"])
        elif item_outcome == "NOT_APPLICABLE":
            valid = set(item) == {"id", "outcome", "rationale"} and isinstance(item.get("rationale"), str) and IDENTIFIER.fullmatch(item["rationale"])
        else:
            valid = False
        observation_shapes_valid = observation_shapes_valid and bool(valid)
    host_aggregate = _aggregate_outcomes(observation_outcomes)
    if not observation_shapes_valid:
        _error(errors, "evidence representative host: exact conditional observation shapes required")
    if host.get("outcome") in {"PASS", "FAIL", "NOT_VERIFIED", "NOT_APPLICABLE"} and host_aggregate != host.get("outcome"):
        _error(errors, "evidence representative host: outcome does not match the observation lattice")
    publication = json_records.get("evidence/hrh-publication.json", {})
    if publication.get("outcome") in {"PASS", "FAIL"} and any(not isinstance(publication.get(field), str) or not SHA256.fullmatch(publication[field]) for field in ("publication_receipt_sha256", "verification_receipt_sha256")):
        _error(errors, "evidence HRH publication: external publication and verification receipt sha256 bindings required")
    recovery = json_records.get("evidence/cold-recovery.json", {})
    if recovery.get("outcome") in {"PASS", "FAIL"}:
        if not isinstance(recovery.get("manifest_sha256"), str) or not SHA256.fullmatch(recovery["manifest_sha256"]):
            _error(errors, "evidence cold recovery: immutable manifest sha256 required")
        if not isinstance(recovery.get("recovery_receipt_sha256"), str) or not SHA256.fullmatch(recovery["recovery_receipt_sha256"]):
            _error(errors, "evidence cold recovery: recovery receipt sha256 required")
    review = json_records.get("independent-review/findings.json", {})
    if review.get("outcome") in {"PASS", "FAIL"} and (any(not isinstance(review.get(key), str) or not IDENTIFIER.fullmatch(review[key]) for key in ("reviewer_id", "authority", "conflict_statement")) or not isinstance(review.get("findings"), list) or not review["findings"] or any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item) for item in review["findings"]) or review.get("technical_go_no_go") != ("GO" if review.get("outcome") == "PASS" else "NO_GO")):
        _error(errors, "evidence independent review: identity/authority/conflict/findings/go-no-go required")
    contract = json_records.get("contracts/clinical-composition.json", {})
    if contract.get("outcome") in {"PASS", "FAIL"} and (not isinstance(contract.get("claim_id"), str) or not IDENTIFIER.fullmatch(contract["claim_id"])):
        _error(errors, "evidence clinical contract: closed claim identifier required")
    if clinical.get("outcome") in {"PASS", "FAIL"} and not all(isinstance(item, str) and IDENTIFIER.fullmatch(item) for item in clinical.get("negative_controls", [])):
        _error(errors, "evidence clinical receipt: closed negative-control identifiers required")
    risk_map = json_records.get("governance/risk-map.json", {})
    risks = risk_map.get("risks")
    if risk_map.get("outcome") in {"PASS", "FAIL"} and (not isinstance(risk_map.get("risk_owner"), str) or not IDENTIFIER.fullmatch(risk_map["risk_owner"]) or not isinstance(risks, list)):
        _error(errors, "evidence governance: closed risk disposition required")
    elif risk_map.get("outcome") in {"PASS", "FAIL"}:
        for risk in risks:
            item = _mapping(risk)
            if item is None or item.get("severity") not in {"P1", "P2"} or item.get("disposition") not in {"CLOSED", "EXTERNALLY_ACCEPTED"} or not isinstance(item.get("id"), str) or not IDENTIFIER.fullmatch(item["id"]):
                _error(errors, "evidence governance: P1/P2 must be closed or explicitly accepted")
                continue
            if item["disposition"] == "EXTERNALLY_ACCEPTED":
                acceptance = _mapping(item.get("acceptance"))
                if set(item) != {"id", "severity", "disposition", "acceptance"} or acceptance is None or set(acceptance) != {"owner", "authority", "evidence_path"} or any(not isinstance(acceptance.get(key), str) or not IDENTIFIER.fullmatch(acceptance[key]) for key in ("owner", "authority")) or acceptance.get("evidence_path") != "governance/risk-map.json":
                    _error(errors, "evidence governance: accepted risk needs authority evidence")
            elif set(item) != {"id", "severity", "disposition"}:
                _error(errors, "evidence governance: closed risk record has extra content")
    controls = manifest.get("controls") if isinstance(manifest.get("controls"), list) else []
    for control in controls:
        if not isinstance(control, dict):
            continue
        outcomes = [json_records.get(path, {}).get("outcome") for path in control.get("evidence_paths", [])]
        status_value = control.get("status")
        aggregate = _aggregate_outcomes(outcomes)
        if status_value in {"PASS", "FAIL", "NOT_VERIFIED", "NOT_APPLICABLE"} and aggregate != status_value:
            _error(errors, f"control {control.get('id')!r}: status does not match the evidence lattice")
        elif status_value == "EXTERNALLY_ACCEPTED":
            acceptance = _mapping(control.get("acceptance")) or {}
            technical_status = acceptance.get("technical_status")
            if technical_status not in {"FAIL", "NOT_VERIFIED"} or aggregate != technical_status:
                _error(errors, f"control {control.get('id')!r}: external acceptance must retain its non-PASS technical evidence")
        if isinstance(control, dict) and control.get("id") == "immutable-application-subjects" and control.get("status") == "PASS" and any(isinstance(subject, dict) and subject.get("status") != "PASS" for subject in subjects):
            _error(errors, "control immutable-application-subjects: PASS requires all four immutable subjects PASS")


def _verify_prereview_binding(manifest: dict[str, Any], json_records: dict[str, dict[str, Any]], raw_records: dict[str, bytes], errors: list[str]) -> None:
    """Bind a v2 verdict to retained A10P bytes and unchanged non-review inputs.

    A10P remains separately frozen. A10F hashes its retained manifest and A9;
    neither A9 nor A10P contains the hash of the enclosing A10F manifest.
    This verifies evidence identity, not the reviewer's authority or sincerity.
    """
    review = json_records.get(REVIEW_PATH, {})
    if manifest.get("profile") != BOUND_REVIEW_PROFILE or review.get("outcome") not in {"PASS", "FAIL"}:
        return
    raw = raw_records.get(PREREVIEW_MANIFEST_PATH)
    pre = json_records.get(PREREVIEW_MANIFEST_PATH)
    expected = review.get("reviewed_manifest_sha256")
    if raw is None or pre is None:
        _error(errors, "pre-review: exact retained manifest required for PASS/FAIL findings")
        return
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(raw).hexdigest() != expected:
        _error(errors, "pre-review: reviewed_manifest_sha256 does not bind retained bytes")
    if raw != canonical_json(pre):
        _error(errors, "pre-review: canonical manifest bytes required")
    metadata_errors: list[str] = []
    _verify_metadata(pre, metadata_errors)
    errors.extend("pre-review: " + error for error in metadata_errors)
    if pre.get("profile") != BOUND_REVIEW_PROFILE:
        _error(errors, "pre-review: v2 input profile required")
    for key in ROOT_KEYS - {"candidate_id", "files", "controls"}:
        if pre.get(key) != manifest.get(key):
            _error(errors, f"pre-review: final {key} differs from reviewed input")
    pre_controls = pre.get("controls")
    final_controls = manifest.get("controls")
    if not isinstance(pre_controls, list) or not isinstance(final_controls, list):
        _error(errors, "pre-review: control inventory required")
        return
    pre_review = [item for item in pre_controls if isinstance(item, dict) and item.get("id") == "independent-review"]
    if pre_review != [{"id": "independent-review", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": [REVIEW_PATH]}]:
        _error(errors, "pre-review: input review gate must be the NOT_VERIFIED placeholder")
    if [item for item in pre_controls if isinstance(item, dict) and item.get("id") != "independent-review"] != [item for item in final_controls if isinstance(item, dict) and item.get("id") != "independent-review"]:
        _error(errors, "pre-review: final non-review controls changed")
    pre_files = pre.get("files")
    if not isinstance(pre_files, list) or not all(isinstance(item, dict) and set(item) == {"path", "size", "media_type", "sha256"} for item in pre_files):
        _error(errors, "pre-review: closed file inventory required")
        return
    paths = [item.get("path") for item in pre_files]
    expected_paths = PROFILE_FILES | {"README.md", "verify_assessment_bundle.py"}
    if any(not isinstance(path, str) for path in paths) or paths != sorted(expected_paths):
        _error(errors, "pre-review: input file inventory must exclude retained/final manifests")
    for item in pre_files:
        if (not isinstance(item.get("size"), int) or not 0 <= item["size"] <= MAX_FILE_BYTES
                or item.get("media_type") != MEDIA_TYPES.get(Path(str(item.get("path"))).suffix)
                or not isinstance(item.get("sha256"), str) or not SHA256.fullmatch(item["sha256"])):
            _error(errors, "pre-review: invalid file metadata")
    final_files = manifest.get("files", [])
    if [item for item in pre_files if item.get("path") != REVIEW_PATH] != [item for item in final_files if isinstance(item, dict) and item.get("path") not in {REVIEW_PATH, PREREVIEW_MANIFEST_PATH}]:
        _error(errors, "pre-review: final non-review evidence bytes differ from reviewed input")


def verify(bundle_dir: Path, *, expected_manifest_sha256: str) -> VerificationResult:
    """Verify only bundle content; no checkout, source tree, or network is used."""
    errors: list[str] = []
    statuses: dict[str, str] = {}
    if not isinstance(expected_manifest_sha256, str) or not SHA256.fullmatch(expected_manifest_sha256):
        return VerificationResult(["expected manifest sha256 is required"], statuses, False)
    expected = expected_manifest_sha256.removeprefix("sha256:")
    try:
        root_mode = bundle_dir.lstat().st_mode
    except OSError as exc:
        return VerificationResult([f"bundle: unavailable: {exc}"], statuses, False)
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        return VerificationResult(["bundle: real directory required"], statuses, False)
    manifest_path = bundle_dir / "assessment.manifest.json"
    if not _regular(manifest_path, errors, "manifest"):
        return VerificationResult(errors, statuses, False)
    manifest_raw = _bounded_read(manifest_path, errors, "manifest")
    if manifest_raw is None:
        return VerificationResult(errors, statuses, False)
    try:
        manifest = json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        return VerificationResult([*errors, f"manifest: unreadable: {exc}"], statuses, False)
    if hashlib.sha256(manifest_raw).hexdigest() != expected:
        _error(errors, "manifest: external expected sha256 does not match")
    record = _mapping(manifest)
    if record is None:
        return VerificationResult([*errors, "manifest: object required"], statuses, False)
    if manifest_raw != canonical_json(record):
        _error(errors, "manifest: canonical byte ordering required")
    statuses = _verify_metadata(record, errors)
    file_records = record.get("files")
    if not isinstance(file_records, list) or not file_records or len(file_records) > MAX_FILES:
        _error(errors, "files: bounded non-empty list required")
        return VerificationResult(errors, statuses, False)
    declared: dict[str, dict[str, Any]] = {}
    prior_paths: list[str] = []
    for item in file_records:
        file_record = _mapping(item)
        if file_record is None or set(file_record) != {"path", "size", "media_type", "sha256"}:
            _error(errors, "files: exact path/size/media_type/sha256 records required")
            continue
        relative = _safe_relative(file_record.get("path"))
        if relative is None or not _allowed_path(relative) or relative == "assessment.manifest.json":
            _error(errors, "files: path is not allowlisted")
            continue
        if not isinstance(file_record.get("size"), int) or not 0 <= file_record["size"] <= MAX_FILE_BYTES or file_record.get("media_type") != MEDIA_TYPES.get(Path(relative).suffix) or not isinstance(file_record.get("sha256"), str) or not SHA256.fullmatch(file_record["sha256"]):
            _error(errors, f"files: invalid metadata for {relative}")
            continue
        declared[relative] = file_record
        prior_paths.append(relative)
    if prior_paths != sorted(prior_paths) or len(declared) != len(file_records):
        _error(errors, "files: uniquely sorted canonical paths required")
    required = {"README.md", "verify_assessment_bundle.py"}
    if not required.issubset(declared):
        _error(errors, "files: README and verifier must be hashed")
    actual: set[str] = set()
    actual_dirs: set[str] = set()
    pending = [bundle_dir]
    visited = 0
    while pending:
        directory = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError as exc:
            _error(errors, f"bundle directory: unreadable: {exc}")
            break
        with iterator:
            for entry in iterator:
                visited += 1
                if visited > MAX_FILES + len(PROFILE_FILES) + 8:
                    _error(errors, "bundle: traversal member limit exceeded")
                    pending.clear()
                    break
                path = Path(entry.path)
                relative = path.relative_to(bundle_dir).as_posix()
                try:
                    mode = path.lstat().st_mode
                except OSError as exc:
                    _error(errors, f"bundle member {relative}: unavailable: {exc}")
                    continue
                if stat.S_ISLNK(mode):
                    _error(errors, f"bundle member {relative}: symlink is forbidden")
                elif stat.S_ISDIR(mode):
                    actual_dirs.add(relative)
                    pending.append(path)
                elif stat.S_ISREG(mode):
                    actual.add(relative)
                else:
                    _error(errors, f"bundle member {relative}: regular file required")
    expected_paths = set(declared) | {"assessment.manifest.json"}
    if actual != expected_paths:
        _error(errors, "bundle: missing or unexpected content")
    expected_dirs = {str(PurePosixPath(relative).parent) for relative in expected_paths if str(PurePosixPath(relative).parent) != "."}
    if actual_dirs != expected_dirs:
        _error(errors, "bundle: unexpected directory content")
    total = len(manifest_raw)
    json_records: dict[str, dict[str, Any]] = {}
    raw_records: dict[str, bytes] = {}
    for relative, metadata in declared.items():
        path = bundle_dir / relative
        if not _regular(path, errors, relative):
            continue
        raw = _bounded_read(path, errors, relative)
        if raw is None:
            continue
        total += len(raw)
        raw_records[relative] = raw
        if len(raw) != metadata["size"] or hashlib.sha256(raw).hexdigest() != metadata["sha256"].removeprefix("sha256:"):
            _error(errors, f"{relative}: size or hash mismatch")
        if _secret_bearing(raw):
            _error(errors, f"{relative}: secret-bearing content is forbidden")
        if Path(relative).suffix == ".json":
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                _error(errors, f"{relative}: valid JSON object required")
            else:
                parsed_record = _mapping(parsed)
                if parsed_record is None:
                    _error(errors, f"{relative}: JSON object required")
                else:
                    json_records[relative] = parsed_record
        if relative == "README.md" and raw != README_CONTENT.encode("ascii"):
            _error(errors, "README: fixed content required")
    if _secret_bearing(manifest_raw):
        _error(errors, "manifest: secret-bearing content is forbidden")
    if total > MAX_TOTAL_BYTES:
        _error(errors, "bundle: total content limit exceeded")
    _verify_profile_evidence(record, json_records, set(declared), errors)
    _verify_prereview_binding(record, json_records, raw_records, errors)
    evidence_paths = set(declared)
    for key in ("dependencies", "controls"):
        status_records = record.get(key)
        if not isinstance(status_records, list):
            continue
        for status_record in status_records:
            if isinstance(status_record, dict) and status_record.get("status") == "EXTERNALLY_ACCEPTED":
                acceptance = _mapping(status_record.get("acceptance"))
                if acceptance is not None and acceptance.get("evidence_path") not in evidence_paths:
                    _error(errors, f"status {status_record.get('id')!r}: acceptance evidence is not a bundled hash")
    blockers = {"FAIL", "NOT_VERIFIED", "EXTERNALLY_ACCEPTED"}
    ready = (not errors and not any(status in blockers for status in statuses.values())
             and all(statuses.get(dependency) == "PASS" for dependency in REQUIRED_DEPENDENCIES)
             and all(statuses.get(gate) == "PASS" for gate in REQUIRED_GATES)
             and json_records.get("independent-review/findings.json", {}).get("technical_go_no_go") == "GO")
    return VerificationResult(errors, statuses, ready)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_dir", type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    result = verify(args.bundle_dir, expected_manifest_sha256=args.expected_manifest_sha256)
    if result.errors:
        print(*["assessment bundle: FAIL: " + error for error in result.errors], sep="\n", file=sys.stderr)
        return 1
    state = "READY" if result.ready_for_technical_go else "NOT_READY"
    print(f"assessment bundle: PASS ({state})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
