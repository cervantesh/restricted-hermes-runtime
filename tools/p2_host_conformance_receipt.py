#!/usr/bin/env python3
"""Build and verify the closed, content-safe P2 host-conformance receipt.

This is an evaluator-side schema. It accepts only outcome labels, immutable
subjects, approved tool versions, and proof digests; callers must retain raw
host observations privately. It does not itself execute privileged host work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "restricted-runtime-p2-host-conformance.v1"
HOST_CLASS = "ubuntu-24.04-lts-x86_64"
CONTROL_NAMES = (
    "admission", "subjects", "secrets", "egress",
    "trust_audit_retention", "recovery", "cleanup", "replay",
)
_SHA = re.compile(r"[a-f0-9]{40}")
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_HEX256 = re.compile(r"[a-f0-9]{64}")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[+._-][A-Za-z0-9._-]+)?")
_CLAIMS = {
    "phi_authorized": False,
    "deployment_conformant": False,
    "independent_assessment": False,
}
_CONTROL_EXPECTATIONS = {
    "admission": {"green": "pass", "unsupported_topology": "deny", "remote_docker": "deny", "unapproved_action": "deny"},
    "subjects": {"green": "pass", "missing": "deny", "substituted": "deny", "mutable": "deny"},
    "secrets": {"green": "pass", "absent": "deny", "stale": "deny", "malformed": "deny", "rotated_away": "deny", "rotation": "pass"},
    "egress": {"green": "pass", "public_ipv4": "deny", "public_ipv6": "deny", "dns_override": "deny", "literal_ip": "deny", "proxy_variable": "deny", "metadata": "deny", "telemetry_download": "deny", "redirect": "deny", "disallowed_sink": "deny"},
    "trust_audit_retention": {"green": "pass", "untrusted": "deny", "audit_unavailable": "deny", "retention_mismatch": "deny"},
    "recovery": {"green": "pass", "invalid_state": "deny", "conflicting_state": "deny", "non_owned_state": "deny"},
    "cleanup": {"green": "pass", "non_owned_resource": "deny"},
    "replay": {"independent": "pass"},
}


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


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


def _candidate(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree", "subjects", "manifest_sha256"}:
        return None
    if not all(isinstance(value[key], str) and _SHA.fullmatch(value[key]) for key in ("runtime_head", "runtime_tree", "hrh_head", "hrh_tree")):
        return None
    subjects = value["subjects"]
    if not isinstance(subjects, dict) or set(subjects) != {"clinical-adapter", "mattermost-ingress"}:
        return None
    if not all(isinstance(digest, str) and _DIGEST.fullmatch(digest) for digest in subjects.values()):
        return None
    if not isinstance(value["manifest_sha256"], str) or not _HEX256.fullmatch(value["manifest_sha256"]):
        return None
    return deepcopy(value)


def _host(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != {"class", "system", "architecture", "tools"}:
        return None
    if value["class"] != HOST_CLASS or value["system"] != "Linux" or value["architecture"] != "x86_64":
        return None
    tools = value["tools"]
    if not isinstance(tools, dict) or set(tools) != {"docker", "compose", "python"}:
        return None
    if not all(isinstance(version, str) and _VERSION.fullmatch(version) for version in tools.values()):
        return None
    return deepcopy(value)


def _controls(value: object) -> dict[str, dict[str, str]] | None:
    if not isinstance(value, dict) or set(value) != set(CONTROL_NAMES):
        return None
    if not all(_strict_equal(value[name], _CONTROL_EXPECTATIONS[name]) for name in CONTROL_NAMES):
        return None
    return deepcopy(value)


def _proofs(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != set(CONTROL_NAMES):
        return None
    if not all(isinstance(digest, str) and _HEX256.fullmatch(digest) for digest in value.values()):
        return None
    return dict(value)


def _proof_hashes(evidence_dir: Path) -> dict[str, str]:
    if not evidence_dir.is_dir():
        raise ValueError("proofs")
    result: dict[str, str] = {}
    for name in CONTROL_NAMES:
        path = evidence_dir / f"{name}.json"
        if not path.is_file() or path.is_symlink():
            raise ValueError("proofs")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def build_receipt(evidence: Mapping[str, Any], *, expected_candidate: Mapping[str, Any], evidence_dir: Path) -> dict[str, Any]:
    candidate = _candidate(evidence.get("candidate"))
    host = _host(evidence.get("host"))
    controls = _controls(evidence.get("controls"))
    expected = _candidate(expected_candidate)
    if candidate is None or expected is None or not _strict_equal(candidate, expected):
        raise ValueError("candidate evidence is incomplete")
    if host is None:
        raise ValueError("host evidence is incomplete")
    if controls is None:
        raise ValueError("controls are incomplete")
    proofs = _proof_hashes(evidence_dir)
    receipt = {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "claims": deepcopy(_CLAIMS),
        "candidate": candidate,
        "host": host,
        "controls": controls,
        "proofs": proofs,
    }
    if verify_receipt(canonical_bytes(receipt), expected_candidate=candidate, evidence_dir=evidence_dir):
        raise ValueError("P2 receipt is not admissible")
    return receipt


def verify_receipt(raw: bytes, *, expected_candidate: Mapping[str, Any], evidence_dir: Path) -> list[str]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return ["canonical"]
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return ["canonical"]
    if set(value) != {"schema", "synthetic_non_phi_only", "claims", "candidate", "host", "controls", "proofs"}:
        return ["fields"]
    if value["schema"] != SCHEMA or value["synthetic_non_phi_only"] is not True:
        return ["schema"]
    if not _strict_equal(value["claims"], _CLAIMS):
        return ["claims"]
    candidate = _candidate(value["candidate"])
    expected = _candidate(expected_candidate)
    if candidate is None or expected is None or not _strict_equal(candidate, expected):
        return ["candidate"]
    if _host(value["host"]) is None:
        return ["host"]
    if _controls(value["controls"]) is None:
        return ["controls"]
    proofs = _proofs(value["proofs"])
    try:
        actual_proofs = _proof_hashes(evidence_dir)
    except (OSError, ValueError):
        actual_proofs = None
    if proofs is None or actual_proofs is None or not _strict_equal(proofs, actual_proofs):
        return ["proofs"]
    return []


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--evidence", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--proof-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.evidence:
            if args.output is None:
                raise ValueError("input")
            receipt = build_receipt(_read_object(args.evidence), expected_candidate=_read_object(args.candidate), evidence_dir=args.proof_dir)
            write_new(args.output, receipt)
            print("p2-host-conformance: PASS receipt_sha256=" + hashlib.sha256(canonical_bytes(receipt)).hexdigest())
            return 0
        if args.output is not None:
            raise ValueError("input")
        errors = verify_receipt(args.verify.read_bytes(), expected_candidate=_read_object(args.candidate), evidence_dir=args.proof_dir)
        if errors:
            raise ValueError("receipt")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        print("p2-host-conformance: DENIED class=input", file=os.sys.stderr)
        return 2
    print("p2-host-conformance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
