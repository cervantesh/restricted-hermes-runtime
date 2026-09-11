from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "representative_host_conformance.py"
HEAD = "a" * 40
TREE = "b" * 40
MANIFEST = "c" * 64
EGRESS = "d" * 64
SUBJECT_SET = "e" * 64


def load_module():
    spec = importlib.util.spec_from_file_location("representative_host_conformance", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(module, *, outcome="PASS"):
    claims = []
    for claim_id in module.CLAIM_IDS:
        claims.append(
            {
                "id": claim_id,
                "outcome": outcome,
                "proof_sha256": hashlib.sha256(claim_id.encode()).hexdigest(),
                "diagnostic": "none" if outcome == "PASS" else "controlled-negative",
            }
        )
    return {
        "schema": module.SCHEMA,
        "synthetic_non_phi_only": True,
        "nonclaims": {
            "phi_authorized": False,
            "deployment_conformant": False,
            "independent_assessment": False,
        },
        "candidate": {
            "runtime_head": HEAD,
            "runtime_tree": TREE,
            "candidate_manifest_sha256": MANIFEST,
            "subject_set_sha256": SUBJECT_SET,
        },
        "inputs": {"container_egress_receipt_sha256": EGRESS},
        "host": {"class": "ubuntu-24.04-lts-x86_64", "toolchain_sha256": "f" * 64},
        "claims": claims,
        "verifier": {"version": "p2-host-conformance-v1", "command_set_sha256": "0" * 64},
        "outcome": outcome,
    }


def test_valid_green_receipt_is_canonical_and_candidate_bound():
    module = load_module()
    value = receipt(module)

    assert module.verify_receipt(
        module.canonical_bytes(value),
        expected_runtime_head=HEAD,
        expected_runtime_tree=TREE,
        expected_candidate_manifest_sha256=MANIFEST,
        expected_subject_set_sha256=SUBJECT_SET,
        expected_egress_receipt_sha256=EGRESS,
        expected_outcome="PASS",
    ) == []


def test_valid_red_receipt_is_structurally_valid_but_cannot_satisfy_green_gate():
    module = load_module()
    value = receipt(module, outcome="FAIL")
    raw = module.canonical_bytes(value)

    assert module.verify_receipt(
        raw,
        expected_runtime_head=HEAD,
        expected_runtime_tree=TREE,
        expected_candidate_manifest_sha256=MANIFEST,
        expected_subject_set_sha256=SUBJECT_SET,
        expected_egress_receipt_sha256=EGRESS,
        expected_outcome="FAIL",
    ) == []
    assert "outcome" in module.verify_receipt(
        raw,
        expected_runtime_head=HEAD,
        expected_runtime_tree=TREE,
        expected_candidate_manifest_sha256=MANIFEST,
        expected_subject_set_sha256=SUBJECT_SET,
        expected_egress_receipt_sha256=EGRESS,
        expected_outcome="PASS",
    )


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda value: value["candidate"].update(runtime_head="0" * 40), "runtime-head"),
        (lambda value: value["candidate"].update(subject_set_sha256="not-a-digest"), "candidate"),
        (lambda value: value["candidate"].update(subject_set_sha256="1" * 64), "subject-set"),
        (lambda value: value["inputs"].update(container_egress_receipt_sha256="0" * 64), "egress"),
        (lambda value: value["claims"].pop(), "claims"),
        (lambda value: value["claims"][0].update(proof_sha256="raw-secret-value"), "claims"),
        (lambda value: value.update(raw_log="forbidden"), "fields"),
        (lambda value: value["host"].update(**{"class": "host-10.0.0.7"}), "host"),
    ],
)
def test_substitution_missing_claim_or_content_bearing_field_is_rejected(mutate, expected):
    module = load_module()
    value = receipt(module)
    mutate(value)

    assert expected in module.verify_receipt(
        module.canonical_bytes(value),
        expected_runtime_head=HEAD,
        expected_runtime_tree=TREE,
        expected_candidate_manifest_sha256=MANIFEST,
        expected_subject_set_sha256=SUBJECT_SET,
        expected_egress_receipt_sha256=EGRESS,
        expected_outcome="PASS",
    )


def test_noncanonical_or_duplicate_json_cannot_be_a_receipt():
    module = load_module()
    value = receipt(module)
    pretty = json.dumps(value, indent=2).encode() + b"\n"
    duplicate = module.canonical_bytes(value).replace(b'{', b'{"schema":"other",', 1)

    for raw in (pretty, duplicate):
        assert "canonical" in module.verify_receipt(
            raw,
            expected_runtime_head=HEAD,
            expected_runtime_tree=TREE,
            expected_candidate_manifest_sha256=MANIFEST,
            expected_subject_set_sha256=SUBJECT_SET,
            expected_egress_receipt_sha256=EGRESS,
            expected_outcome="PASS",
        )
