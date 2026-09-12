from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p2_host_conformance_receipt.py"

RUNTIME_HEAD = "7" * 40
RUNTIME_TREE = "3" * 40
HRH_HEAD = "a" * 40
HRH_TREE = "f" * 40
SUBJECTS = {
    "clinical-adapter": "sha256:" + "5" * 64,
    "mattermost-ingress": "sha256:" + "d" * 64,
}


def load_module():
    spec = importlib.util.spec_from_file_location("p2_host_conformance_receipt", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence(module):
    return {
        "candidate": {
            "runtime_head": RUNTIME_HEAD,
            "runtime_tree": RUNTIME_TREE,
            "hrh_head": HRH_HEAD,
            "hrh_tree": HRH_TREE,
            "subjects": dict(SUBJECTS),
            "manifest_sha256": "b" * 64,
        },
        "host": {
            "class": module.HOST_CLASS,
            "system": "Linux",
            "architecture": "x86_64",
            "tools": {"docker": "29.1.3", "compose": "2.40.3", "python": "3.12.0"},
        },
        "controls": {
            "admission": {"green": "pass", "unsupported_topology": "deny", "remote_docker": "deny", "unapproved_action": "deny"},
            "subjects": {"green": "pass", "missing": "deny", "substituted": "deny", "mutable": "deny"},
            "secrets": {"green": "pass", "absent": "deny", "stale": "deny", "malformed": "deny", "rotated_away": "deny", "rotation": "pass"},
            "egress": {"green": "pass", "public_ipv4": "deny", "public_ipv6": "deny", "dns_override": "deny", "literal_ip": "deny", "proxy_variable": "deny", "metadata": "deny", "telemetry_download": "deny", "redirect": "deny", "disallowed_sink": "deny"},
            "trust_audit_retention": {"green": "pass", "untrusted": "deny", "audit_unavailable": "deny", "retention_mismatch": "deny"},
            "recovery": {"green": "pass", "invalid_state": "deny", "conflicting_state": "deny", "non_owned_state": "deny"},
            "cleanup": {"green": "pass", "non_owned_resource": "deny"},
            "replay": {"independent": "pass"},
        },
        "proofs": {name: "c" * 64 for name in module.CONTROL_NAMES},
    }


def test_builds_a_closed_canonical_receipt_bound_to_all_required_controls():
    module = load_module()
    value = module.build_receipt(evidence(module))
    raw = module.canonical_bytes(value)
    assert module.verify_receipt(
        raw,
        expected_candidate=evidence(module)["candidate"],
    ) == []
    assert b"endpoint" not in raw and b"token" not in raw and b"credential" not in raw


@pytest.mark.parametrize("mutate, expected", [
    (lambda value: value["candidate"]["subjects"].update({"mattermost-ingress": "sha256:" + "0" * 64}), "candidate"),
    (lambda value: value["host"].update({"architecture": "arm64"}), "host"),
    (lambda value: value["controls"]["egress"].update({"metadata": "pass"}), "controls"),
    (lambda value: value["controls"].pop("replay"), "controls"),
    (lambda value: value["proofs"].pop("cleanup"), "proofs"),
    (lambda value: value["claims"].update({"phi_authorized": True}), "claims"),
    (lambda value: value.update({"raw_log": "forbidden"}), "fields"),
])
def test_rejects_subject_substitution_incomplete_matrix_claim_escalation_and_extra_fields(mutate, expected):
    module = load_module()
    source = evidence(module)
    receipt = module.build_receipt(source)
    mutate(receipt)
    assert module.verify_receipt(module.canonical_bytes(receipt), expected_candidate=source["candidate"]) == [expected]


def test_builder_refuses_any_missing_or_noncanonical_control_evidence():
    module = load_module()
    values = evidence(module)
    values["controls"]["secrets"]["rotation"] = "deny"
    with pytest.raises(ValueError, match="controls"):
        module.build_receipt(values)


def test_writer_does_not_replace_existing_receipt(tmp_path):
    module = load_module()
    output = tmp_path / "receipt.json"
    output.write_bytes(b"sentinel")
    with pytest.raises(FileExistsError):
        module.write_new(output, module.build_receipt(evidence(module)))
    assert output.read_bytes() == b"sentinel"


def test_receipt_is_immutable_from_caller_mutation():
    module = load_module()
    values = evidence(module)
    receipt = module.build_receipt(values)
    receipt["controls"]["cleanup"]["green"] = "deny"
    assert module.build_receipt(values)["controls"]["cleanup"]["green"] == "pass"


def test_cli_builds_and_verifies_without_echoing_source_inputs(tmp_path, capsys):
    module = load_module()
    values = evidence(module)
    evidence_path = tmp_path / "evidence.json"
    candidate_path = tmp_path / "candidate.json"
    output = tmp_path / "receipt.json"
    evidence_path.write_text(json.dumps(values), encoding="utf-8")
    candidate_path.write_text(json.dumps(values["candidate"]), encoding="utf-8")

    assert module.main(["--evidence", str(evidence_path), "--output", str(output)]) == 0
    assert capsys.readouterr().out.startswith("p2-host-conformance: PASS receipt_sha256=")
    assert module.main(["--verify", str(output), "--candidate", str(candidate_path)]) == 0
    assert capsys.readouterr().out == "p2-host-conformance: PASS\n"


def test_cli_denies_invalid_input_without_echoing_its_contents(tmp_path, capsys):
    module = load_module()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text('{"secret":"must-not-echo"}', encoding="utf-8")
    assert module.main(["--evidence", str(evidence_path), "--output", str(tmp_path / "receipt.json")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "p2-host-conformance: DENIED class=input\n"
