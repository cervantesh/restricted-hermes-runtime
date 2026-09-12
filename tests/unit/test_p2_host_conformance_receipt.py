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
    "restricted-clinical-adapter": "sha256:" + "5" * 64,
    "restricted-mattermost-ingress": "sha256:" + "d" * 64,
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
    }


def proof_dir(tmp_path):
    root = tmp_path / "proofs"
    root.mkdir(parents=True)
    for name in load_module().CONTROL_NAMES:
        (root / f"{name}.json").write_bytes(f"proof:{name}\n".encode("ascii"))
    return root


def receipt(module, tmp_path):
    values = evidence(module)
    return module.build_receipt(
        values,
        expected_candidate=values["candidate"],
        evidence_dir=proof_dir(tmp_path),
    )


def test_builds_a_closed_canonical_receipt_bound_to_all_required_controls(tmp_path):
    module = load_module()
    values = evidence(module)
    proofs = proof_dir(tmp_path)
    value = module.build_receipt(values, expected_candidate=values["candidate"], evidence_dir=proofs)
    raw = module.canonical_bytes(value)
    assert module.verify_receipt(
        raw,
        expected_candidate=values["candidate"],
        evidence_dir=proofs,
    ) == []
    assert b"endpoint" not in raw and b"token" not in raw and b"credential" not in raw


@pytest.mark.parametrize("mutate, expected", [
    (lambda value: value["candidate"]["subjects"].update({"restricted-mattermost-ingress": "sha256:" + "0" * 64}), "candidate"),
    (lambda value: value["host"].update({"architecture": "arm64"}), "host"),
    (lambda value: value["controls"]["egress"].update({"metadata": "pass"}), "controls"),
    (lambda value: value["controls"].pop("replay"), "controls"),
    (lambda value: value["proofs"].pop("cleanup"), "proofs"),
    (lambda value: value["claims"].update({"phi_authorized": True}), "claims"),
    (lambda value: value.update({"raw_log": "forbidden"}), "fields"),
])
def test_rejects_subject_substitution_incomplete_matrix_claim_escalation_and_extra_fields(mutate, expected, tmp_path):
    module = load_module()
    source = evidence(module)
    value = receipt(module, tmp_path)
    mutate(value)
    assert module.verify_receipt(module.canonical_bytes(value), expected_candidate=source["candidate"], evidence_dir=tmp_path / "proofs") == [expected]


def test_builder_refuses_any_missing_or_noncanonical_control_evidence(tmp_path):
    module = load_module()
    values = evidence(module)
    values["controls"]["secrets"]["rotation"] = "deny"
    with pytest.raises(ValueError, match="controls"):
        module.build_receipt(values, expected_candidate=values["candidate"], evidence_dir=proof_dir(tmp_path))


def test_builder_refuses_a_self_reported_candidate_that_differs_from_the_external_frame(tmp_path):
    module = load_module()
    values = evidence(module)
    expected = deepcopy(values["candidate"])
    values["candidate"]["subjects"]["restricted-clinical-adapter"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="candidate"):
        module.build_receipt(values, expected_candidate=expected, evidence_dir=proof_dir(tmp_path))


def test_verifier_rejects_a_sidecar_altered_after_receipt_generation(tmp_path):
    module = load_module()
    values = evidence(module)
    proofs = proof_dir(tmp_path)
    value = module.build_receipt(values, expected_candidate=values["candidate"], evidence_dir=proofs)
    (proofs / "egress.json").write_bytes(b"altered")
    assert module.verify_receipt(module.canonical_bytes(value), expected_candidate=values["candidate"], evidence_dir=proofs) == ["proofs"]


def test_writer_does_not_replace_existing_receipt(tmp_path):
    module = load_module()
    output = tmp_path / "receipt.json"
    output.write_bytes(b"sentinel")
    with pytest.raises(FileExistsError):
        module.write_new(output, receipt(module, tmp_path))
    assert output.read_bytes() == b"sentinel"


def test_receipt_is_immutable_from_caller_mutation(tmp_path):
    module = load_module()
    values = evidence(module)
    value = receipt(module, tmp_path)
    value["controls"]["cleanup"]["green"] = "deny"
    next_proofs = proof_dir(tmp_path / "next")
    assert module.build_receipt(values, expected_candidate=values["candidate"], evidence_dir=next_proofs)["controls"]["cleanup"]["green"] == "pass"


def test_cli_builds_and_verifies_without_echoing_source_inputs(tmp_path, capsys):
    module = load_module()
    values = evidence(module)
    evidence_path = tmp_path / "evidence.json"
    candidate_path = tmp_path / "candidate.json"
    output = tmp_path / "receipt.json"
    proofs = proof_dir(tmp_path)
    evidence_path.write_text(json.dumps(values), encoding="utf-8")
    candidate_path.write_text(json.dumps(values["candidate"]), encoding="utf-8")

    assert module.main(["--evidence", str(evidence_path), "--candidate", str(candidate_path), "--proof-dir", str(proofs), "--output", str(output)]) == 0
    assert capsys.readouterr().out.startswith("p2-host-conformance: PASS receipt_sha256=")
    assert module.main(["--verify", str(output), "--candidate", str(candidate_path), "--proof-dir", str(proofs)]) == 0
    assert capsys.readouterr().out == "p2-host-conformance: PASS\n"


def test_cli_denies_invalid_input_without_echoing_its_contents(tmp_path, capsys):
    module = load_module()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text('{"secret":"must-not-echo"}', encoding="utf-8")
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(json.dumps(evidence(module)["candidate"]), encoding="utf-8")
    assert module.main(["--evidence", str(evidence_path), "--candidate", str(candidate_path), "--proof-dir", str(proof_dir(tmp_path)), "--output", str(tmp_path / "receipt.json")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "p2-host-conformance: DENIED class=input\n"


def test_candidate_frame_is_derived_from_the_exact_tag_clean_sources_and_published_manifest(tmp_path, monkeypatch):
    module = load_module()
    runtime = tmp_path / "runtime"
    hrh = tmp_path / "hrh"
    staging = runtime / "deploy" / "clinical-staging"
    staging.mkdir(parents=True)
    hrh.mkdir()
    (staging / "clinical_staging.py").write_text(
        f'REQUIRED_HRH_SHA = "{HRH_HEAD}"\nREQUIRED_HRH_TREE = "{HRH_TREE}"\n', encoding="utf-8"
    )
    manifest = {
        "schema_version": "restricted-runtime-immutable-candidate.v1",
        "source_revision": RUNTIME_HEAD,
        "platform": "linux/amd64",
        "subjects": [
            {"name": name, "digest": digest, "image": "ghcr.io/example/" + name + "@" + digest, "platform": "linux/amd64"}
            for name, digest in SUBJECTS.items()
        ],
    }
    manifest_path = tmp_path / "candidate.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def fake_git(path, *args):
        key = (Path(path).name, *args)
        values = {
            ("runtime", "rev-parse", "HEAD"): RUNTIME_HEAD,
            ("runtime", "rev-parse", "HEAD^{tree}"): RUNTIME_TREE,
            ("runtime", "rev-parse", f"refs/tags/{module.IMMUTABLE_TAG}^{{commit}}") : RUNTIME_HEAD,
            ("runtime", "status", "--porcelain"): "",
            ("hrh", "rev-parse", "HEAD"): HRH_HEAD,
            ("hrh", "rev-parse", "HEAD^{tree}"): HRH_TREE,
            ("hrh", "status", "--porcelain"): "",
        }
        return values[key]

    monkeypatch.setattr(module, "_git", fake_git)
    frame = module.candidate_from_manifest(runtime, hrh, manifest_path)
    assert frame["runtime_head"] == RUNTIME_HEAD
    assert frame["runtime_tree"] == RUNTIME_TREE
    assert frame["hrh_head"] == HRH_HEAD
    assert frame["subjects"] == SUBJECTS


@pytest.mark.parametrize("mutate", [
    lambda manifest: manifest.update(source_revision="0" * 40),
    lambda manifest: manifest["subjects"].pop(),
    lambda manifest: manifest["subjects"][0].update(digest="sha256:" + "0" * 64),
])
def test_candidate_frame_rejects_manifest_substitution(tmp_path, monkeypatch, mutate):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    staging = runtime / "deploy" / "clinical-staging"
    staging.mkdir(parents=True)
    hrh.mkdir()
    (staging / "clinical_staging.py").write_text(
        f'REQUIRED_HRH_SHA = "{HRH_HEAD}"\nREQUIRED_HRH_TREE = "{HRH_TREE}"\n', encoding="utf-8"
    )
    manifest = {"schema_version": "restricted-runtime-immutable-candidate.v1", "source_revision": RUNTIME_HEAD,
                "platform": "linux/amd64", "subjects": [{"name": name, "digest": digest, "image": "x@" + digest, "platform": "linux/amd64"} for name, digest in SUBJECTS.items()]}
    mutate(manifest)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(module, "_git", lambda path, *args: {
        ("runtime", "rev-parse", "HEAD"): RUNTIME_HEAD, ("runtime", "rev-parse", "HEAD^{tree}"): RUNTIME_TREE,
        ("runtime", "rev-parse", f"refs/tags/{module.IMMUTABLE_TAG}^{{commit}}") : RUNTIME_HEAD, ("runtime", "status", "--porcelain"): "",
        ("hrh", "rev-parse", "HEAD"): HRH_HEAD, ("hrh", "rev-parse", "HEAD^{tree}"): HRH_TREE, ("hrh", "status", "--porcelain"): "",
    }[(Path(path).name, *args)])
    with pytest.raises(ValueError, match="candidate"):
        module.candidate_from_manifest(runtime, hrh, path)


def test_cli_derives_a_safe_candidate_frame(tmp_path, monkeypatch, capsys):
    module = load_module()
    runtime, hrh = tmp_path / "runtime", tmp_path / "hrh"
    staging = runtime / "deploy" / "clinical-staging"
    staging.mkdir(parents=True)
    hrh.mkdir()
    (staging / "clinical_staging.py").write_text(f'REQUIRED_HRH_SHA = "{HRH_HEAD}"\nREQUIRED_HRH_TREE = "{HRH_TREE}"\n', encoding="utf-8")
    manifest = {"schema_version": "restricted-runtime-immutable-candidate.v1", "source_revision": RUNTIME_HEAD,
                "platform": "linux/amd64", "subjects": [{"name": name, "digest": digest, "image": "x@" + digest, "platform": "linux/amd64"} for name, digest in SUBJECTS.items()]}
    manifest_path, output = tmp_path / "manifest.json", tmp_path / "candidate.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(module, "_git", lambda path, *args: {
        ("runtime", "rev-parse", "HEAD"): RUNTIME_HEAD, ("runtime", "rev-parse", "HEAD^{tree}"): RUNTIME_TREE,
        ("runtime", "rev-parse", f"refs/tags/{module.IMMUTABLE_TAG}^{{commit}}") : RUNTIME_HEAD, ("runtime", "status", "--porcelain"): "",
        ("hrh", "rev-parse", "HEAD"): HRH_HEAD, ("hrh", "rev-parse", "HEAD^{tree}"): HRH_TREE, ("hrh", "status", "--porcelain"): "",
    }[(Path(path).name, *args)])
    assert module.main(["--derive-candidate", "--runtime-root", str(runtime), "--hrh-root", str(hrh), "--candidate-manifest", str(manifest_path), "--candidate-output", str(output)]) == 0
    assert capsys.readouterr().out.startswith("p2-host-conformance: CANDIDATE-FRAME sha256=")
    assert json.loads(output.read_text(encoding="utf-8"))["subjects"] == SUBJECTS
