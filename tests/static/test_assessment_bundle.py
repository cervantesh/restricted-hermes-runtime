"""Offline contract tests for the content-safe assessment bundle."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "tools" / "build_assessment_bundle.py"
VERIFY = ROOT / "tools" / "verify_assessment_bundle.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_builder():
    sys.path.insert(0, str(BUILD.parent))
    try:
        return _load(BUILD, "assessment_bundle_builder")
    finally:
        sys.path.pop(0)


def test_reparse_point_metadata_is_rejected_without_platform_privileges(tmp_path: Path):
    builder = _load_builder()
    assert builder._is_reparse_point(SimpleNamespace(st_file_attributes=0x0400))
    assert not builder._is_reparse_point(SimpleNamespace(st_file_attributes=0))


@pytest.mark.skipif(os.name != "nt", reason="NTFS junctions are Windows-only")
def test_windows_junction_is_detected_when_available(tmp_path: Path):
    builder = _load_builder()
    target = tmp_path / "target"; target.mkdir()
    junction = tmp_path / "junction"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True, text=True)
    if created.returncode != 0:
        pytest.skip("junction creation unavailable")
    assert builder._is_reparse_point(junction.lstat())


def _declaration() -> dict[str, object]:
    return {
        "profile": "restricted-clinical-candidate.v1",
        "sources": [
            {"name": "governance-contract", "revision": "9" * 40, "tree": "8" * 40},
            {"name": "health-record-hub-contract", "revision": "a" * 40, "tree": "b" * 40},
            {"name": "health-record-hub-publication", "revision": "b" * 40, "tree": "c" * 40},
            {"name": "restricted-edge", "revision": "c" * 40, "tree": "d" * 40},
            {"name": "restricted-runtime", "revision": "d" * 40, "tree": "e" * 40},
        ],
        "subjects": [
            {"name": "health-record-hub-migration", "status": "NOT_VERIFIED", "reason": "hrh-publication-missing"},
            {"name": "health-record-hub-web", "status": "NOT_VERIFIED", "reason": "hrh-publication-missing"},
            {"name": "restricted-clinical-adapter", "status": "PASS", "kind": "oci-image", "reference": "ghcr.io/example/clinical-adapter@sha256:" + "e" * 64},
            {"name": "restricted-mattermost-ingress", "status": "PASS", "kind": "oci-image", "reference": "ghcr.io/example/mattermost-ingress@sha256:" + "f" * 64},
        ],
        "producer": {"producer_id": "ci", "run_id": "run-17", "toolchain_id": "python-3.11", "host_id": "synthetic-linux"},
        "policy": {"epoch": "policy-7", "digest": "sha256:" + "1" * 64},
        "controls": [
            {"id": "bounded-inputs", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": ["evidence/bounded-inputs.json"]},
            {"id": "clinical-composition", "status": "NOT_VERIFIED", "dependencies": ["immutable-images"], "evidence_paths": ["contracts/clinical-composition.json", "evidence/clinical-receipt.json"]},
            {"id": "cold-recovery", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": ["evidence/cold-recovery.json"]},
            {"id": "governance-decision", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": ["governance/risk-map.json"]},
            {"id": "hrh-publication", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": ["evidence/hrh-publication.json"]},
            {"id": "immutable-application-subjects", "status": "NOT_VERIFIED", "dependencies": ["immutable-images"], "evidence_paths": ["subjects/images.json"]},
            {"id": "independent-review", "status": "NOT_VERIFIED", "dependencies": [], "evidence_paths": ["independent-review/findings.json"]},
            {"id": "representative-host", "status": "NOT_VERIFIED", "dependencies": ["representative-host-input"], "evidence_paths": ["evidence/representative-host.json"]},
        ],
        "dependencies": [
            {"id": "immutable-images", "status": "PASS"},
            {"id": "representative-host-input", "status": "NOT_VERIFIED"},
        ],
        "nonclaims": [
            "no PHI authorization", "no production approval", "not a compliance certification",
        ],
        "files": [
            "contracts/clinical-composition.json", "evidence/bounded-inputs.json", "evidence/clinical-receipt.json",
            "evidence/cold-recovery.json", "evidence/hrh-publication.json", "evidence/representative-host.json",
            "governance/risk-map.json", "independent-review/findings.json", "subjects/images.json",
        ],
    }


def _build(tmp_path: Path) -> Path:
    declaration_value = _declaration()
    source = tmp_path / "source"
    for relative in declaration_value["files"]:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_evidence(relative, declaration=declaration_value)), encoding="utf-8")
    declaration = tmp_path / "declaration.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    bundle = tmp_path / "assessment-bundle"
    result = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(bundle)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return bundle


HOST_OBSERVATIONS = (
    "backup-recovery", "dns", "effective-host-runtime", "ingress-ports", "ipv4", "ipv6",
    "logging-audit-sinks", "metadata-endpoints", "mounts", "patch-baseline",
    "principals-iam-denials", "proxy-env", "secret-mounts-rotation", "time-source", "trust-roots",
)


def _ready_declaration() -> dict[str, object]:
    value = _declaration()
    for index, subject in enumerate(value["subjects"]):
        if subject["status"] != "PASS":
            value["subjects"][index] = {
                "name": subject["name"],
                "status": "PASS",
                "kind": "oci-image",
                "reference": f"ghcr.io/example/{subject['name']}@sha256:" + str(index + 1) * 64,
            }
    for dependency in value["dependencies"]:
        dependency["status"] = "PASS"
    for control in value["controls"]:
        control["status"] = "PASS"
    return value


def _control(declaration: dict[str, object], identifier: str) -> dict[str, object]:
    return next(control for control in declaration["controls"] if control["id"] == identifier)


def _evidence(relative: str, *, outcome: str = "NOT_VERIFIED", declaration: dict[str, object] | None = None) -> dict[str, object]:
    declaration_value = declaration or _declaration()
    common = {
        "scope": "SYNTHETIC_NON_PHI_ONLY",
        "outcome": outcome,
        "sources": declaration_value["sources"],
        "subjects": declaration_value["subjects"],
        "producer": declaration_value["producer"],
        "policy": declaration_value["policy"],
    }
    if outcome == "NOT_VERIFIED":
        if relative == "evidence/representative-host.json":
            return {**common, "observations": [{"id": identifier, "outcome": "NOT_VERIFIED", "reason": "external-evidence-missing"} for identifier in HOST_OBSERVATIONS]}
        if relative == "subjects/images.json":
            return {**common, "reason": "external-evidence-missing", "edge_candidate_manifest_sha256": "sha256:" + "d" * 64}
        return {**common, "reason": "external-evidence-missing"}
    if outcome == "NOT_APPLICABLE":
        if relative == "subjects/images.json":
            return {**common, "rationale": "closed-profile-exception", "edge_candidate_manifest_sha256": "sha256:" + "d" * 64}
        return {**common, "rationale": "closed-profile-exception"}
    if outcome not in {"PASS", "FAIL"}:
        raise AssertionError(outcome)
    if relative == "contracts/clinical-composition.json": return {**common, "claim_id": "synthetic-clinical-composition"}
    if relative == "evidence/clinical-receipt.json": return {**common, "negative_controls": ["no-general-hermes"]}
    if relative == "evidence/cold-recovery.json": return {**common, "manifest_sha256": "sha256:" + "a" * 64, "recovery_receipt_sha256": "sha256:" + "b" * 64}
    if relative == "evidence/bounded-inputs.json": return {**common, "inputs": [
        {"id": "delivery-reauthorization-pr18", "source_revision": "1" * 40, "source_tree": "2" * 40, "evidence_artifact_sha256": "sha256:" + "3" * 64, "hosted_ci": {"run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34104221878", "head_sha": "1" * 40, "receipt_sha256": "sha256:" + "a" * 64, "conclusion": "PASS"}, "classification": "bounded-delivery-reauthorization"},
        {"id": "representative-container-egress-pr19", "source_revision": "4" * 40, "source_tree": "5" * 40, "evidence_artifact_sha256": "sha256:" + "6" * 64, "hosted_ci": {"run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34109706405", "head_sha": "4" * 40, "receipt_sha256": "sha256:" + "b" * 64, "conclusion": "PASS"}, "classification": "bounded-synthetic-container"},
        {"id": "secret-boundary-pr15", "source_revision": "7" * 40, "source_tree": "8" * 40, "evidence_artifact_sha256": "sha256:" + "9" * 64, "hosted_ci": {"run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/34101476120", "head_sha": "7" * 40, "receipt_sha256": "sha256:" + "c" * 64, "conclusion": "PASS"}, "classification": "bounded-secret-boundary"},
    ]}
    if relative == "evidence/hrh-publication.json": return {**common, "publication_receipt_sha256": "sha256:" + "b" * 64, "verification_receipt_sha256": "sha256:" + "c" * 64}
    if relative == "evidence/representative-host.json": return {**common, "observations": [{"id": identifier, "outcome": outcome, "witness_sha256": "sha256:" + "a" * 64} for identifier in HOST_OBSERVATIONS]}
    if relative == "governance/risk-map.json": return {**common, "risk_owner": "technical-owner", "risks": [{"id": "synthetic-scope", "severity": "P2", "disposition": "CLOSED"}]}
    if relative == "independent-review/findings.json": return {**common, "reviewer_id": "external-reviewer", "authority": "independent-technical-review", "conflict_statement": "none-declared", "findings": ["external-inputs-missing"], "technical_go_no_go": "GO" if outcome == "PASS" else "NO_GO"}
    if relative == "subjects/images.json": return {**common, "edge_candidate_manifest_sha256": "sha256:" + "d" * 64}
    raise AssertionError(relative)


def _write_evidence(source: Path, declaration: dict[str, object], outcomes: dict[str, str] | None = None) -> None:
    for relative in declaration["files"]:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_evidence(relative, outcome=(outcomes or {}).get(relative, "NOT_VERIFIED"), declaration=declaration)), encoding="utf-8")


def _expected(bundle: Path) -> str:
    return hashlib.sha256((bundle / "assessment.manifest.json").read_bytes()).hexdigest()


def test_synthetic_bundle_is_clean_room_verifiable_and_not_ready(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_verifier")
    bundle = _build(tmp_path)
    result = verifier.verify(bundle, expected_manifest_sha256=_expected(bundle))
    assert result.errors == []
    assert result.ready_for_technical_go is False
    assert result.statuses["bounded-inputs"] == "NOT_VERIFIED"
    assert result.statuses["representative-host"] == "NOT_VERIFIED"
    manifest = json.loads((bundle / "assessment.manifest.json").read_text(encoding="utf-8"))
    payload = dict(manifest)
    candidate_id = payload.pop("candidate_id")
    assert candidate_id == "sha256:" + hashlib.sha256(verifier.canonical_json(payload)).hexdigest()
    assert (bundle / "verify_assessment_bundle.py").is_file()
    clean_room = subprocess.run([sys.executable, str(bundle / "verify_assessment_bundle.py"), str(bundle), "--expected-manifest-sha256", _expected(bundle)], capture_output=True, text=True)
    assert clean_room.returncode == 0 and "NOT_READY" in clean_room.stdout


def test_verifier_fails_closed_for_extra_changed_symlinked_reordered_and_bad_status_content(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_verifier_mutations")
    bundle = _build(tmp_path)
    expected = _expected(bundle)
    (bundle / "evidence" / "extra.json").write_text("{}", encoding="utf-8")
    assert any("unexpected" in error for error in verifier.verify(bundle, expected_manifest_sha256=expected).errors)
    (bundle / "evidence" / "extra.json").unlink()
    receipt = bundle / "evidence" / "clinical-receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    assert any("hash" in error for error in verifier.verify(bundle, expected_manifest_sha256=expected).errors)
    bundle = _build(tmp_path / "missing")
    expected = _expected(bundle)
    (bundle / "governance" / "risk-map.json").unlink()
    assert any("missing or unexpected" in error for error in verifier.verify(bundle, expected_manifest_sha256=expected).errors)
    bundle = _build(tmp_path / "symlink")
    expected = _expected(bundle)
    target = bundle / "subjects" / "images.json"
    replacement = bundle / "subjects" / "replacement.json"
    replacement.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(replacement)
    except OSError:
        return
    assert any("symlink" in error for error in verifier.verify(bundle, expected_manifest_sha256=expected).errors)
    bundle = _build(tmp_path / "reordered")
    expected = _expected(bundle)
    manifest_path = bundle / "assessment.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sources"].reverse()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    assert any("canonical" in error for error in verifier.verify(bundle, expected_manifest_sha256=expected).errors)


def test_export_rejects_canary_traversal_and_external_acceptance_without_authority(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    for relative in _declaration()["files"]:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_evidence(relative)), encoding="utf-8")
    (source / "evidence" / "clinical-receipt.json").write_text('{"password": "PASSWORD_SECRET_CANARY_9159"}', encoding="utf-8")
    declaration = tmp_path / "declaration.json"; declaration.write_text(json.dumps(_declaration()), encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "bundle")], capture_output=True, text=True)
    assert rejected.returncode != 0 and "secret-bearing" in rejected.stderr
    bad = _declaration(); bad["controls"][bad["controls"].index(_control(bad, "independent-review"))] = {"id": "independent-review", "status": "EXTERNALLY_ACCEPTED", "dependencies": [], "evidence_paths": ["independent-review/findings.json"]}
    declaration.write_text(json.dumps(bad), encoding="utf-8")
    (source / "evidence" / "clinical-receipt.json").write_text(json.dumps(_evidence("evidence/clinical-receipt.json")), encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "bundle")], capture_output=True, text=True)
    assert rejected.returncode != 0 and "acceptance" in rejected.stderr
    traversal = _declaration(); traversal["files"].append("evidence/../secrets.json")
    declaration.write_text(json.dumps(traversal), encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "traversal")], capture_output=True, text=True)
    assert rejected.returncode != 0 and "allowlist" in rejected.stderr


def test_external_acceptance_is_a_retained_risk_decision_not_a_technical_pass(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_acceptance")
    declaration_value = _ready_declaration()
    declaration_value["controls"][declaration_value["controls"].index(_control(declaration_value, "independent-review"))] = {
        "id": "independent-review", "status": "EXTERNALLY_ACCEPTED", "dependencies": [], "evidence_paths": ["independent-review/findings.json"],
        "acceptance": {"owner": "risk-owner", "authority": "technical-risk-board", "evidence_path": "governance/risk-map.json", "technical_status": "NOT_VERIFIED"},
    }
    source = tmp_path / "source"
    outcomes = {relative: "PASS" for relative in declaration_value["files"]}
    outcomes["independent-review/findings.json"] = "NOT_VERIFIED"
    _write_evidence(source, declaration_value, outcomes)
    declaration = tmp_path / "declaration.json"; declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    bundle = tmp_path / "bundle"
    result = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(bundle)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    verified = verifier.verify(bundle, expected_manifest_sha256=_expected(bundle))
    assert verified.errors == []
    assert verified.statuses["independent-review"] == "EXTERNALLY_ACCEPTED"
    assert verified.ready_for_technical_go is False

    (source / "independent-review" / "findings.json").write_text(
        json.dumps(_evidence("independent-review/findings.json", outcome="PASS", declaration=declaration_value)),
        encoding="utf-8",
    )
    pass_as_accepted = subprocess.run(
        [sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "pass-as-accepted")],
        capture_output=True,
        text=True,
    )
    assert pass_as_accepted.returncode != 0


def test_truthful_not_ready_records_are_individually_closed_and_mixed_shapes_are_rejected(tmp_path: Path):
    source = tmp_path / "source"
    declaration_value = _declaration()
    _write_evidence(source, declaration_value)

    def export(name: str) -> subprocess.CompletedProcess[str]:
        declaration = tmp_path / f"{name}.json"
        declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)

    assert export("truthful-not-ready").returncode == 0

    receipt_path = source / "evidence" / "clinical-receipt.json"
    receipt = _evidence("evidence/clinical-receipt.json", declaration=declaration_value)
    receipt["negative_controls"] = ["proof-field-forbidden-while-unverified"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    assert export("unverified-with-proof").returncode != 0

    receipt_path.write_text(json.dumps(_evidence("evidence/clinical-receipt.json", outcome="PASS", declaration=declaration_value)), encoding="utf-8")
    (source / "contracts" / "clinical-composition.json").write_text(json.dumps(_evidence("contracts/clinical-composition.json", outcome="PASS", declaration=declaration_value)), encoding="utf-8")
    assert export("unverified-control-with-pass-evidence").returncode != 0

    receipt_path.write_text(json.dumps(_evidence("evidence/clinical-receipt.json", declaration=declaration_value)), encoding="utf-8")
    (source / "contracts" / "clinical-composition.json").write_text(json.dumps(_evidence("contracts/clinical-composition.json", declaration=declaration_value)), encoding="utf-8")
    host_path = source / "evidence" / "representative-host.json"
    host = _evidence("evidence/representative-host.json", declaration=declaration_value)
    host["observations"][0] = {"id": HOST_OBSERVATIONS[0], "outcome": "NOT_VERIFIED", "witness_sha256": "sha256:" + "a" * 64}
    host_path.write_text(json.dumps(host), encoding="utf-8")
    assert export("unverified-host-with-proof").returncode != 0


def test_pass_and_fail_require_complete_proof_shapes_and_no_go_cannot_be_ready(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_pass_fail_shapes")
    declaration_value = _ready_declaration()
    _control(declaration_value, "independent-review")["status"] = "FAIL"
    source = tmp_path / "source"
    outcomes = {relative: "PASS" for relative in declaration_value["files"]}
    outcomes["independent-review/findings.json"] = "FAIL"
    _write_evidence(source, declaration_value, outcomes)
    declaration = tmp_path / "no-go.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    bundle = tmp_path / "no-go"
    built = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(bundle)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    checked = verifier.verify(bundle, expected_manifest_sha256=_expected(bundle))
    assert checked.errors == []
    assert checked.ready_for_technical_go is False

    false_pass_review = _evidence("independent-review/findings.json", outcome="PASS", declaration=declaration_value)
    false_pass_review["technical_go_no_go"] = "NO_GO"
    (source / "independent-review" / "findings.json").write_text(json.dumps(false_pass_review), encoding="utf-8")
    false_pass_declaration = _ready_declaration()
    false_pass_path = tmp_path / "false-pass-no-go.json"
    false_pass_path.write_text(json.dumps(false_pass_declaration), encoding="utf-8")
    assert subprocess.run([sys.executable, str(BUILD), "--declaration", str(false_pass_path), "--input-dir", str(source), "--output-dir", str(tmp_path / "false-pass-no-go")], capture_output=True, text=True).returncode != 0

    (source / "independent-review" / "findings.json").write_text(json.dumps(_evidence("independent-review/findings.json", outcome="FAIL", declaration=declaration_value)), encoding="utf-8")

    incomplete = _evidence("evidence/cold-recovery.json", outcome="PASS", declaration=declaration_value)
    incomplete.pop("manifest_sha256")
    (source / "evidence" / "cold-recovery.json").write_text(json.dumps(incomplete), encoding="utf-8")
    assert subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "missing-pass-proof")], capture_output=True, text=True).returncode != 0

    (source / "evidence" / "cold-recovery.json").write_text(json.dumps(_evidence("evidence/cold-recovery.json", outcome="PASS", declaration=declaration_value)), encoding="utf-8")
    host = _evidence("evidence/representative-host.json", outcome="PASS", declaration=declaration_value)
    host["observations"][0].pop("witness_sha256")
    (source / "evidence" / "representative-host.json").write_text(json.dumps(host), encoding="utf-8")
    assert subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "missing-host-witness")], capture_output=True, text=True).returncode != 0


def test_cold_recovery_requires_independent_manifest_and_recovery_receipt_bindings(tmp_path: Path):
    declaration_value = _ready_declaration()
    source = tmp_path / "source"
    _write_evidence(source, declaration_value, {relative: "PASS" for relative in declaration_value["files"]})
    declaration = tmp_path / "ready.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")

    def export(record: dict[str, object], name: str) -> subprocess.CompletedProcess[str]:
        (source / "evidence" / "cold-recovery.json").write_text(json.dumps(record), encoding="utf-8")
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)

    complete = _evidence("evidence/cold-recovery.json", outcome="PASS", declaration=declaration_value)
    assert export(complete, "complete-cold-proof").returncode == 0

    for field in ("manifest_sha256", "recovery_receipt_sha256"):
        diagnostic = "immutable manifest sha256" if field == "manifest_sha256" else "recovery receipt sha256"
        missing = dict(complete)
        missing.pop(field)
        missing_result = export(missing, f"missing-{field}")
        assert missing_result.returncode != 0 and diagnostic in missing_result.stderr

        malformed = dict(complete)
        malformed[field] = "sha256:not-a-binding"
        malformed_result = export(malformed, f"malformed-{field}")
        assert malformed_result.returncode != 0 and diagnostic in malformed_result.stderr

    manifest_only = dict(complete)
    manifest_only.pop("recovery_receipt_sha256")
    manifest_only_result = export(manifest_only, "manifest-only-cannot-ready")
    assert manifest_only_result.returncode != 0 and "recovery receipt sha256" in manifest_only_result.stderr


def test_profile_dependency_inventory_mapping_and_not_applicable_cannot_waive_readiness(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_dependencies")
    source = tmp_path / "source"
    declaration_value = _declaration()
    _write_evidence(source, declaration_value)

    def export(value: dict[str, object], name: str) -> subprocess.CompletedProcess[str]:
        declaration = tmp_path / f"{name}.json"
        declaration.write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)

    replacement = _declaration()
    replacement["dependencies"][1]["id"] = "replacement-host-input"
    assert export(replacement, "replacement-dependency").returncode != 0

    wrong_governance_source = _declaration()
    wrong_governance_source["sources"][0]["name"] = "replacement-governance-contract"
    wrong_source_result = export(wrong_governance_source, "replacement-governance-source")
    assert wrong_source_result.returncode != 0 and "source inventory" in wrong_source_result.stderr

    empty = _declaration()
    empty["dependencies"] = []
    assert export(empty, "empty-dependencies").returncode != 0

    wrong_gate_mapping = _declaration()
    _control(wrong_gate_mapping, "clinical-composition")["dependencies"] = []
    assert export(wrong_gate_mapping, "wrong-gate-dependency").returncode != 0

    ready = _ready_declaration()
    _write_evidence(source, ready, {relative: "PASS" for relative in ready["files"]})
    ready_build = export(ready, "all-pass")
    assert ready_build.returncode == 0, ready_build.stderr
    ready_bundle = tmp_path / "all-pass"
    ready_result = verifier.verify(ready_bundle, expected_manifest_sha256=_expected(ready_bundle))
    assert ready_result.errors == [] and ready_result.ready_for_technical_go is True

    waived = _ready_declaration()
    waived["dependencies"][1] = {"id": "representative-host-input", "status": "NOT_APPLICABLE", "rationale": "host-input-waived"}
    built = export(waived, "not-applicable-dependency")
    assert built.returncode == 0, built.stderr
    bundle = tmp_path / "not-applicable-dependency"
    checked = verifier.verify(bundle, expected_manifest_sha256=_expected(bundle))
    assert checked.errors == []
    assert checked.ready_for_technical_go is False


def test_hrh_publication_proof_binds_both_external_receipts(tmp_path: Path):
    # These hashes bind the two external artifacts; an offline bundle verifier
    # does not claim that either artifact exists in a registry.
    declaration_value = _ready_declaration()
    source = tmp_path / "source"
    _write_evidence(source, declaration_value, {relative: "PASS" for relative in declaration_value["files"]})
    declaration = tmp_path / "ready.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")

    complete = tmp_path / "complete-publication-proof"
    complete_result = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(complete)], capture_output=True, text=True)
    assert complete_result.returncode == 0, complete_result.stderr

    publication_path = source / "evidence" / "hrh-publication.json"
    incomplete = _evidence("evidence/hrh-publication.json", outcome="PASS", declaration=declaration_value)
    incomplete.pop("verification_receipt_sha256")
    publication_path.write_text(json.dumps(incomplete), encoding="utf-8")
    missing = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "missing-publication-proof")], capture_output=True, text=True)
    assert missing.returncode != 0

    malformed = _evidence("evidence/hrh-publication.json", outcome="PASS", declaration=declaration_value)
    malformed["publication_receipt_sha256"] = "sha256:not-a-content-binding"
    publication_path.write_text(json.dumps(malformed), encoding="utf-8")
    invalid = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "invalid-publication-proof")], capture_output=True, text=True)
    assert invalid.returncode != 0


def test_edge_manifest_availability_binding_is_closed_and_changes_the_candidate(tmp_path: Path):
    declaration_value = _declaration()
    source = tmp_path / "source"
    _write_evidence(source, declaration_value)
    declaration = tmp_path / "declaration.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")

    def export(name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)

    first = export("edge-binding-first")
    assert first.returncode == 0, first.stderr
    first_manifest = json.loads((tmp_path / "edge-binding-first" / "assessment.manifest.json").read_text(encoding="utf-8"))

    images_path = source / "subjects" / "images.json"
    changed = _evidence("subjects/images.json", declaration=declaration_value)
    changed["edge_candidate_manifest_sha256"] = "sha256:" + "e" * 64
    images_path.write_text(json.dumps(changed), encoding="utf-8")
    second = export("edge-binding-second")
    assert second.returncode == 0, second.stderr
    second_manifest = json.loads((tmp_path / "edge-binding-second" / "assessment.manifest.json").read_text(encoding="utf-8"))
    assert first_manifest["candidate_id"] != second_manifest["candidate_id"]

    for value in (None, "sha256:not-a-binding"):
        invalid = _evidence("subjects/images.json", declaration=declaration_value)
        if value is None:
            invalid.pop("edge_candidate_manifest_sha256")
        else:
            invalid["edge_candidate_manifest_sha256"] = value
        images_path.write_text(json.dumps(invalid), encoding="utf-8")
        rejected = export("edge-binding-" + ("missing" if value is None else "malformed"))
        assert rejected.returncode != 0

    pass_declaration = _ready_declaration()
    pass_source = tmp_path / "pass-source"
    _write_evidence(pass_source, pass_declaration, {relative: "PASS" for relative in pass_declaration["files"]})
    pass_images = _evidence("subjects/images.json", outcome="PASS", declaration=pass_declaration)
    pass_images.pop("edge_candidate_manifest_sha256")
    (pass_source / "subjects" / "images.json").write_text(json.dumps(pass_images), encoding="utf-8")
    pass_declaration_path = tmp_path / "pass-declaration.json"
    pass_declaration_path.write_text(json.dumps(pass_declaration), encoding="utf-8")
    missing_pass_binding = subprocess.run([sys.executable, str(BUILD), "--declaration", str(pass_declaration_path), "--input-dir", str(pass_source), "--output-dir", str(tmp_path / "missing-pass-edge-binding")], capture_output=True, text=True)
    assert missing_pass_binding.returncode != 0 and "edge candidate manifest sha256" in missing_pass_binding.stderr


def test_bounded_inputs_gate_closes_inventory_shape_and_classification(tmp_path: Path):
    declaration_value = _ready_declaration()
    source = tmp_path / "source"
    _write_evidence(source, declaration_value, {relative: "PASS" for relative in declaration_value["files"]})
    declaration = tmp_path / "ready.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    bounded_path = source / "evidence" / "bounded-inputs.json"
    complete = _evidence("evidence/bounded-inputs.json", outcome="PASS", declaration=declaration_value)

    def export(record: dict[str, object], name: str) -> subprocess.CompletedProcess[str]:
        bounded_path.write_text(json.dumps(record), encoding="utf-8")
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)

    complete_result = export(complete, "bounded-complete")
    assert complete_result.returncode == 0, complete_result.stderr

    missing = json.loads(json.dumps(complete))
    missing["inputs"].pop()
    assert export(missing, "bounded-missing").returncode != 0

    extra = json.loads(json.dumps(complete))
    extra["inputs"].append({"id": "extra-input", "source_revision": "a" * 40, "source_tree": "b" * 40, "evidence_artifact_sha256": "sha256:" + "c" * 64, "hosted_ci": {"run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1", "head_sha": "a" * 40, "receipt_sha256": "sha256:" + "d" * 64, "conclusion": "PASS"}, "classification": "bounded-secret-boundary"})
    assert export(extra, "bounded-extra").returncode != 0

    malformed = json.loads(json.dumps(complete))
    malformed["inputs"][0]["evidence_artifact_sha256"] = "not-a-hash"
    assert export(malformed, "bounded-malformed").returncode != 0

    misclassified = json.loads(json.dumps(complete))
    misclassified["inputs"][1]["classification"] = "representative-host"
    assert export(misclassified, "bounded-misclassified").returncode != 0

    hosted_mutations = {
        "missing-hosted-ci": lambda item: item.pop("hosted_ci"),
        "malformed-hosted-ci": lambda item: item.update(hosted_ci="run-34104221878"),
        "fabricated-run-id": lambda item: item["hosted_ci"].update(run_url="https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/99999999999"),
        "wrong-run-repo": lambda item: item["hosted_ci"].update(run_url="https://github.com/other/repository/actions/runs/34104221878"),
        "wrong-run-path": lambda item: item["hosted_ci"].update(run_url="https://github.com/cervantesh/restricted-hermes-runtime/runs/34104221878"),
        "mismatched-head": lambda item: item["hosted_ci"].update(head_sha="f" * 40),
        "non-pass-conclusion": lambda item: item["hosted_ci"].update(conclusion="SUCCESS"),
        "missing-ci-receipt": lambda item: item["hosted_ci"].pop("receipt_sha256"),
    }
    for name, mutate in hosted_mutations.items():
        candidate = json.loads(json.dumps(complete))
        mutate(candidate["inputs"][0])
        result = export(candidate, "bounded-" + name)
        assert result.returncode != 0


def test_partial_host_and_multifile_control_evidence_follow_the_closed_lattice(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_partial_evidence")
    declaration_value = _declaration()
    source = tmp_path / "source"
    _write_evidence(source, declaration_value)
    host_path = source / "evidence" / "representative-host.json"
    host = _evidence("evidence/representative-host.json", declaration=declaration_value)
    host["observations"][0] = {"id": HOST_OBSERVATIONS[0], "outcome": "PASS", "witness_sha256": "sha256:" + "a" * 64}
    host["observations"][1] = {"id": HOST_OBSERVATIONS[1], "outcome": "NOT_APPLICABLE", "rationale": "not-applicable-on-host"}
    host_path.write_text(json.dumps(host), encoding="utf-8")
    (source / "contracts" / "clinical-composition.json").write_text(json.dumps(_evidence("contracts/clinical-composition.json", outcome="PASS", declaration=declaration_value)), encoding="utf-8")
    declaration = tmp_path / "partial.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    bundle = tmp_path / "partial"
    built = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(bundle)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    checked = verifier.verify(bundle, expected_manifest_sha256=_expected(bundle))
    assert checked.errors == [] and checked.ready_for_technical_go is False
    retained = json.loads((bundle / "evidence" / "representative-host.json").read_text(encoding="utf-8"))
    assert retained["observations"][0]["witness_sha256"] == "sha256:" + "a" * 64
    assert retained["observations"][1]["rationale"] == "not-applicable-on-host"

    pass_control = _declaration()
    _control(pass_control, "clinical-composition")["status"] = "PASS"
    pass_declaration = tmp_path / "pass-control.json"
    pass_declaration.write_text(json.dumps(pass_control), encoding="utf-8")
    inconsistent_control = subprocess.run([sys.executable, str(BUILD), "--declaration", str(pass_declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "pass-with-unverified-sibling")], capture_output=True, text=True)
    assert inconsistent_control.returncode != 0

    inconsistent_host = dict(host)
    inconsistent_host["observations"] = list(host["observations"])
    inconsistent_host["observations"][2] = {"id": HOST_OBSERVATIONS[2], "outcome": "FAIL", "witness_sha256": "sha256:" + "d" * 64}
    host_path.write_text(json.dumps(inconsistent_host), encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "inconsistent-host")], capture_output=True, text=True)
    assert rejected.returncode != 0

    host_path.write_text(json.dumps(host), encoding="utf-8")
    failed_control = _declaration()
    _control(failed_control, "clinical-composition")["status"] = "FAIL"
    failed_declaration = tmp_path / "failed-control.json"
    failed_declaration.write_text(json.dumps(failed_control), encoding="utf-8")
    (source / "evidence" / "clinical-receipt.json").write_text(json.dumps(_evidence("evidence/clinical-receipt.json", outcome="FAIL", declaration=failed_control)), encoding="utf-8")
    (source / "contracts" / "clinical-composition.json").write_text(json.dumps(_evidence("contracts/clinical-composition.json", declaration=failed_control)), encoding="utf-8")
    rejected = subprocess.run([sys.executable, str(BUILD), "--declaration", str(failed_declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "failed-with-unverified-sibling")], capture_output=True, text=True)
    assert rejected.returncode == 0, rejected.stderr


def test_pass_aggregate_retains_not_applicable_host_and_multifile_evidence(tmp_path: Path):
    declaration_value = _declaration()
    _control(declaration_value, "clinical-composition")["status"] = "PASS"
    _control(declaration_value, "representative-host")["status"] = "PASS"
    source = tmp_path / "source"
    _write_evidence(source, declaration_value)

    (source / "contracts" / "clinical-composition.json").write_text(
        json.dumps(_evidence("contracts/clinical-composition.json", outcome="PASS", declaration=declaration_value)),
        encoding="utf-8",
    )
    (source / "evidence" / "clinical-receipt.json").write_text(
        json.dumps(_evidence("evidence/clinical-receipt.json", outcome="NOT_APPLICABLE", declaration=declaration_value)),
        encoding="utf-8",
    )
    host = _evidence("evidence/representative-host.json", outcome="PASS", declaration=declaration_value)
    host["observations"][0] = {
        "id": HOST_OBSERVATIONS[0],
        "outcome": "NOT_APPLICABLE",
        "rationale": "not-applicable-on-host",
    }
    (source / "evidence" / "representative-host.json").write_text(json.dumps(host), encoding="utf-8")

    declaration = tmp_path / "pass-with-not-applicable.json"
    declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    built = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "pass-with-not-applicable")], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr


def test_profile_rejects_a_dummy_or_incomplete_candidate_from_ready(tmp_path: Path):
    declaration_value = _declaration()
    declaration_value.pop("profile")
    declaration_value["sources"] = declaration_value["sources"][:1]
    declaration_value["subjects"] = declaration_value["subjects"][:1]
    declaration_value["controls"] = [{"id": "clinical-composition", "status": "PASS", "dependencies": []}]
    declaration_value["dependencies"] = []
    source = tmp_path / "source"
    for relative in declaration_value["files"]:
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(_evidence(relative)), encoding="utf-8")
    declaration = tmp_path / "declaration.json"; declaration.write_text(json.dumps(declaration_value), encoding="utf-8")
    result = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "bundle")], capture_output=True, text=True)
    assert result.returncode != 0 and "profile" in result.stderr
    incomplete = _declaration()
    incomplete["sources"] = incomplete["sources"][:1]
    incomplete["subjects"] = incomplete["subjects"][:1]
    incomplete["controls"] = [{"id": "clinical-composition", "status": "PASS", "dependencies": [], "evidence_paths": ["contracts/clinical-composition.json", "evidence/clinical-receipt.json"]}]
    declaration.write_text(json.dumps(incomplete), encoding="utf-8")
    result = subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(source), "--output-dir", str(tmp_path / "incomplete")], capture_output=True, text=True)
    assert result.returncode != 0 and "inventory" in result.stderr


def test_profile_rejects_ready_bypasses_for_collisions_opaque_evidence_subjects_phi_and_manifest_size(tmp_path: Path):
    verifier = _load(VERIFY, "assessment_bundle_profile_bypasses")
    source = tmp_path / "source"
    for relative in _declaration()["files"]:
        path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(_evidence(relative)), encoding="utf-8")
    def export(value: dict[str, object], name: str, input_dir: Path = source) -> subprocess.CompletedProcess[str]:
        declaration = tmp_path / f"{name}.json"; declaration.write_text(json.dumps(value), encoding="utf-8")
        return subprocess.run([sys.executable, str(BUILD), "--declaration", str(declaration), "--input-dir", str(input_dir), "--output-dir", str(tmp_path / name)], capture_output=True, text=True)
    collision = _declaration()
    collision["dependencies"].append({"id": "clinical-composition", "status": "NOT_VERIFIED"})
    assert export(collision, "collision").returncode != 0
    source_subject = _declaration(); source_subject["subjects"][0] = {"name": "health-record-hub-migration", "kind": "source", "reference": ""}
    assert export(source_subject, "source-subject").returncode != 0
    all_pass = _declaration()
    for dependency in all_pass["dependencies"]: dependency["status"] = "PASS"
    for control in all_pass["controls"]: control["status"] = "PASS"
    assert export(all_pass, "pass-status-with-unverified-evidence").returncode != 0
    (source / "evidence" / "clinical-receipt.json").write_text("{}", encoding="utf-8")
    assert export(_declaration(), "opaque").returncode != 0
    (source / "evidence" / "clinical-receipt.json").write_text(json.dumps(_evidence("evidence/clinical-receipt.json")), encoding="utf-8")
    (source / "evidence" / "representative-host.json").write_text('{"patient_id": "PHI_CANARY_9159"}', encoding="utf-8")
    assert export(_declaration(), "phi").returncode != 0
    (source / "evidence" / "representative-host.json").write_text(json.dumps(_evidence("evidence/representative-host.json")), encoding="utf-8")
    extra_phi = _evidence("evidence/clinical-receipt.json"); extra_phi["patient_name"] = "synthetic"
    (source / "evidence" / "clinical-receipt.json").write_text(json.dumps(extra_phi), encoding="utf-8")
    assert export(_declaration(), "extra-phi").returncode != 0
    (source / "evidence" / "clinical-receipt.json").write_text(json.dumps(_evidence("evidence/clinical-receipt.json")), encoding="utf-8")
    invalid_recovery_declaration = _declaration()
    _control(invalid_recovery_declaration, "cold-recovery")["status"] = "PASS"
    invalid_recovery = _evidence("evidence/cold-recovery.json", outcome="PASS", declaration=invalid_recovery_declaration)
    invalid_recovery["manifest_sha256"] = "not-a-hash"
    (source / "evidence" / "cold-recovery.json").write_text(json.dumps(invalid_recovery), encoding="utf-8")
    invalid_recovery_result = export(invalid_recovery_declaration, "invalid-recovery")
    assert invalid_recovery_result.returncode != 0 and "immutable manifest sha256" in invalid_recovery_result.stderr
    (source / "evidence" / "cold-recovery.json").write_text(json.dumps(_evidence("evidence/cold-recovery.json")), encoding="utf-8")
    oversized = _declaration(); oversized["producer"]["host_id"] = "x" * 1_048_577
    assert export(oversized, "oversized").returncode != 0
    raw_log = _declaration(); raw_log["files"].append("evidence/raw-log.json")
    (source / "evidence" / "raw-log.json").write_text(json.dumps(_evidence("evidence/clinical-receipt.json")), encoding="utf-8")
    assert export(raw_log, "raw-log").returncode != 0
    bad_oci = _declaration()
    bad_oci["subjects"][0] = {"name": "health-record-hub-migration", "status": "PASS", "kind": "oci-image", "reference": "@sha256:" + "a" * 64}
    bad_oci_source = tmp_path / "bad-oci-source"
    _write_evidence(bad_oci_source, bad_oci)
    bad_oci_result = export(bad_oci, "bad-oci", bad_oci_source)
    assert bad_oci_result.returncode != 0 and "OCI subject must be immutable by digest" in bad_oci_result.stderr
    bad_host = _evidence("evidence/representative-host.json"); bad_host["observations"] = []
    (source / "evidence" / "representative-host.json").write_text(json.dumps(bad_host), encoding="utf-8")
    assert export(_declaration(), "bad-host").returncode != 0
    failed_host_declaration = _declaration()
    _control(failed_host_declaration, "representative-host")["status"] = "FAIL"
    failed_host = _evidence("evidence/representative-host.json", outcome="FAIL", declaration=failed_host_declaration)
    failed_host["observations"][0]["witness_sha256"] = "not-a-hash"
    (source / "evidence" / "representative-host.json").write_text(json.dumps(failed_host), encoding="utf-8")
    failed_host_result = export(failed_host_declaration, "failed-host-observation")
    assert failed_host_result.returncode != 0 and "conditional observation shapes" in failed_host_result.stderr
    outside = tmp_path / "outside-evidence"; shutil.copytree(source / "evidence", outside)
    shutil.rmtree(source / "evidence")
    try:
        (source / "evidence").symlink_to(outside, target_is_directory=True)
    except OSError:
        return
    assert export(_declaration(), "parent-symlink").returncode != 0
