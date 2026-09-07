"""v2 review findings bind the exact immutable pre-review input, not themselves."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROFILE = "restricted-clinical-candidate.v2"
PREVIEW = "independent-review/prereview.manifest.json"
REVIEW = "independent-review/findings.json"
SPEC = importlib.util.spec_from_file_location("assessment_v1_fixtures", Path(__file__).with_name("test_assessment_bundle.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _build(directory, declaration, source):
    declaration_path = directory / "declaration.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")
    bundle = directory / "bundle"
    result = subprocess.run([sys.executable, str(FIXTURE.BUILD), "--declaration", str(declaration_path),
        "--input-dir", str(source), "--output-dir", str(bundle)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return bundle


def _pre_review(tmp_path):
    declaration = FIXTURE._ready_declaration()
    declaration["profile"] = PROFILE
    FIXTURE._control(declaration, "independent-review")["status"] = "NOT_VERIFIED"
    source = tmp_path / "input"
    outcomes = {name: "PASS" for name in declaration["files"]}
    outcomes[REVIEW] = "NOT_VERIFIED"
    FIXTURE._write_evidence(source, declaration, outcomes)
    return _build(tmp_path, declaration, source), declaration, source


def _final(tmp_path, outcome="PASS"):
    pre_root = tmp_path / "pre"
    pre_root.mkdir()
    pre, declaration, source = _pre_review(pre_root)
    pre_bytes = (pre / "assessment.manifest.json").read_bytes()
    FIXTURE._control(declaration, "independent-review")["status"] = outcome
    declaration["files"] = sorted([*declaration["files"], PREVIEW])
    review = FIXTURE._evidence(REVIEW, outcome=outcome, declaration=declaration)
    review["reviewed_manifest_sha256"] = _hash(pre_bytes)
    (source / REVIEW).write_text(json.dumps(review), encoding="utf-8")
    (source / PREVIEW).write_bytes(pre_bytes)
    final_root = tmp_path / "final"
    final_root.mkdir()
    return _build(final_root, declaration, source), pre_bytes


def _rewrite_manifest(bundle, verifier):
    path = bundle / "assessment.manifest.json"
    manifest = json.loads(path.read_bytes())
    for item in manifest["files"]:
        raw = (bundle / item["path"]).read_bytes()
        item.update(size=len(raw), sha256=_hash(raw))
    manifest.pop("candidate_id")
    manifest["candidate_id"] = "sha256:" + _hash(verifier.canonical_json(manifest))
    path.write_bytes(verifier.canonical_json(manifest))


def _verify(bundle):
    verifier = FIXTURE._load(FIXTURE.VERIFY, "assessment_bound_review")
    return verifier.verify(bundle, expected_manifest_sha256=FIXTURE._expected(bundle))


@pytest.mark.parametrize("outcome", ["PASS", "FAIL"])
def test_v2_review_binds_retained_exact_prereview_bytes_without_self_reference(tmp_path, outcome):
    bundle, pre_bytes = _final(tmp_path, outcome)
    result = _verify(bundle)
    assert result.errors == []
    assert result.ready_for_technical_go is (outcome == "PASS")
    assert (bundle / PREVIEW).read_bytes() == pre_bytes
    assert _hash(pre_bytes) != FIXTURE._expected(bundle)
    clean_room = subprocess.run([sys.executable, str(bundle / "verify_assessment_bundle.py"), str(bundle),
        "--expected-manifest-sha256", FIXTURE._expected(bundle)], capture_output=True, text=True)
    assert clean_room.returncode == 0, clean_room.stderr


@pytest.mark.parametrize("mutation", ["missing", "wrong", "current-final", "final-as-prereview", "noncanonical", "changed-candidate", "changed-proof"])
def test_v2_review_rejects_missing_wrong_self_and_substituted_inputs_even_if_rehashed(tmp_path, mutation):
    bundle, pre_bytes = _final(tmp_path)
    verifier = FIXTURE._load(FIXTURE.VERIFY, "assessment_bound_review_mutations")
    path = bundle / REVIEW
    review = json.loads(path.read_bytes())
    if mutation == "missing":
        review.pop("reviewed_manifest_sha256")
    elif mutation == "wrong":
        review["reviewed_manifest_sha256"] = "0" * 64
    elif mutation == "current-final":
        review["reviewed_manifest_sha256"] = FIXTURE._expected(bundle)
    elif mutation == "final-as-prereview":
        raw = (bundle / "assessment.manifest.json").read_bytes()
        (bundle / PREVIEW).write_bytes(raw)
        review["reviewed_manifest_sha256"] = _hash(raw)
    elif mutation == "noncanonical":
        raw = json.dumps(json.loads(pre_bytes), indent=2).encode()
        (bundle / PREVIEW).write_bytes(raw)
        review["reviewed_manifest_sha256"] = _hash(raw)
    elif mutation == "changed-candidate":
        pre = json.loads(pre_bytes)
        pre["sources"][0]["revision"] = "7" * 40
        pre.pop("candidate_id")
        pre["candidate_id"] = "sha256:" + _hash(verifier.canonical_json(pre))
        raw = verifier.canonical_json(pre)
        (bundle / PREVIEW).write_bytes(raw)
        review["reviewed_manifest_sha256"] = _hash(raw)
    else:
        proof = bundle / "evidence/clinical-receipt.json"
        value = json.loads(proof.read_bytes())
        value["negative_controls"].append("different-unreviewed-control")
        proof.write_text(json.dumps(value), encoding="utf-8")
    path.write_text(json.dumps(review), encoding="utf-8")
    _rewrite_manifest(bundle, verifier)
    result = _verify(bundle)
    assert result.errors and not result.ready_for_technical_go
    assert any("review" in error for error in result.errors), result.errors


def test_v2_not_verified_keeps_closed_placeholder_and_needs_no_prereview_file(tmp_path):
    bundle, declaration, source = _pre_review(tmp_path)
    result = _verify(bundle)
    assert result.errors == [] and not result.ready_for_technical_go
    assert not (bundle / PREVIEW).exists()
    path = bundle / REVIEW
    value = json.loads(path.read_bytes())
    value["reviewed_manifest_sha256"] = "0" * 64
    path.write_text(json.dumps(value), encoding="utf-8")
    verifier = FIXTURE._load(FIXTURE.VERIFY, "assessment_bound_review_pending")
    _rewrite_manifest(bundle, verifier)
    assert any("NOT_VERIFIED" in error for error in _verify(bundle).errors)


def test_v2_missing_retained_manifest_cannot_export_final_review(tmp_path):
    pre, declaration, source = _pre_review(tmp_path)
    FIXTURE._control(declaration, "independent-review")["status"] = "PASS"
    review = FIXTURE._evidence(REVIEW, outcome="PASS", declaration=declaration)
    review["reviewed_manifest_sha256"] = FIXTURE._expected(pre)
    (source / REVIEW).write_text(json.dumps(review), encoding="utf-8")
    declaration_path = tmp_path / "final-declaration.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")
    result = subprocess.run([sys.executable, str(FIXTURE.BUILD), "--declaration", str(declaration_path),
        "--input-dir", str(source), "--output-dir", str(tmp_path / "final")], capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tmp_path / "final").exists()
