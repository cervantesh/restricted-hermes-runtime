"""Contract tests for the immutable clinical-edge candidate boundary."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
VERIFY_PATH = ROOT / "tools" / "verify_immutable_candidate.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("immutable_candidate_verifier", VERIFY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _subject(name: str, image: str, lock: str, marker: str) -> dict[str, object]:
    digest = _digest(marker)
    return {
        "name": name,
        "image": f"{image}@{digest}",
        "digest": digest,
        "platform": "linux/amd64",
        "base_materials": [{
            "image": "docker.io/library/python",
            "digest": _digest("a"),
            "platform": "linux/amd64",
        }],
        "dependency_lock": {
            "path": lock,
            "sha256": "b" * 64,
            "artifacts": [{"name": "closed", "version": "1.0.0", "sha256": "c" * 64}],
        },
        "sbom": {
            "format": "spdxjson",
            "subject_digest": digest,
            "verification": {
                "verified": True,
                "repository": "cervantesh/restricted-hermes-runtime",
                "workflow": ".github/workflows/immutable-candidate.yml",
                "subject_digest": digest,
            },
        },
        "provenance": {
            "subject_digest": digest,
            "verification": {
                "verified": True,
                "repository": "cervantesh/restricted-hermes-runtime",
                "workflow": ".github/workflows/immutable-candidate.yml",
                "subject_digest": digest,
            },
        },
        "tests": [{
            "name": "published-role-closure",
            "outcome": "passed",
            "subject_digest": digest,
            "receipt": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1",
        }],
    }


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "restricted-runtime-immutable-candidate.v1",
        "source_revision": "d" * 40,
        "platform": "linux/amd64",
        "workflow": {
            "repository": "cervantesh/restricted-hermes-runtime",
            "path": ".github/workflows/immutable-candidate.yml",
            "run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1",
        },
        "subjects": [
            _subject("restricted-mattermost-ingress", "ghcr.io/cervantesh/restricted-mattermost-ingress", "requirements/immutable/mattermost-ingress.txt", "e"),
            _subject("restricted-clinical-adapter", "ghcr.io/cervantesh/restricted-clinical-adapter", "requirements/immutable/clinical-adapter.txt", "f"),
        ],
        "external_subjects": [{
            "name": "health-record-hub",
            "reference": "registry.invalid/hrh@" + _digest("1"),
            "digest": _digest("1"),
            "verified": True,
            "build_or_attestation_claimed": False,
        }],
    }


def test_closed_dockerfiles_use_linux_amd64_manifest_subjects_and_hashed_locks():
    expected = "python@sha256:d1053354624536b044162aaab1e418bd000ea35184fb1ae098ab3166b1072e72"
    for recipe in (ROOT / "Dockerfile.mattermost-ingress", ROOT / "Dockerfile.clinical-adapter"):
        source = recipe.read_text(encoding="utf-8")
        assert source.count("FROM python@sha256:") == 2
        assert "FROM python:3.11-slim" not in source
        assert source.count(expected) == 2
        assert "--no-build-isolation" in source
        assert "--require-hashes" in source
        assert "--no-deps" in source


def test_immutable_locks_are_exact_and_hashed():
    for lock in (ROOT / "requirements" / "immutable").glob("*.txt"):
        lines = [line.strip() for line in lock.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        for line in lines:
            assert "==" in line
            assert "--hash=sha256:" in line
            assert ">=" not in line and "<" not in line


def test_candidate_workflow_is_same_repository_build_once_and_attests_each_final_subject():
    source = (ROOT / ".github" / "workflows" / "immutable-candidate.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in source
    assert "packages: write" in source and "attestations: write" in source and "id-token: write" in source
    assert "github.event_name != 'pull_request'" in source
    assert "platforms: linux/amd64" in source
    assert "push: true" in source
    assert "sbom: true" in source and "provenance: mode=max" in source
    assert "actions/attest-build-provenance@" in source
    assert "verify_immutable_candidate.py" in source
    assert "test_mattermost_esr_staging.py" in source
    assert "test_clinical_adapter_process.py" in source


def test_candidate_verifier_accepts_matching_subjects_and_rejects_relational_failures():
    verifier = _load_verifier()
    manifest = valid_manifest()
    assert verifier.verify(manifest) == []

    wrong_digest = copy.deepcopy(manifest)
    wrong_digest["subjects"][0]["tests"][0]["subject_digest"] = _digest("0")
    assert any("test receipt" in error for error in verifier.verify(wrong_digest))

    wrong_platform = copy.deepcopy(manifest)
    wrong_platform["subjects"][0]["platform"] = "linux/arm64"
    assert any("platform" in error for error in verifier.verify(wrong_platform))

    missing_subject = copy.deepcopy(manifest)
    missing_subject["subjects"].pop()
    assert any("subject set" in error for error in verifier.verify(missing_subject))

    cross_subject = copy.deepcopy(manifest)
    cross_subject["subjects"][1]["sbom"]["subject_digest"] = cross_subject["subjects"][0]["digest"]
    assert any("SBOM" in error for error in verifier.verify(cross_subject))

    unverified_external = copy.deepcopy(manifest)
    unverified_external["external_subjects"][0]["verified"] = False
    assert any("external subject" in error for error in verifier.verify(unverified_external))


def test_published_subject_harnesses_pull_digest_and_never_build_when_digest_is_supplied():
    for script, variable in (
        (ROOT / "tests" / "deployment" / "test_mattermost_ingress_image.sh", "RESTRICTED_MATTERMOST_IMAGE_DIGEST"),
        (ROOT / "tests" / "deployment" / "test_clinical_adapter_image.sh", "RESTRICTED_CLINICAL_ADAPTER_IMAGE_DIGEST"),
    ):
        source = script.read_text(encoding="utf-8")
        assert variable in source
        assert 'docker pull "$image"' in source
        assert 'docker build' in source
        assert 'must be immutable' in source


def test_staging_harnesses_have_an_exact_digest_no_rebuild_mode():
    for path in (
        ROOT / "tests" / "deployment" / "test_mattermost_esr_staging.py",
        ROOT / "tests" / "deployment" / "test_clinical_composed_e2e.py",
    ):
        source = path.read_text(encoding="utf-8")
        assert "RESTRICTED_IMMUTABLE_CANDIDATE_MANIFEST" in source
        assert "published subject requires an immutable digest" in source
        assert "no-rebuild" in source
