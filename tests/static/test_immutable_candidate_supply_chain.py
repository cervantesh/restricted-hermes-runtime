"""Contract tests for the immutable clinical-edge candidate boundary."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

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


def _subject(name: str, image: str, lock: str, marker: str, repo_root: Path) -> dict[str, object]:
    digest = _digest(marker)
    run_url = "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1"
    verification_path = f"candidate-verification/{name}.attestations.json"
    platform_path = f"candidate-verification/{name}.platform.json"
    lock_bytes = (ROOT / lock).read_bytes()
    provenance_path = f"candidate-verification/{name}.provenance.json"
    sbom_path = f"candidate-verification/{name}.sbom.json"
    for relative in (provenance_path, sbom_path):
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
    verification = {
        "schema_version": "restricted-runtime-attestation-receipt.v1",
        "image": f"{image}@{digest}",
        "digest": digest,
        "source_revision": "d" * 40,
        "workflow_run_url": run_url,
        "provenance": {"predicate_type": "https://slsa.dev/provenance/v1", "raw_artifact": provenance_path, "raw_sha256": hashlib.sha256((repo_root / provenance_path).read_bytes()).hexdigest()},
        "sbom": {"predicate_type": "https://spdx.dev/Document", "raw_artifact": sbom_path, "raw_sha256": hashlib.sha256((repo_root / sbom_path).read_bytes()).hexdigest()},
    }
    platform = {
        "schema_version": "restricted-runtime-subject-receipt.v1",
        "image": f"{image}@{digest}",
        "subject_digest": digest,
        "source_revision": "d" * 40,
        "workflow_run_url": run_url,
        "resolved_platform": "linux/amd64",
        "subject_kind": "manifest",
        "linux_amd64_child_digest": digest,
        "source": "https://github.com/cervantesh/restricted-hermes-runtime",
        "labels": {
            "org.opencontainers.image.source": "https://github.com/cervantesh/restricted-hermes-runtime",
            "org.opencontainers.image.revision": "d" * 40,
        },
    }
    for relative, value in ((verification_path, verification), (platform_path, platform)):
        path = repo_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
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
            "sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "artifacts": [{"name": "closed", "version": "1.0.0", "sha256": "c" * 64}],
        },
        "sbom": {
            "format": "spdxjson",
            "subject_digest": digest,
            "verification": {
                "subject_digest": digest,
                "source_revision": "d" * 40,
                "workflow_run_url": run_url,
                "predicate_type": "https://spdx.dev/Document",
                "receipt": verification_path,
                "receipt_sha256": hashlib.sha256((repo_root / verification_path).read_bytes()).hexdigest(),
            },
        },
        "provenance": {
            "subject_digest": digest,
            "verification": {
                "subject_digest": digest,
                "source_revision": "d" * 40,
                "workflow_run_url": run_url,
                "predicate_type": "https://slsa.dev/provenance/v1",
                "receipt": verification_path,
                "receipt_sha256": hashlib.sha256((repo_root / verification_path).read_bytes()).hexdigest(),
            },
        },
        "platform_receipt": {
            "receipt": platform_path,
            "receipt_sha256": hashlib.sha256((repo_root / platform_path).read_bytes()).hexdigest(),
        },
        "tests": [{
            "name": "published-role-closure",
            "outcome": "passed",
            "subject_digest": digest,
            "receipt": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1",
        }],
    }


def valid_manifest(repo_root: Path) -> dict[str, object]:
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
            _subject("restricted-mattermost-ingress", "ghcr.io/cervantesh/restricted-mattermost-ingress", "requirements/immutable/mattermost-ingress.txt", "e", repo_root),
            _subject("restricted-clinical-adapter", "ghcr.io/cervantesh/restricted-clinical-adapter", "requirements/immutable/clinical-adapter.txt", "f", repo_root),
        ],
        "external_subjects": [{
            "name": "health-record-hub",
            "reference": "registry.invalid/hrh@" + _digest("1"),
            "digest": _digest("1"),
            "verified": True,
            "build_or_attestation_claimed": False,
        }],
        "evidence": {
            "source_revision": "d" * 40,
            "workflow_run_url": "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/1",
            "phi_authorized": False,
            "deployment_conformant": False,
            "commands": [{"name": "published-role-closure", "outcome": "passed"}],
            "results": {"published_role_closure": "passed"},
            "summary": {"passed": 1, "skipped": 0, "failed": 0},
            "subject_digests": {
                "restricted-mattermost-ingress": _digest("e"),
                "restricted-clinical-adapter": _digest("f"),
            },
        },
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


def test_candidate_workflow_exports_published_digests_before_consuming_them_and_scopes_permissions():
    source = (ROOT / ".github" / "workflows" / "immutable-candidate.yml").read_text(encoding="utf-8")
    export = source.index("name: Export immutable published subject references")
    closure = source.index("name: Pull only the published subjects and verify their role closure")
    assert export < closure
    exported_block = source[export:closure]
    assert '>> "$GITHUB_ENV"' in exported_block
    assert "RESTRICTED_PUBLISHED_CANDIDATE=1" in exported_block
    assert "packages: read" in source
    consumer = source[source.index("exercise-published-subjects:"):]
    assert "GH_TOKEN: ${{ github.token }}" in consumer
    assert "--predicate-type https://slsa.dev/provenance/v1" in consumer
    assert "--predicate-type https://spdx.dev/Document" in consumer
    assert "verify_published_attestations.py" in consumer
    assert "inspect_published_subject.py" in consumer
    builder = (ROOT / "tools" / "build_immutable_candidate_manifest.py").read_text(encoding="utf-8")
    assert '"verified": True' not in builder


def test_published_mode_fails_before_any_docker_fallback_when_digest_is_absent():
    bash = Path("C:/Program Files/Git/bin/bash.exe")
    if not bash.exists():
        pytest.skip("Git Bash unavailable")
    for script, variable in (
        (ROOT / "tests" / "deployment" / "test_mattermost_ingress_image.sh", "RESTRICTED_MATTERMOST_IMAGE_DIGEST"),
        (ROOT / "tests" / "deployment" / "test_clinical_adapter_image.sh", "RESTRICTED_CLINICAL_ADAPTER_IMAGE_DIGEST"),
    ):
        result = subprocess.run(
            [str(bash), str(script)], cwd=ROOT,
            env={**os.environ, "RESTRICTED_PUBLISHED_CANDIDATE": "1", variable: ""},
            capture_output=True, text=True,
        )
        assert result.returncode == 64
        assert "requires an immutable digest" in result.stderr


def test_candidate_verifier_accepts_matching_subjects_and_rejects_relational_failures(tmp_path: Path):
    verifier = _load_verifier()
    for lock in ("requirements/immutable/mattermost-ingress.txt", "requirements/immutable/clinical-adapter.txt"):
        target = tmp_path / lock
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / lock).read_bytes())
    manifest = valid_manifest(tmp_path)
    assert verifier.verify(manifest, repo_root=tmp_path) == []

    wrong_digest = copy.deepcopy(manifest)
    wrong_digest["subjects"][0]["tests"][0]["subject_digest"] = _digest("0")
    assert any("test receipt" in error for error in verifier.verify(wrong_digest, repo_root=tmp_path))

    wrong_platform = copy.deepcopy(manifest)
    wrong_platform["subjects"][0]["platform"] = "linux/arm64"
    assert any("platform" in error for error in verifier.verify(wrong_platform, repo_root=tmp_path))

    missing_subject = copy.deepcopy(manifest)
    missing_subject["subjects"].pop()
    assert any("subject set" in error for error in verifier.verify(missing_subject, repo_root=tmp_path))

    cross_subject = copy.deepcopy(manifest)
    cross_subject["subjects"][1]["sbom"]["subject_digest"] = cross_subject["subjects"][0]["digest"]
    assert any("SBOM" in error for error in verifier.verify(cross_subject, repo_root=tmp_path))

    unverified_external = copy.deepcopy(manifest)
    unverified_external["external_subjects"][0]["verified"] = False
    assert any("external subject" in error for error in verifier.verify(unverified_external, repo_root=tmp_path))

    wrong_image = copy.deepcopy(manifest)
    wrong_image["subjects"][0]["image"] = "ghcr.io/cervantesh/other@" + wrong_image["subjects"][0]["digest"]
    assert any("expected GHCR image" in error for error in verifier.verify(wrong_image, repo_root=tmp_path))

    wrong_lock = copy.deepcopy(manifest)
    wrong_lock["subjects"][0]["dependency_lock"]["sha256"] = "0" * 64
    assert any("hash does not match" in error for error in verifier.verify(wrong_lock, repo_root=tmp_path))

    wrong_claim = copy.deepcopy(manifest)
    wrong_claim["evidence"]["phi_authorized"] = True
    assert any("phi_authorized" in error for error in verifier.verify(wrong_claim, repo_root=tmp_path))

    wrong_run = copy.deepcopy(manifest)
    wrong_run["subjects"][0]["tests"][0]["receipt"] = "https://github.com/cervantesh/restricted-hermes-runtime/actions/runs/2"
    assert any("exact subject and run" in error for error in verifier.verify(wrong_run, repo_root=tmp_path))

    wrong_receipt = copy.deepcopy(manifest)
    platform_path = tmp_path / wrong_receipt["subjects"][0]["platform_receipt"]["receipt"]
    receipt = json.loads(platform_path.read_text())
    receipt["resolved_platform"] = "linux/arm64"
    platform_path.write_text(json.dumps(receipt), encoding="utf-8")
    assert any("receipt hash does not match" in error for error in verifier.verify(wrong_receipt, repo_root=tmp_path))


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
