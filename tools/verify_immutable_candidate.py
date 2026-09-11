#!/usr/bin/env python3
"""Fail-closed verifier for immutable clinical-edge candidate evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "restricted-runtime-immutable-candidate.v1"
PLATFORM = "linux/amd64"
REPOSITORY = "cervantesh/restricted-hermes-runtime"
WORKFLOW = ".github/workflows/immutable-candidate.yml"
SOURCE = "https://github.com/cervantesh/restricted-hermes-runtime"
RUN_URL = re.compile(r"https://github\.com/cervantesh/restricted-hermes-runtime/actions/runs/[1-9][0-9]*$")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}$")
SHA256_RAW = re.compile(r"[0-9a-f]{64}$")
GIT_SHA = re.compile(r"[0-9a-f]{40}$")
EXPECTED_IMAGES = {
    "restricted-mattermost-ingress": "ghcr.io/cervantesh/restricted-mattermost-ingress",
    "restricted-clinical-adapter": "ghcr.io/cervantesh/restricted-clinical-adapter",
}
EXPECTED_LOCKS = {
    "restricted-mattermost-ingress": "requirements/immutable/mattermost-ingress.txt",
    "restricted-clinical-adapter": "requirements/immutable/clinical-adapter.txt",
}
EXPECTED_DOCKERFILES = {
    "restricted-mattermost-ingress": "Dockerfile.mattermost-ingress",
    "restricted-clinical-adapter": "Dockerfile.clinical-adapter",
}
LOCK_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})$")
BASE_IMAGE = re.compile(r"^FROM\s+([^@\s]+)@(sha256:[0-9a-f]{64})(?:\s|$)", re.MULTILINE)


def _mapping(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _digest(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256.fullmatch(value))


def _raw_hash(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RAW.fullmatch(value))


def _lock_artifacts(content: bytes) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for raw in content.decode("utf-8").splitlines():
        match = LOCK_LINE.fullmatch(raw.strip())
        if match:
            artifacts.append({"name": match.group(1), "version": match.group(2), "sha256": match.group(3)})
    return artifacts


def _error(errors: list[str], message: str) -> None:
    errors.append(message)


def _attestation_entries(value: object) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, dict)]
    if isinstance(value, dict) and isinstance(value.get("verificationResults"), list):
        return [entry for entry in value["verificationResults"] if isinstance(entry, dict)]
    return [value] if isinstance(value, dict) else []


def _raw_names_subject(value: object, digest: str, predicate: str) -> bool:
    for entry in _attestation_entries(value):
        verification_result = _mapping(entry.get("verificationResult"))
        statement = _mapping(verification_result.get("statement")) if verification_result else None
        if statement is None or statement.get("predicateType") != predicate:
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            item = _mapping(subject)
            digest_map = _mapping(item.get("digest")) if item else None
            if digest_map and digest_map.get("sha256") == digest.removeprefix("sha256:"):
                return True
    return False


def _raw_names_revision(value: object, revision: str) -> bool:
    if value == revision:
        return True
    if isinstance(value, dict):
        return any(_raw_names_revision(child, revision) for child in value.values())
    if isinstance(value, list):
        return any(_raw_names_revision(child, revision) for child in value)
    return False


def _read_hashed_json(repo_root: Path, relative: object, expected_hash: object, errors: list[str], context: str, *, object_required: bool = True) -> dict[str, Any] | object | None:
    if not isinstance(relative, str) or not _raw_hash(expected_hash):
        _error(errors, f"{context}: receipt reference and sha256 are required")
        return None
    root = repo_root.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        _error(errors, f"{context}: receipt escapes repo root")
        return None
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        _error(errors, f"{context}: unreadable receipt: {exc}")
        return None
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        _error(errors, f"{context}: receipt hash does not match")
        return None
    if not object_required:
        return value
    record = _mapping(value)
    if record is None:
        _error(errors, f"{context}: receipt is not an object")
    return record


def _verify_attestation(errors: list[str], name: str, kind: str, value: object, image: str, digest: str, source_revision: str, run_url: str, repo_root: Path) -> None:
    record = _mapping(value)
    if record is None or record.get("subject_digest") != digest:
        _error(errors, f"{name}: {kind} subject digest does not match image subject")
        return
    verification = _mapping(record.get("verification"))
    expected_predicate = "https://spdx.dev/Document/v2.3" if kind == "SBOM" else "https://slsa.dev/provenance/v1"
    if verification is None:
        _error(errors, f"{name}: {kind} verification is missing")
        return
    if (verification.get("subject_digest") != digest or verification.get("source_revision") != source_revision
            or verification.get("workflow_run_url") != run_url or verification.get("predicate_type") != expected_predicate):
        _error(errors, f"{name}: {kind} verification binding mismatch")
    receipt = _read_hashed_json(repo_root, verification.get("receipt"), verification.get("receipt_sha256"), errors, f"{name}: {kind}")
    if receipt is None:
        return
    part = _mapping(receipt.get(kind.lower()))
    if (receipt.get("schema_version") != "restricted-runtime-attestation-receipt.v1" or receipt.get("image") != image
            or receipt.get("digest") != digest or receipt.get("source_revision") != source_revision
            or receipt.get("workflow_run_url") != run_url or part is None
            or part.get("predicate_type") != expected_predicate or not isinstance(part.get("raw_artifact"), str)
            or not _raw_hash(part.get("raw_sha256"))):
        _error(errors, f"{name}: {kind} receipt does not prove the exact OCI subject")
        return
    raw = _read_hashed_json(repo_root, part.get("raw_artifact"), part.get("raw_sha256"), errors, f"{name}: {kind} raw verification", object_required=False)
    if raw is None:
        return
    if not _raw_names_subject(raw, digest, expected_predicate):
        _error(errors, f"{name}: {kind} raw verification does not name the exact subject")
    if kind == "provenance" and not _raw_names_revision(raw, source_revision):
        _error(errors, f"{name}: provenance raw verification does not name the expected source revision")


def _verify_platform(errors: list[str], name: str, item: dict[str, Any], image: str, digest: str, source_revision: str, run_url: str, repo_root: Path) -> None:
    reference = _mapping(item.get("platform_receipt"))
    if reference is None:
        _error(errors, f"{name}: platform receipt is missing")
        return
    receipt = _read_hashed_json(repo_root, reference.get("receipt"), reference.get("receipt_sha256"), errors, f"{name}: platform")
    if receipt is None:
        return
    if (receipt.get("schema_version") != "restricted-runtime-subject-receipt.v1" or receipt.get("image") != image
            or receipt.get("subject_digest") != digest or receipt.get("source_revision") != source_revision
            or receipt.get("workflow_run_url") != run_url or receipt.get("resolved_platform") != PLATFORM
            or receipt.get("subject_kind") not in {"manifest", "index"} or not _digest(receipt.get("linux_amd64_child_digest"))
            or receipt.get("source") != SOURCE or _mapping(receipt.get("labels")) is None
            or _mapping(receipt.get("labels")).get("org.opencontainers.image.source") != SOURCE
            or _mapping(receipt.get("labels")).get("org.opencontainers.image.revision") != source_revision):
        _error(errors, f"{name}: platform receipt does not prove linux/amd64 exact subject")


def _verify_distinct_attestation_artifacts(errors: list[str], name: str, item: dict[str, Any], repo_root: Path) -> None:
    sbom = _mapping(item.get("sbom"))
    verification = _mapping(sbom.get("verification")) if sbom else None
    if verification is None:
        return
    receipt = _read_hashed_json(repo_root, verification.get("receipt"), verification.get("receipt_sha256"), errors, f"{name}: attestation pair")
    if receipt is None:
        return
    provenance = _mapping(receipt.get("provenance"))
    sbom_part = _mapping(receipt.get("sbom"))
    if (provenance is None or sbom_part is None or provenance.get("predicate_type") != "https://slsa.dev/provenance/v1"
            or sbom_part.get("predicate_type") != "https://spdx.dev/Document/v2.3"
            or provenance.get("raw_artifact") == sbom_part.get("raw_artifact")):
        _error(errors, f"{name}: provenance and SBOM must be distinct predicate artifacts")


def _verify_subject(errors: list[str], subject: object, source_revision: str, run_url: str, repo_root: Path) -> str | None:
    item = _mapping(subject)
    if item is None:
        _error(errors, "subject is not an object")
        return None
    name = item.get("name")
    if not isinstance(name, str):
        _error(errors, "subject has no name")
        return None
    digest = item.get("digest")
    image = item.get("image")
    expected_image = EXPECTED_IMAGES.get(name)
    if not _digest(digest):
        _error(errors, f"{name}: image digest is invalid")
        return name
    if expected_image is None or image != f"{expected_image}@{digest}":
        _error(errors, f"{name}: image must be the expected GHCR image at its exact digest")
    if item.get("platform") != PLATFORM:
        _error(errors, f"{name}: platform must be {PLATFORM}")
    materials = item.get("base_materials")
    if not isinstance(materials, list) or not materials or any(_mapping(x) is None or not _digest(_mapping(x).get("digest")) or _mapping(x).get("platform") != PLATFORM for x in materials):
        _error(errors, f"{name}: base material must be an immutable {PLATFORM} subject")
    lock = _mapping(item.get("dependency_lock"))
    expected_lock = EXPECTED_LOCKS.get(name)
    if lock is None or not isinstance(lock.get("path"), str) or not _raw_hash(lock.get("sha256")):
        _error(errors, f"{name}: dependency lock is invalid")
    elif lock["path"] != expected_lock:
        _error(errors, f"{name}: designated dependency lock does not match subject")
    else:
        lock_path = (repo_root / lock["path"]).resolve()
        if not lock_path.is_relative_to(repo_root.resolve()):
            _error(errors, f"{name}: dependency lock escapes repo root")
        else:
            try:
                actual_hash = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            except OSError as exc:
                _error(errors, f"{name}: dependency lock unavailable: {exc}")
            else:
                if actual_hash != lock["sha256"]:
                    _error(errors, f"{name}: dependency lock hash does not match repo content")
                elif lock.get("artifacts") != _lock_artifacts(lock_path.read_bytes()):
                    _error(errors, f"{name}: dependency lock artifacts do not match repo content")
    _verify_attestation(errors, name, "SBOM", item.get("sbom"), str(image), str(digest), source_revision, run_url, repo_root)
    _verify_attestation(errors, name, "provenance", item.get("provenance"), str(image), str(digest), source_revision, run_url, repo_root)
    _verify_distinct_attestation_artifacts(errors, name, item, repo_root)
    _verify_platform(errors, name, item, str(image), str(digest), source_revision, run_url, repo_root)
    tests = item.get("tests")
    if not isinstance(tests, list) or not tests or any(_mapping(x) is None or _mapping(x).get("outcome") != "passed" or _mapping(x).get("subject_digest") != digest or _mapping(x).get("receipt") != run_url for x in tests):
        _error(errors, f"{name}: test receipt does not prove this exact subject and run")
    return name


def _verify_evidence(errors: list[str], value: object, source_revision: str, run_url: str, subject_digests: dict[str, str]) -> None:
    evidence = _mapping(value)
    if evidence is None:
        _error(errors, "AC10 evidence is missing")
        return
    if evidence.get("source_revision") != source_revision or evidence.get("workflow_run_url") != run_url:
        _error(errors, "AC10 evidence is bound to a different source or run")
    if evidence.get("phi_authorized") is not False:
        _error(errors, "AC10 evidence must state phi_authorized=false")
    if evidence.get("deployment_conformant") is not False:
        _error(errors, "AC10 evidence must state deployment_conformant=false")
    commands = evidence.get("commands")
    results = _mapping(evidence.get("results"))
    if not isinstance(commands, list) or not commands or results is None:
        _error(errors, "AC10 evidence must include commands and results")
        return
    command_names: set[str] = set()
    for command in commands:
        item = _mapping(command)
        if (item is None or not isinstance(item.get("id"), str) or not item["id"]
                or not isinstance(item.get("command"), str) or not item["command"]
                or item.get("outcome") != "passed" or item.get("exit_code") != 0):
            _error(errors, "AC10 evidence command lacks id/text/passed exit_code=0")
            continue
        command_names.add(item["id"])
    if len(command_names) != len(commands):
        _error(errors, "AC10 evidence command ids must be unique")
    summary = _mapping(evidence.get("summary"))
    if summary is None or any(not isinstance(summary.get(key), int) or summary[key] < 0 for key in ("passed", "skipped", "failed")):
        _error(errors, "AC10 evidence must include pass/skip/failure counts")
    elif summary["passed"] != len(commands) or summary["skipped"] != 0 or summary["failed"] != 0:
        _error(errors, "AC10 evidence summary is inconsistent with passed command receipts")
    if set(results) != command_names or any(value != "passed" for value in results.values()):
        _error(errors, "AC10 results are inconsistent with command receipts")
    if evidence.get("subject_digests") != subject_digests:
        _error(errors, "AC10 evidence must bind the exact published subject digests")


def _verify_external_subjects(errors: list[str], value: object) -> None:
    items = value if isinstance(value, list) else None
    if not items:
        _error(errors, "external subjects are missing")
        return
    found = False
    for item in items:
        record = _mapping(item)
        if record is None:
            _error(errors, "external subject is not an object")
            continue
        if record.get("name") == "health-record-hub":
            found = True
        if not _digest(record.get("digest")) or not isinstance(record.get("reference"), str) or not record["reference"].endswith("@" + str(record.get("digest"))):
            _error(errors, f"external subject {record.get('name')!r} must have an exact immutable reference")
        if record.get("verified") is not True or record.get("build_or_attestation_claimed") is not False:
            _error(errors, f"external subject {record.get('name')!r} is invalid")
    if not found:
        _error(errors, "health-record-hub external subject is missing")


def verify(manifest: object, *, require_external: bool = True, repo_root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    root = _mapping(manifest)
    if root is None:
        return ["manifest is not an object"]
    if root.get("schema_version") != SCHEMA:
        _error(errors, "schema version mismatch")
    source_revision = root.get("source_revision")
    if not isinstance(source_revision, str) or not GIT_SHA.fullmatch(source_revision):
        _error(errors, "source revision must be an exact git SHA")
        source_revision = ""
    if root.get("platform") != PLATFORM:
        _error(errors, f"manifest platform must be {PLATFORM}")
    workflow = _mapping(root.get("workflow"))
    run_url = ""
    if workflow is None or workflow.get("repository") != REPOSITORY or workflow.get("path") != WORKFLOW or not isinstance(workflow.get("run_url"), str) or not RUN_URL.fullmatch(workflow["run_url"]):
        _error(errors, "workflow identity is incomplete or mismatched")
    else:
        run_url = workflow["run_url"]
    names: set[str] = set()
    subject_digests: dict[str, str] = {}
    subjects = root.get("subjects")
    if not isinstance(subjects, list):
        _error(errors, "subjects are missing")
    else:
        for subject in subjects:
            name = _verify_subject(errors, subject, source_revision, run_url, repo_root)
            if name in names:
                _error(errors, f"duplicate subject {name}")
            if name:
                names.add(name)
                item = _mapping(subject)
                if item and isinstance(item.get("digest"), str):
                    subject_digests[name] = item["digest"]
    if names != set(EXPECTED_IMAGES):
        _error(errors, f"subject set must be exactly {sorted(EXPECTED_IMAGES)}")
    _verify_evidence(errors, root.get("evidence"), source_revision, run_url, subject_digests)
    if require_external:
        _verify_external_subjects(errors, root.get("external_subjects"))
    return errors


def _git_show(repo_root: Path, revision: str, path: str) -> bytes | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{revision}:{path}"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def _expected_base_material(source: bytes) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for image, digest in BASE_IMAGE.findall(source.decode("utf-8")):
        found.append({"image": "docker.io/library/" + image if "/" not in image else image, "digest": digest, "platform": PLATFORM})
    return found[:1]


def verify_live_attestations(manifest: object, *, repo_root: Path = ROOT) -> list[str]:
    """Re-run GitHub's verifier; retained JSON is audit material, not trust."""
    root = _mapping(manifest)
    if root is None:
        return ["attestation authentication requires a manifest object"]
    source_revision = root.get("source_revision")
    subjects = root.get("subjects")
    workflow = _mapping(root.get("workflow"))
    run_url = workflow.get("run_url") if workflow else None
    if not isinstance(source_revision, str) or not isinstance(subjects, list) or not isinstance(run_url, str):
        return ["attestation authentication requires a valid candidate frame"]
    if shutil.which("gh") is None:
        return ["attestation verifier unavailable"]
    errors: list[str] = []
    authenticated_runs: set[str] = set()
    for subject in subjects:
        item = _mapping(subject)
        name = item.get("name") if item else "unknown-subject"
        image = item.get("image") if item else None
        if not isinstance(name, str) or not isinstance(image, str):
            errors.append("attestation authentication has an invalid subject")
            continue
        lock = _mapping(item.get("dependency_lock"))
        lock_bytes = _git_show(repo_root, source_revision, EXPECTED_LOCKS.get(name, ""))
        if lock_bytes is None or lock is None or lock.get("sha256") != hashlib.sha256(lock_bytes or b"").hexdigest() or lock.get("artifacts") != _lock_artifacts(lock_bytes or b""):
            errors.append(f"{name}: authenticated source lock binding failed")
        dockerfile = _git_show(repo_root, source_revision, EXPECTED_DOCKERFILES.get(name, ""))
        if dockerfile is None or item.get("base_materials") != _expected_base_material(dockerfile):
            errors.append(f"{name}: authenticated source base material binding failed")
        for kind, predicate in (("provenance", "https://slsa.dev/provenance/v1"), ("SBOM", "https://spdx.dev/Document/v2.3")):
            command = [
                "gh", "attestation", "verify", f"oci://{image}", "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}", "--bundle-from-oci",
                "--source-digest", source_revision, "--predicate-type", predicate, "--format=json",
            ]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
            except (OSError, subprocess.TimeoutExpired):
                errors.append(f"{name}: {kind} attestation authentication unavailable")
                continue
            if result.returncode != 0:
                errors.append(f"{name}: {kind} attestation authentication failed")
                continue
            try:
                entries = _attestation_entries(json.loads(result.stdout))
                invocation = _mapping(_mapping(entries[0].get("verificationResult")).get("signature")).get("certificate").get("runInvocationURI")
            except (AttributeError, IndexError, json.JSONDecodeError):
                errors.append(f"{name}: {kind} attestation lacks an authenticated run identity")
                continue
            if not isinstance(invocation, str) or not invocation.startswith(run_url + "/attempts/"):
                errors.append(f"{name}: {kind} attestation run identity does not match evidence")
            else:
                authenticated_runs.add(invocation)
    if len(authenticated_runs) != 1:
        errors.append("attestation authentication does not bind one workflow run")
    elif authenticated_runs:
        run_id = authenticated_runs.pop().removeprefix(f"https://github.com/{REPOSITORY}/actions/runs/").split("/", 1)[0]
        try:
            result = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}"], capture_output=True, text=True, timeout=30, check=False)
            run = json.loads(result.stdout) if result.returncode == 0 else {}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            run = {}
        if run.get("conclusion") != "success" or run.get("head_sha") != source_revision:
            errors.append("authenticated workflow run is not a successful source-matched run")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--closed-subjects-only", action="store_true")
    parser.add_argument("--offline-structure-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"immutable candidate: unreadable manifest: {exc}", file=sys.stderr)
        return 2
    errors = verify(manifest, require_external=not args.closed_subjects_only, repo_root=args.repo_root)
    if not errors and not args.offline_structure_only:
        errors.extend(verify_live_attestations(manifest, repo_root=args.repo_root))
    if errors:
        print(*["immutable candidate: FAIL: " + error for error in errors], sep="\n", file=sys.stderr)
        return 1
    if args.offline_structure_only:
        print("immutable candidate: STRUCTURE ONLY; attestation authenticity not reverified")
        return 3
    print("immutable candidate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
