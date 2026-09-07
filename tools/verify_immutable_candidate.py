#!/usr/bin/env python3
"""Fail-closed verifier for an immutable clinical-edge candidate manifest.

This is deliberately a relationship verifier.  It does not trust a tag, a
locally rebuilt image, or an attestation for a different OCI subject.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "restricted-runtime-immutable-candidate.v1"
PLATFORM = "linux/amd64"
REPOSITORY = "cervantesh/restricted-hermes-runtime"
WORKFLOW = ".github/workflows/immutable-candidate.yml"
SUBJECTS = {
    "restricted-mattermost-ingress",
    "restricted-clinical-adapter",
}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}$")
SHA256_RAW = re.compile(r"[0-9a-f]{64}$")
GIT_SHA = re.compile(r"[0-9a-f]{40}$")


def _error(errors: list[str], text: str) -> None:
    errors.append(text)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256.fullmatch(value))


def _is_raw_hash(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RAW.fullmatch(value))


def _mapping(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _verify_attestation(errors: list[str], name: str, kind: str, value: object, digest: str) -> None:
    record = _mapping(value)
    if record is None:
        _error(errors, f"{name}: missing {kind} record")
        return
    if record.get("subject_digest") != digest:
        _error(errors, f"{name}: {kind} subject digest does not match image subject")
    verification = _mapping(record.get("verification"))
    if verification is None:
        _error(errors, f"{name}: {kind} verification is missing")
        return
    if verification.get("verified") is not True:
        _error(errors, f"{name}: {kind} verification is not true")
    if verification.get("subject_digest") != digest:
        _error(errors, f"{name}: {kind} verification names another subject")
    if verification.get("repository") != REPOSITORY:
        _error(errors, f"{name}: {kind} verification repository mismatch")
    if verification.get("workflow") != WORKFLOW:
        _error(errors, f"{name}: {kind} verification workflow mismatch")


def _verify_subject(errors: list[str], subject: object, source_revision: str) -> str | None:
    item = _mapping(subject)
    if item is None:
        _error(errors, "subject is not an object")
        return None
    name = item.get("name")
    if not isinstance(name, str):
        _error(errors, "subject has no name")
        return None
    digest = item.get("digest")
    if not _is_digest(digest):
        _error(errors, f"{name}: image digest is invalid")
        return name
    image = item.get("image")
    if not isinstance(image, str) or not image.endswith("@" + digest):
        _error(errors, f"{name}: image reference must name its immutable digest")
    if item.get("platform") != PLATFORM:
        _error(errors, f"{name}: platform must be {PLATFORM}")
    base_materials = item.get("base_materials")
    if not isinstance(base_materials, list) or not base_materials:
        _error(errors, f"{name}: base materials are missing")
    else:
        for material in base_materials:
            material_map = _mapping(material)
            if material_map is None or not _is_digest(material_map.get("digest")) or material_map.get("platform") != PLATFORM:
                _error(errors, f"{name}: base material must be an immutable {PLATFORM} subject")
    lock = _mapping(item.get("dependency_lock"))
    if lock is None:
        _error(errors, f"{name}: dependency lock is missing")
    else:
        path = lock.get("path")
        if not isinstance(path, str) or not path.startswith("requirements/immutable/"):
            _error(errors, f"{name}: dependency lock is outside the immutable lock directory")
        if not _is_raw_hash(lock.get("sha256")):
            _error(errors, f"{name}: dependency lock hash is invalid")
        artifacts = lock.get("artifacts")
        if not isinstance(artifacts, list):
            _error(errors, f"{name}: dependency lock artifacts are missing")
        else:
            for artifact in artifacts:
                artifact_map = _mapping(artifact)
                if artifact_map is None or not isinstance(artifact_map.get("name"), str) or not isinstance(artifact_map.get("version"), str) or not _is_raw_hash(artifact_map.get("sha256")):
                    _error(errors, f"{name}: dependency lock contains an invalid artifact")
    _verify_attestation(errors, name, "SBOM", item.get("sbom"), digest)
    _verify_attestation(errors, name, "provenance", item.get("provenance"), digest)
    tests = item.get("tests")
    if not isinstance(tests, list) or not tests:
        _error(errors, f"{name}: test receipt is missing")
    else:
        for receipt in tests:
            receipt_map = _mapping(receipt)
            if receipt_map is None or receipt_map.get("outcome") != "passed" or receipt_map.get("subject_digest") != digest or not isinstance(receipt_map.get("receipt"), str):
                _error(errors, f"{name}: test receipt does not prove this exact subject")
    return name


def _verify_external_subjects(errors: list[str], value: object) -> None:
    items = value if isinstance(value, list) else None
    if not items:
        _error(errors, "external subjects are missing")
        return
    found_hrh = False
    for item in items:
        record = _mapping(item)
        if record is None:
            _error(errors, "external subject is not an object")
            continue
        name = record.get("name")
        if name == "health-record-hub":
            found_hrh = True
        digest = record.get("digest")
        if not _is_digest(digest) or not isinstance(record.get("reference"), str) or not record["reference"].endswith("@" + str(digest)):
            _error(errors, f"external subject {name!r} must have an exact immutable reference")
        if record.get("verified") is not True:
            _error(errors, f"external subject {name!r} is unverified")
        if record.get("build_or_attestation_claimed") is not False:
            _error(errors, f"external subject {name!r} cannot be claimed as a candidate build or attestation")
    if not found_hrh:
        _error(errors, "health-record-hub external subject is missing")


def verify(manifest: object, *, require_external: bool = True) -> list[str]:
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
    if workflow is None or workflow.get("repository") != REPOSITORY or workflow.get("path") != WORKFLOW or not isinstance(workflow.get("run_url"), str):
        _error(errors, "workflow identity is incomplete or mismatched")
    listed_names: set[str] = set()
    subjects = root.get("subjects")
    if not isinstance(subjects, list):
        _error(errors, "subjects are missing")
    else:
        for subject in subjects:
            name = _verify_subject(errors, subject, source_revision)
            if name:
                if name in listed_names:
                    _error(errors, f"duplicate subject {name}")
                listed_names.add(name)
    if listed_names != SUBJECTS:
        _error(errors, f"subject set must be exactly {sorted(SUBJECTS)}")
    if require_external:
        _verify_external_subjects(errors, root.get("external_subjects"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--closed-subjects-only", action="store_true", help="verify the two built subjects before an external deployment frame is available")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"immutable candidate: unreadable manifest: {exc}", file=sys.stderr)
        return 2
    errors = verify(manifest, require_external=not args.closed_subjects_only)
    if errors:
        for error in errors:
            print("immutable candidate: FAIL: " + error, file=sys.stderr)
        return 1
    print("immutable candidate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
