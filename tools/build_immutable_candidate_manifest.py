#!/usr/bin/env python3
"""Build a manifest only from hashed, workflow-produced verification receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCKS = {"restricted-mattermost-ingress": "requirements/immutable/mattermost-ingress.txt", "restricted-clinical-adapter": "requirements/immutable/clinical-adapter.txt"}
LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})$")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected object")
    return value


def _load_list(path: Path) -> list[Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise SystemExit(f"{path}: expected list")
    return value


def lock_record(name: str, repo_root: Path) -> dict[str, Any]:
    relative = LOCKS[name]
    content = (repo_root / relative).read_bytes()
    artifacts = []
    for raw in content.decode("utf-8").splitlines():
        match = LINE.fullmatch(raw.strip())
        if match:
            artifacts.append({"name": match.group(1), "version": match.group(2), "sha256": match.group(3)})
    return {"path": relative, "sha256": hashlib.sha256(content).hexdigest(), "artifacts": artifacts}


def _at_root(repo_root: Path, path: Path) -> Path:
    root = repo_root.resolve()
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not resolved.is_relative_to(root):
        raise SystemExit(f"candidate evidence path escapes repository root: {path}")
    return resolved


def _reference(path: Path, repo_root: Path) -> dict[str, str]:
    resolved = _at_root(repo_root, path)
    return {"receipt": resolved.relative_to(repo_root.resolve()).as_posix(), "receipt_sha256": _sha(resolved)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--subject-dir", type=Path, required=True)
    parser.add_argument("--test-receipts", type=Path, required=True)
    parser.add_argument("--verification-dir", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--external-subjects", type=Path)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    subject_dir = _at_root(repo_root, args.subject_dir)
    verification_dir = _at_root(repo_root, args.verification_dir)
    receipts = _load(_at_root(repo_root, args.test_receipts))
    evidence = _load(_at_root(repo_root, args.evidence))
    if (evidence.get("source_revision") != args.source_revision or evidence.get("workflow_run_url") != args.run_url
            or evidence.get("phi_authorized") is not False or evidence.get("deployment_conformant") is not False):
        raise SystemExit("candidate evidence is not bound or contains an authorization/conformance claim")
    subjects: list[dict[str, Any]] = []
    for name in LOCKS:
        source = _load(subject_dir / f"{name}.json")
        digest = source.get("digest")
        image = source.get("image")
        attestation_path = verification_dir / f"{name}.attestations.json"
        platform_path = verification_dir / f"{name}.platform.json"
        attestation = _load(attestation_path)
        platform = _load(platform_path)
        provenance = attestation.get("provenance") if isinstance(attestation.get("provenance"), dict) else {}
        sbom = attestation.get("sbom") if isinstance(attestation.get("sbom"), dict) else {}
        if (attestation.get("image") != image or attestation.get("digest") != digest
                or attestation.get("source_revision") != args.source_revision or attestation.get("workflow_run_url") != args.run_url
                or platform.get("image") != image or platform.get("subject_digest") != digest
                or platform.get("source_revision") != args.source_revision or platform.get("workflow_run_url") != args.run_url
                or provenance.get("predicate_type") != "https://slsa.dev/provenance/v1"
                or sbom.get("predicate_type") != "https://spdx.dev/Document/v2.3"
                or provenance.get("raw_artifact") == sbom.get("raw_artifact")):
            raise SystemExit(f"{name}: verification receipt is not bound to the published subject")
        attestation_ref = _reference(attestation_path, repo_root)
        platform_ref = _reference(platform_path, repo_root)
        subjects.append({
            "name": name, "image": image, "digest": digest, "platform": "linux/amd64",
            "base_materials": source["base_materials"], "dependency_lock": lock_record(name, repo_root),
            "sbom": {"format": "spdxjson", "subject_digest": digest, "verification": {**attestation_ref, "subject_digest": digest, "source_revision": args.source_revision, "workflow_run_url": args.run_url, "predicate_type": "https://spdx.dev/Document/v2.3"}},
            "provenance": {"subject_digest": digest, "verification": {**attestation_ref, "subject_digest": digest, "source_revision": args.source_revision, "workflow_run_url": args.run_url, "predicate_type": "https://slsa.dev/provenance/v1"}},
            "platform_receipt": platform_ref, "tests": receipts.get(name, []),
        })
    manifest: dict[str, Any] = {"schema_version": "restricted-runtime-immutable-candidate.v1", "source_revision": args.source_revision, "platform": "linux/amd64", "workflow": {"repository": "cervantesh/restricted-hermes-runtime", "path": ".github/workflows/immutable-candidate.yml", "run_url": args.run_url}, "subjects": subjects, "evidence": evidence}
    if args.external_subjects:
        manifest["external_subjects"] = _load_list(_at_root(repo_root, args.external_subjects))
    _at_root(repo_root, args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
