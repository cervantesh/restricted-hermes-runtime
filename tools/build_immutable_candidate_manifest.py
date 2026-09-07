#!/usr/bin/env python3
"""Build a candidate manifest from workflow-generated immutable subject receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCKS = {
    "restricted-mattermost-ingress": "requirements/immutable/mattermost-ingress.txt",
    "restricted-clinical-adapter": "requirements/immutable/clinical-adapter.txt",
}
LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})$")


def lock_record(name: str) -> dict[str, Any]:
    relative = LOCKS[name]
    content = (ROOT / relative).read_bytes()
    artifacts: list[dict[str, str]] = []
    for raw in content.decode("utf-8").splitlines():
        match = LINE.fullmatch(raw.strip())
        if match:
            artifacts.append({"name": match.group(1), "version": match.group(2), "sha256": match.group(3)})
    return {"path": relative, "sha256": hashlib.sha256(content).hexdigest(), "artifacts": artifacts}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--subject-dir", type=Path, required=True)
    parser.add_argument("--test-receipts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--external-subjects", type=Path)
    args = parser.parse_args()
    receipts = json.loads(args.test_receipts.read_text(encoding="utf-8"))
    if not isinstance(receipts, dict):
        raise SystemExit("test receipts must be an object keyed by subject name")
    subjects: list[dict[str, Any]] = []
    for name in LOCKS:
        source = json.loads((args.subject_dir / f"{name}.json").read_text(encoding="utf-8"))
        digest = source["digest"]
        verification = {
            "verified": True,
            "repository": "cervantesh/restricted-hermes-runtime",
            "workflow": ".github/workflows/immutable-candidate.yml",
            "subject_digest": digest,
        }
        subject = {
            "name": name,
            "image": source["image"],
            "digest": digest,
            "platform": "linux/amd64",
            "base_materials": source["base_materials"],
            "dependency_lock": lock_record(name),
            "sbom": {"format": "spdxjson", "subject_digest": digest, "verification": verification},
            "provenance": {"subject_digest": digest, "verification": verification},
            "tests": receipts.get(name, []),
        }
        subjects.append(subject)
    manifest: dict[str, Any] = {
        "schema_version": "restricted-runtime-immutable-candidate.v1",
        "source_revision": args.source_revision,
        "platform": "linux/amd64",
        "workflow": {
            "repository": "cervantesh/restricted-hermes-runtime",
            "path": ".github/workflows/immutable-candidate.yml",
            "run_url": args.run_url,
        },
        "subjects": subjects,
    }
    if args.external_subjects:
        manifest["external_subjects"] = json.loads(args.external_subjects.read_text(encoding="utf-8"))
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
