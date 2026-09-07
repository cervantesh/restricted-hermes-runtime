#!/usr/bin/env python3
"""Bind ``gh attestation verify --format=json`` output to one OCI subject."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _contains_subject(value: object, digest: str, predicate: str) -> bool:
    if isinstance(value, list):
        entries = value
    elif isinstance(value, dict) and isinstance(value.get("verificationResults"), list):
        entries = value["verificationResults"]
    elif isinstance(value, dict):
        entries = [value]
    else:
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        statement = entry.get("verificationResult", {}).get("statement", {})
        if not isinstance(statement, dict) or statement.get("predicateType") != predicate:
            continue
        for subject in statement.get("subject", []):
            if isinstance(subject, dict) and subject.get("digest", {}).get("sha256") == digest.removeprefix("sha256:"):
                return True
    return False


def _contains_revision(value: object, revision: str) -> bool:
    """SLSA layouts differ; only accept an attestation whose raw statement names SHA."""
    if value == revision:
        return True
    if isinstance(value, dict):
        return any(_contains_revision(child, revision) for child in value.values())
    if isinstance(value, list):
        return any(_contains_revision(child, revision) for child in value)
    return False


def _raw_ref(path: Path, root: Path) -> dict[str, str]:
    return {"raw_artifact": path.relative_to(root).as_posix(), "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--workflow-run-url", required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if "@" not in args.image:
        raise SystemExit("image must be digest-pinned")
    _, digest = args.image.rsplit("@", 1)
    if not DIGEST.fullmatch(digest):
        raise SystemExit("image digest is invalid")
    if not _contains_subject(_load(args.provenance), digest, "https://slsa.dev/provenance/v1"):
        raise SystemExit("provenance verification does not name the exact subject")
    if not _contains_subject(_load(args.sbom), digest, "https://spdx.dev/Document"):
        raise SystemExit("SPDX verification does not name the exact subject")
    provenance = _load(args.provenance)
    if not _contains_revision(provenance, args.source_revision):
        raise SystemExit("provenance verification does not name the expected source revision")
    root = args.output.parent.parent
    result: dict[str, Any] = {"schema_version": "restricted-runtime-attestation-receipt.v1", "image": args.image, "digest": digest, "source_revision": args.source_revision, "workflow_run_url": args.workflow_run_url, "provenance": {"predicate_type": "https://slsa.dev/provenance/v1", **_raw_ref(args.provenance, root)}, "sbom": {"predicate_type": "https://spdx.dev/Document", **_raw_ref(args.sbom, root)}}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
