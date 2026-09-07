#!/usr/bin/env python3
"""Pull and record an exact OCI subject's linux/amd64 resolution and labels."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"sha256:[0-9a-f]{64}$")
SOURCE = "https://github.com/cervantesh/restricted-hermes-runtime"


def _run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--workflow-run-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if "@" not in args.image:
        raise SystemExit("image must be digest-pinned")
    _, digest = args.image.rsplit("@", 1)
    if not DIGEST.fullmatch(digest):
        raise SystemExit("image digest is invalid")
    _run("docker", "pull", args.image)
    inspect = json.loads(_run("docker", "image", "inspect", args.image))[0]
    labels = inspect.get("Config", {}).get("Labels", {}) or {}
    if inspect.get("Os") != "linux" or inspect.get("Architecture") != "amd64":
        raise SystemExit("pulled subject is not linux/amd64")
    if labels.get("org.opencontainers.image.source") != SOURCE or labels.get("org.opencontainers.image.revision") != args.source_revision:
        raise SystemExit("pulled subject labels do not bind the expected source revision")
    raw = json.loads(_run("docker", "buildx", "imagetools", "inspect", "--raw", args.image))
    manifests = raw.get("manifests") if isinstance(raw, dict) else None
    if isinstance(manifests, list):
        child = next((m.get("digest") for m in manifests if isinstance(m, dict) and m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"), None)
        if not isinstance(child, str) or not DIGEST.fullmatch(child):
            raise SystemExit("OCI index has no linux/amd64 child")
        kind = "index"
    else:
        child, kind = digest, "manifest"
    result: dict[str, Any] = {"schema_version": "restricted-runtime-subject-receipt.v1", "image": args.image, "subject_digest": digest, "source_revision": args.source_revision, "workflow_run_url": args.workflow_run_url, "resolved_platform": "linux/amd64", "subject_kind": kind, "linux_amd64_child_digest": child, "source": SOURCE, "labels": {"org.opencontainers.image.source": labels.get("org.opencontainers.image.source"), "org.opencontainers.image.revision": labels.get("org.opencontainers.image.revision")}}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
