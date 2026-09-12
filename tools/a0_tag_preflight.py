#!/usr/bin/env python3
"""Validate a proposed A0 immutable tag without publishing anything."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "restricted-runtime-a0-tag-preflight.v1"
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"immutable-candidate-\d{4}-\d{2}-\d{2}-([0-9a-f]{7,40})")
WORKFLOW = ".github/workflows/immutable-candidate.yml"
REQUIRED_PATHS = (
    "Dockerfile.mattermost-ingress",
    "Dockerfile.clinical-adapter",
    "tools/verify_immutable_candidate.py",
)


class Denied(ValueError):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def _run(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise Denied("candidate-binding")
    return result.stdout.strip()


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _source_revision(
    repo_root: Path, requested: str, expected_tree: str
) -> tuple[str, str]:
    revision = _run(repo_root, "rev-parse", "--verify", f"{requested}^{{commit}}")
    tree = _run(repo_root, "rev-parse", f"{revision}^{{tree}}")
    if (
        not SHA.fullmatch(revision)
        or not SHA.fullmatch(expected_tree)
        or tree != expected_tree
    ):
        raise Denied("candidate-binding")
    return revision, tree


def _validate_tag(repo_root: Path, tag: str, revision: str) -> None:
    match = TAG.fullmatch(tag)
    # A prefix relationship is not enough: a repository can eventually have
    # two commits sharing a seven-character prefix.  Bind to Git's current
    # unambiguous short form so the human-readable tag is itself a stable
    # subject identifier before the tag exists remotely.
    expected_short = _run(repo_root, "rev-parse", "--short=7", revision)
    if match is None or match.group(1) != expected_short:
        raise Denied("tag-shape")


def _candidate_has_a0_prerequisites(repo_root: Path, revision: str) -> None:
    try:
        workflow = _run(repo_root, "show", f"{revision}:{WORKFLOW}")
        for path in REQUIRED_PATHS:
            _run(repo_root, "cat-file", "-e", f"{revision}:{path}")
    except Denied:
        raise Denied("workflow-source") from None
    required_text = (
        "push:",
        "tags:",
        "immutable-candidate-*",
        "restricted-mattermost-ingress",
        "restricted-clinical-adapter",
        "--closed-subjects-only",
    )
    if not all(text in workflow for text in required_text):
        raise Denied("workflow-source")


def _remote_has_tag(repo_root: Path, remote: str, tag: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-remote",
            "--tags",
            "--refs",
            remote,
            f"refs/tags/{tag}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise Denied("preflight-generic")
    return bool(result.stdout.strip())


def build_receipt(
    *,
    repo_root: Path,
    candidate_revision: str,
    candidate_tree: str,
    tag: str,
    remote: str,
) -> dict[str, Any]:
    revision, tree = _source_revision(repo_root, candidate_revision, candidate_tree)
    _validate_tag(repo_root, tag, revision)
    _candidate_has_a0_prerequisites(repo_root, revision)
    if _remote_has_tag(repo_root, remote, tag):
        raise Denied("tag-exists")
    return {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "candidate": {"revision": revision, "tree": tree},
        "tag": tag,
        "remote": remote,
        "checks": {
            "candidate_binding": True,
            "workflow_source": True,
            "remote_tag_absent": True,
        },
        "claims": {
            "tag_created": False,
            "image_published": False,
            "a0_completed": False,
            "phi_authorized": False,
            "deployment_conformant": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-revision", required=True)
    parser.add_argument("--candidate-tree", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        receipt = build_receipt(
            repo_root=args.repo_root.resolve(),
            candidate_revision=args.candidate_revision,
            candidate_tree=args.candidate_tree,
            tag=args.tag,
            remote=args.remote,
        )
        _write_new(args.output, _canonical(receipt))
        print(
            "a0-tag-preflight: PASS sha256="
            + hashlib.sha256(_canonical(receipt)).hexdigest()
        )
        return 0
    except Denied as exc:
        print("a0-tag-preflight: DENIED class=" + exc.category)
        return 2
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print("a0-tag-preflight: DENIED class=preflight-generic")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
