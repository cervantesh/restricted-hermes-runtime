#!/usr/bin/env python3
"""Build and verify the bounded source ledger for the reconciled candidate.

The ledger deliberately proves a narrow claim: the named candidate descends
from the required control lines and the retained synthetic receipts name
intermediate source frames that are ancestors of that candidate.  It does not
turn locally-built images into published immutable subjects, and it does not
make any host, PHI, or deployment-conformance claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "restricted-runtime-reconciled-candidate-ledger.v1"
SHA = re.compile(r"[0-9a-f]{40}")
RAW_SHA = re.compile(r"[0-9a-f]{64}")
SOURCE_KEYS = {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}
PRODUCT_SHA = "c0fc85d894700823deb92a085d36291589160028"
REQUIRED_LINES = (
    ("immutable_candidate_base", "76cf83e9cbb75e614f0394ed26886b25c25177ec"),
    ("lifecycle_serialization", "a14e864fb2c944dc27b0a888a2523b07a79dd5f2"),
    ("delivery_reauthorization", "ef62f29ddbd0d016d969f391e03f76e421b2fe75"),
    ("source_frame", "f6723c5d45b1800324dc2fb2bfac9b7bf5887def"),
    ("initialization_recovery", "d22f3a8dd81576b0cf5ad198d768618102b0e66f"),
    ("staging_compose_seal", "f0b0d73da3587e47cb5e78f66128d0f4478ff0cd"),
    ("composed_compose_seal", "efcc2e0b04a5b59c9a9c51c95d4505636363e1bb"),
)
RECEIPTS = (
    ("clinical_egress", "docs/evidence/clinical-egress-wsl-receipt-2026-09-11.json", "29c321cb06076e935833e01e7b7d4f70d6bf7c10", "565e2198d09f5a046a91b77ebe4c2a95f3351b2f", "restricted-runtime-clinical-egress-witness.v1"),
    ("clinical_composed", "docs/evidence/clinical-composed-receipt-2026-09-11.json", "14793b98d310fab44ef4bc22086c55039e279d46", "cc83f7c4cad7e6f4da063c4ce9fcc90ad90bce19", "restricted-runtime-composed-e2e-receipt.v1"),
)
FROZEN_HRH_SOURCE = {
    "hrh_head": "ad13735e9881a48580a9e138daac137f8c865dea",
    "hrh_tree": "f217b0b1cf7f438422528dfe178d81b78212c68b",
}


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise ValueError("git " + " ".join(args) + " failed")
    return result.stdout.strip()


def _git_bytes(repo_root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, check=False, timeout=30)
    if result.returncode:
        raise ValueError("git " + " ".join(args) + " failed")
    return result.stdout


def _tree(repo_root: Path, revision: str) -> str:
    return _git(repo_root, "rev-parse", f"{revision}^{{tree}}")


def _ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True, text=True, check=False, timeout=30,
    ).returncode == 0


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _read_json_bytes(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _source(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != SOURCE_KEYS:
        return None
    if not all(isinstance(item, str) and SHA.fullmatch(item) for item in value.values()):
        return None
    return dict(value)


def _receipt_source(value: dict[str, Any]) -> dict[str, str] | None:
    """Extract the source frame without pretending both receipt schemas match."""
    if value.get("schema") == "restricted-runtime-clinical-egress-witness.v1":
        candidate = value.get("candidate_receipt")
        return _source(candidate.get("source")) if isinstance(candidate, dict) else None
    return _source(value.get("source"))


def build_ledger(*, repo_root: Path, candidate_revision: str) -> dict[str, Any]:
    candidate_revision = _git(repo_root, "rev-parse", "--verify", f"{candidate_revision}^{{commit}}")
    candidate_tree = _tree(repo_root, candidate_revision)
    source_lines = [
        {"name": name, "revision": revision, "tree": _tree(repo_root, revision)}
        for name, revision in REQUIRED_LINES
    ]
    receipts: list[dict[str, Any]] = []
    for name, relative, runtime_head, runtime_tree, _schema in RECEIPTS:
        tracked = _git_bytes(repo_root, "show", f"HEAD:{relative}")
        value = _read_json_bytes(tracked)
        source = _receipt_source(value) if value else None
        if source is None or source["runtime_head"] != runtime_head or source["runtime_tree"] != runtime_tree or any(source[key] != expected for key, expected in FROZEN_HRH_SOURCE.items()):
            raise ValueError(f"{name}: retained receipt has unexpected source")
        receipts.append({
            "name": name, "path": relative, "sha256": _sha_bytes(tracked),
            "source": source,
        })
    return {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "candidate": {"revision": candidate_revision, "tree": candidate_tree},
        "required_source_lines": source_lines,
        "retained_receipts": receipts,
        "claims": {
            "bounded_source_reconciliation": True,
            "published_immutable_subjects_reverified": False,
            "representative_host_verified": False,
            "phi_authorized": False,
            "deployment_conformant": False,
        },
    }


def _canonical(raw: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        return None
    return value


def verify_ledger(raw: bytes, *, repo_root: Path) -> list[str]:
    value = _canonical(raw)
    if value is None:
        return ["canonical"]
    required_fields = {"schema", "synthetic_non_phi_only", "candidate", "required_source_lines", "retained_receipts", "claims"}
    if set(value) != required_fields or value.get("schema") != SCHEMA or value.get("synthetic_non_phi_only") is not True:
        return ["schema"]
    candidate = value.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {"revision", "tree"} or not isinstance(candidate["revision"], str) or not SHA.fullmatch(candidate["revision"]) or not isinstance(candidate["tree"], str) or not SHA.fullmatch(candidate["tree"]):
        return ["candidate"]
    try:
        if _tree(repo_root, candidate["revision"]) != candidate["tree"]:
            return ["candidate-tree"]
    except ValueError:
        return ["candidate-revision"]
    lines = value.get("required_source_lines")
    if not isinstance(lines, list) or len(lines) != len(REQUIRED_LINES):
        return ["source-lines"]
    expected_lines = {name: revision for name, revision in REQUIRED_LINES}
    seen: set[str] = set()
    for item in lines:
        if not isinstance(item, dict) or set(item) != {"name", "revision", "tree"} or not isinstance(item.get("name"), str):
            return ["source-lines"]
        name = item["name"]
        if name in seen or expected_lines.get(name) != item.get("revision") or not isinstance(item.get("tree"), str) or not SHA.fullmatch(item["tree"]):
            return ["source-lines"]
        seen.add(name)
        try:
            if _tree(repo_root, item["revision"]) != item["tree"] or not _ancestor(repo_root, item["revision"], candidate["revision"]):
                return ["source-lines"]
        except ValueError:
            return ["source-lines"]
    if seen != set(expected_lines):
        return ["source-lines"]
    receipts = value.get("retained_receipts")
    if not isinstance(receipts, list) or len(receipts) != len(RECEIPTS):
        return ["receipts"]
    expected_receipts = {name: (path, head, tree, schema) for name, path, head, tree, schema in RECEIPTS}
    seen_receipts: set[str] = set()
    for item in receipts:
        if not isinstance(item, dict) or set(item) != {"name", "path", "sha256", "source"} or not isinstance(item.get("name"), str):
            return ["receipts"]
        name = item["name"]
        expected = expected_receipts.get(name)
        source = _source(item.get("source"))
        if name in seen_receipts or expected is None or item.get("path") != expected[0] or not isinstance(item.get("sha256"), str) or not RAW_SHA.fullmatch(item["sha256"]) or source is None or source["runtime_head"] != expected[1] or source["runtime_tree"] != expected[2] or any(source[key] != expected_value for key, expected_value in FROZEN_HRH_SOURCE.items()):
            return ["receipts"]
        try:
            tracked = _git_bytes(repo_root, "show", f"HEAD:{item['path']}")
        except ValueError:
            return ["receipts"]
        retained = _read_json_bytes(tracked)
        if _sha_bytes(tracked) != item["sha256"] or retained is None or retained.get("schema") != expected[3] or _receipt_source(retained) != source:
            return ["receipts"]
        try:
            if _tree(repo_root, source["runtime_head"]) != source["runtime_tree"] or not _ancestor(repo_root, PRODUCT_SHA, source["runtime_head"]) or not _ancestor(repo_root, source["runtime_head"], candidate["revision"]):
                return ["receipts"]
        except ValueError:
            return ["receipts"]
        seen_receipts.add(name)
    if seen_receipts != set(expected_receipts):
        return ["receipts"]
    claims = value.get("claims")
    expected_claims = {
        "bounded_source_reconciliation": True,
        "published_immutable_subjects_reverified": False,
        "representative_host_verified": False,
        "phi_authorized": False,
        "deployment_conformant": False,
    }
    if claims != expected_claims:
        return ["claims"]
    return []


def write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # link() is an atomic create-if-absent operation: unlike exists()+replace(),
        # it cannot replace a file created by another writer after our check.
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-revision")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    if bool(args.output) == bool(args.verify):
        parser.error("choose exactly one of --output or --verify")
    try:
        if args.verify:
            errors = verify_ledger(args.verify.read_bytes(), repo_root=repo_root)
            if errors:
                print("candidate ledger: FAIL: " + ", ".join(errors))
                return 1
            print("candidate ledger: PASS")
            return 0
        if not args.candidate_revision:
            parser.error("--candidate-revision is required with --output")
        ledger = build_ledger(repo_root=repo_root, candidate_revision=args.candidate_revision)
        write_new(args.output, canonical_bytes(ledger))
        print("candidate ledger: wrote " + str(args.output))
        return 0
    except (OSError, ValueError) as exc:
        print("candidate ledger: FAIL: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
