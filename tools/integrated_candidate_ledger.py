#!/usr/bin/env python3
"""Build and verify a source-bound ledger for a fresh integrated candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "restricted-runtime-integrated-candidate-ledger.v2"
SHA = re.compile(r"[0-9a-f]{40}")
RAW_SHA = re.compile(r"[0-9a-f]{64}")
SOURCE_KEYS = {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}
CLAIMS = {
    "bounded_source_reconciliation": True,
    "historical_receipts_are_candidate_evidence": False,
    "published_immutable_subjects_reverified": False,
    "representative_host_verified": False,
    "phi_authorized": False,
    "deployment_conformant": False,
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
    return subprocess.run(["git", "-C", str(repo_root), "merge-base", "--is-ancestor", ancestor, descendant], capture_output=True, check=False, timeout=30).returncode == 0


def _source(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != SOURCE_KEYS:
        return None
    if not all(isinstance(item, str) and SHA.fullmatch(item) for item in value.values()):
        return None
    return dict(value)


def _receipt(value: object, *, expected_schema: str) -> dict[str, str] | None:
    if not isinstance(value, dict) or value.get("schema") != expected_schema:
        return None
    return _source({key: value.get(key) for key in SOURCE_KEYS})


def _descriptor(name: str, path: str, schema: str) -> dict[str, str]:
    if not name or not schema or not path or Path(path).is_absolute() or "\\" in path:
        raise ValueError("invalid receipt descriptor")
    return {"name": name, "path": path, "schema": schema}


def build_ledger(*, repo_root: Path, candidate_revision: str, required_source_lines: Sequence[tuple[str, str]], receipts: Sequence[tuple[str, str, str]]) -> dict[str, Any]:
    candidate_revision = _git(repo_root, "rev-parse", "--verify", f"{candidate_revision}^{{commit}}")
    candidate_tree = _tree(repo_root, candidate_revision)
    source_lines = []
    for name, revision in required_source_lines:
        revision = _git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}")
        source_lines.append({"name": name, "revision": revision, "tree": _tree(repo_root, revision)})
    retained = []
    for name, path, schema in receipts:
        descriptor = _descriptor(name, path, schema)
        raw = _git_bytes(repo_root, "show", f"{candidate_revision}:{path}")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{name}: retained receipt is unreadable") from exc
        source = _receipt(value, expected_schema=schema)
        if source is None:
            raise ValueError(f"{name}: retained receipt has unexpected source")
        retained.append({**descriptor, "sha256": hashlib.sha256(raw).hexdigest(), "source": source})
    ledger = {
        "schema": SCHEMA,
        "synthetic_non_phi_only": True,
        "candidate": {"revision": candidate_revision, "tree": candidate_tree},
        "required_source_lines": source_lines,
        "retained_receipts": retained,
        "historical_receipts_only": True,
        "claims": CLAIMS,
    }
    errors = verify_ledger(canonical_bytes(ledger), repo_root=repo_root)
    if errors:
        raise ValueError("ledger would not verify: " + ",".join(errors))
    return ledger


def verify_ledger(raw: bytes, *, repo_root: Path) -> list[str]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return ["json"]
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        return ["canonical"]
    required = {"schema", "synthetic_non_phi_only", "candidate", "required_source_lines", "retained_receipts", "historical_receipts_only", "claims"}
    if set(value) != required or value.get("schema") != SCHEMA or value.get("synthetic_non_phi_only") is not True or value.get("historical_receipts_only") is not True:
        return ["schema"]
    if value.get("claims") != CLAIMS:
        return ["claims"]
    candidate = value.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {"revision", "tree"} or not all(isinstance(candidate.get(key), str) and SHA.fullmatch(candidate[key]) for key in candidate):
        return ["candidate"]
    try:
        if _tree(repo_root, candidate["revision"]) != candidate["tree"]:
            return ["candidate"]
    except ValueError:
        return ["candidate"]
    lines = value.get("required_source_lines")
    if not isinstance(lines, list) or len({item.get("name") for item in lines if isinstance(item, dict)}) != len(lines):
        return ["source-lines"]
    for item in lines:
        if not isinstance(item, dict) or set(item) != {"name", "revision", "tree"} or not isinstance(item["name"], str) or not all(isinstance(item[key], str) and SHA.fullmatch(item[key]) for key in ("revision", "tree")):
            return ["source-lines"]
        try:
            if _tree(repo_root, item["revision"]) != item["tree"] or not _ancestor(repo_root, item["revision"], candidate["revision"]):
                return ["source-lines"]
        except ValueError:
            return ["source-lines"]
    receipts = value.get("retained_receipts")
    if not isinstance(receipts, list) or not receipts:
        return ["receipts"]
    names: set[str] = set()
    paths: set[str] = set()
    for item in receipts:
        if not isinstance(item, dict) or set(item) != {"name", "path", "schema", "sha256", "source"}:
            return ["receipts"]
        try:
            descriptor = _descriptor(item["name"], item["path"], item["schema"])
        except (TypeError, ValueError):
            return ["receipts"]
        if descriptor["name"] in names or descriptor["path"] in paths or not isinstance(item["sha256"], str) or not RAW_SHA.fullmatch(item["sha256"]):
            return ["receipts"]
        names.add(descriptor["name"]); paths.add(descriptor["path"])
        source = _source(item["source"])
        if source is None:
            return ["receipts"]
        try:
            tracked = _git_bytes(repo_root, "show", f"{candidate['revision']}:{descriptor['path']}")
            receipt_value = json.loads(tracked.decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return ["receipts"]
        if hashlib.sha256(tracked).hexdigest() != item["sha256"] or _receipt(receipt_value, expected_schema=descriptor["schema"]) != source:
            return ["receipts"]
        # Receipt source is historical provenance. Only declared control lines
        # establish candidate ancestry; receipt ancestry cannot prove that this
        # exact candidate was executed.
    return []


def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # Atomic create-if-absent. Unlike exists()+replace(), a concurrent
        # writer cannot be replaced between a check and publication.
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink()


def _parse_source_line(value: str) -> tuple[str, str]:
    name, separator, revision = value.partition("=")
    if not separator or not name or not SHA.fullmatch(revision):
        raise argparse.ArgumentTypeError("source line must be NAME=40-hex-revision")
    return name, revision


def _parse_receipt(value: str) -> tuple[str, str, str]:
    name, separator, rest = value.partition("=")
    path, separator2, schema = rest.partition(",")
    if not separator or not separator2:
        raise argparse.ArgumentTypeError("receipt must be NAME=relative-path,schema")
    try:
        _descriptor(name, path, schema)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("receipt descriptor is invalid") from exc
    return name, path, schema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--candidate-revision")
    parser.add_argument("--required-source-line", type=_parse_source_line, action="append", default=[])
    parser.add_argument("--receipt", type=_parse_receipt, action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    options = parser.parse_args()
    if options.verify is not None:
        errors = verify_ledger(options.verify.read_bytes(), repo_root=options.repo_root)
        print("integrated candidate ledger: " + ("PASS" if not errors else "FAIL: " + ",".join(errors)))
        raise SystemExit(bool(errors))
    if not options.candidate_revision or not options.output or not options.receipt:
        parser.error("build requires --candidate-revision, --receipt, and --output")
    value = build_ledger(repo_root=options.repo_root, candidate_revision=options.candidate_revision, required_source_lines=options.required_source_line, receipts=options.receipt)
    write_new(options.output, canonical_bytes(value))


if __name__ == "__main__":
    main()
