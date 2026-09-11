from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("reconciled_candidate_ledger", ROOT / "tools" / "reconciled_candidate_ledger.py")
assert SPEC and SPEC.loader
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()


def test_current_candidate_ledger_verifies() -> None:
    head = git(ROOT, "rev-parse", "HEAD")
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=head)
    assert ledger.verify_ledger(ledger.canonical_bytes(value), repo_root=ROOT) == []


def test_candidate_ledger_rejects_source_line_not_in_candidate() -> None:
    head = git(ROOT, "rev-parse", "HEAD")
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=head)
    changed = copy.deepcopy(value)
    changed["required_source_lines"][0]["revision"] = "0" * 40
    assert ledger.verify_ledger(ledger.canonical_bytes(changed), repo_root=ROOT) == ["source-lines"]


def test_candidate_ledger_rejects_retained_receipt_hash_or_claim_escalation() -> None:
    head = git(ROOT, "rev-parse", "HEAD")
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=head)
    changed_hash = copy.deepcopy(value)
    changed_hash["retained_receipts"][0]["sha256"] = "0" * 64
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_hash), repo_root=ROOT) == ["receipts"]
    changed_claim = copy.deepcopy(value)
    changed_claim["claims"]["phi_authorized"] = True
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_claim), repo_root=ROOT) == ["claims"]
