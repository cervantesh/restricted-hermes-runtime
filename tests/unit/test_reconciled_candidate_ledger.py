from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RETAINED_A0_CANDIDATE = "49dca06b7a2e2b8134e2c4e426112e55fa73d0c3"
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


def test_ledger_can_be_retained_in_a_later_evidence_frame() -> None:
    """The evidence file need not exist in the tree of the code subject it binds."""
    candidate = git(ROOT, "rev-parse", RETAINED_A0_CANDIDATE)
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=candidate)
    assert value["candidate"]["revision"] == candidate
    assert ledger.verify_ledger(ledger.canonical_bytes(value), repo_root=ROOT) == []


@pytest.mark.parametrize(
    "name",
    (
        "reconciled-candidate-ledger-2026-09-11.json",
        "reconciled-a0-candidate-ledger-2026-09-11.json",
    ),
)
def test_retained_candidate_ledgers_verify_from_the_evidence_frame(name: str) -> None:
    raw = (ROOT / "docs" / "evidence" / name).read_bytes()
    assert ledger.verify_ledger(raw, repo_root=ROOT) == []


def test_receipt_hashes_bind_committed_git_bytes_not_worktree_line_endings() -> None:
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=RETAINED_A0_CANDIDATE)
    for receipt in value["retained_receipts"]:
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"HEAD:{receipt['path']}"],
            capture_output=True,
            check=True,
        ).stdout
        assert receipt["sha256"] == hashlib.sha256(tracked).hexdigest()


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


def test_candidate_ledger_rejects_fabricated_source_tree_or_hrh_frame() -> None:
    head = git(ROOT, "rev-parse", "HEAD")
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=head)
    changed_tree = copy.deepcopy(value)
    changed_tree["retained_receipts"][0]["source"]["runtime_tree"] = "0" * 40
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_tree), repo_root=ROOT) == ["receipts"]
    changed_hrh = copy.deepcopy(value)
    changed_hrh["retained_receipts"][1]["source"]["hrh_tree"] = "0" * 40
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_hrh), repo_root=ROOT) == ["receipts"]


def test_candidate_ledger_writer_never_replaces_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "ledger.json"
    output.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        ledger.write_new(output, b"new")
    assert output.read_bytes() == b"existing"


def test_contract_ci_keeps_history_required_for_ledger_ancestry() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    contracts = workflow.split("  synthetic-linux-e2e:", maxsplit=1)[0]
    assert "fetch-depth: 0" in contracts
