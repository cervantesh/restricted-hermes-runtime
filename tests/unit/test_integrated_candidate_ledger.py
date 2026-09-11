from __future__ import annotations

import copy
import hashlib
import importlib.util
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RECEIPT = "docs/evidence/clinical-composed-receipt-2026-09-11-integrated.json"
SPEC = importlib.util.spec_from_file_location("integrated_candidate_ledger", ROOT / "tools" / "integrated_candidate_ledger.py")
assert SPEC and SPEC.loader
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()


def build() -> dict:
    head = git("rev-parse", "HEAD")
    receipt_head = git("log", "-1", "--format=%H", "--", RECEIPT)
    return ledger.build_ledger(
        repo_root=ROOT,
        candidate_revision=head,
        required_source_lines=[("receipt-producer", receipt_head)],
        receipts=[("clinical-composed", RECEIPT, "restricted-runtime-composed-e2e-receipt.v1")],
    )


def test_fresh_integrated_ledger_verifies_and_hashes_committed_receipt_bytes() -> None:
    value = build()
    assert ledger.verify_ledger(ledger.canonical_bytes(value), repo_root=ROOT) == []
    tracked = subprocess.run(["git", "-C", str(ROOT), "show", f"HEAD:{RECEIPT}"], capture_output=True, check=True).stdout
    assert value["retained_receipts"][0]["sha256"] == hashlib.sha256(tracked).hexdigest()


def test_integrated_ledger_rejects_source_or_receipt_tampering() -> None:
    value = build()
    changed_line = copy.deepcopy(value)
    changed_line["required_source_lines"][0]["revision"] = "0" * 40
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_line), repo_root=ROOT) == ["source-lines"]
    changed_receipt = copy.deepcopy(value)
    changed_receipt["retained_receipts"][0]["sha256"] = "0" * 64
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_receipt), repo_root=ROOT) == ["receipts"]
    changed_claim = copy.deepcopy(value)
    changed_claim["claims"]["phi_authorized"] = True
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_claim), repo_root=ROOT) == ["claims"]
    changed_scope = copy.deepcopy(value)
    changed_scope["claims"]["historical_receipts_are_candidate_evidence"] = True
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_scope), repo_root=ROOT) == ["claims"]


def test_integrated_ledger_writer_never_replaces_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "ledger.json"
    output.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        ledger.write_new(output, b"new")
    assert output.read_bytes() == b"existing"


def test_integrated_ledger_writer_never_replaces_concurrent_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "ledger.json"
    original_link = ledger.os.link

    def competing_link(source: Path, destination: Path) -> None:
        output.write_bytes(b"concurrent")
        original_link(source, destination)

    monkeypatch.setattr(ledger.os, "link", competing_link)
    with pytest.raises(FileExistsError):
        ledger.write_new(output, b"new")
    assert output.read_bytes() == b"concurrent"
