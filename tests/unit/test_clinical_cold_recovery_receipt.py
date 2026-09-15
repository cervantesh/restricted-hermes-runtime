"""The retained composed cold-recovery receipt must stay bounded and truthful.

This receipt is the only artifact in the repository produced by a real
backup -> destroy -> restore cycle against live Docker. These contracts keep it
from drifting into a claim it does not support, and bind it to a revision that
is actually in this candidate's ancestry.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RECEIPT = ROOT / "docs" / "evidence" / "clinical-cold-recovery-receipt-2026-09-15.json"
STAGING = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
FROZEN_HRH = {
    "hrh_head": "ad13735e9881a48580a9e138daac137f8c865dea",
    "hrh_tree": "f217b0b1cf7f438422528dfe178d81b78212c68b",
}


def load_staging():
    spec = importlib.util.spec_from_file_location("clinical_staging_receipt", STAGING)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def raw() -> bytes:
    return RECEIPT.read_bytes()


@pytest.fixture(scope="module")
def receipt(raw: bytes) -> dict:
    return json.loads(raw.decode("utf-8"))


def git(*args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(ROOT), *args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.returncode}")
    return result.stdout.strip()


def test_receipt_is_canonical_and_bounded(receipt, raw):
    module = load_staging()
    assert receipt["schema"] == module.BACKUP_SCHEMA
    assert receipt["synthetic_only"] is True
    # Compare against normalized bytes: this repository checks out with
    # autocrlf on some hosts, and the committed object -- not the worktree
    # copy -- is what a ledger would ever hash.
    canonical = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
    assert raw.replace(b"\r\n", b"\n") == canonical
    for nonclaim in (
        "not PHI",
        "not production",
        "not a representative host",
        "not a compliance certification",
    ):
        assert nonclaim in receipt["nonclaims"], nonclaim


def test_receipt_records_both_distinct_terminal_delivery_contracts(receipt):
    deleted = receipt["source_deletion_after"]
    unknown = receipt["unknown_delivery_after"]
    assert deleted["state"] == unknown["state"] == "AMBIGUOUS"
    # The reconciliation had to keep these apart, not collapse them.
    assert deleted["reason"] == "delivery_authorization_unknown"
    assert unknown["reason"] == "restart_in_flight"
    assert deleted["record_tag"] != unknown["record_tag"]
    for before_key, after in (
        ("source_deletion_before", deleted),
        ("unknown_delivery_before", unknown),
    ):
        before = receipt[before_key]
        assert before["state"] == "IN_FLIGHT"
        assert before["nonce_erased"] is False and before["ciphertext_erased"] is False
        assert after["nonce_erased"] is True and after["ciphertext_erased"] is True
        assert after["generation"] == before["generation"] + 1
        assert after["record_tag"] == before["record_tag"]
    assert receipt["delivered_count_before_after"] == 1


def test_receipt_reports_the_recomposed_controls(receipt):
    module = load_staging()
    assert receipt["restored_tls_probe"]["verified"] is True
    assert receipt["restored_tls_probe"]["hostname"] == "127.0.0.1"
    assert re.fullmatch("[a-f0-9]{64}", receipt["restored_policy_digest"])
    images = receipt["restored_built_images"]
    assert set(images) == set(module.LONG_RUNNING_SERVICES)
    for name, digest in images.items():
        assert re.fullmatch(r"sha256:[a-f0-9]{64}", digest), name
    assert re.fullmatch("[a-f0-9]{64}", receipt["manifest_sha256"])


def test_receipt_claims_only_the_mode_it_actually_ran(receipt):
    # The published immutable-subject manifest names a different revision, so
    # this replay ran in exact-source mode.  The receipt must say so rather
    # than imply a subject-admitted run.
    assert receipt["subject_admitted"] is False
    assert receipt["elapsed_seconds"] > 0
    assert receipt["project"].startswith("clinicalstagingrecovery")


def test_receipt_carries_no_fixture_content_or_private_path(raw):
    text = raw.decode("utf-8")
    for token in (
        "cold-already-delivered",
        "cold-unknown",
        "cold-source-deleted",
        "cold-allowed",
        "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1",
        "password",
        "/tmp/",
        "seed",
    ):
        assert token not in text, token


def test_receipt_binds_the_frozen_hrh_source_and_a_real_ancestor(receipt):
    source = receipt["source"]
    assert set(source) == {"runtime_head", "runtime_tree", "hrh_head", "hrh_tree"}
    for key, value in FROZEN_HRH.items():
        assert source[key] == value, key
    # The replay must name a revision this candidate actually descends from,
    # and the tree it names must be that revision's real tree.
    assert (
        git("rev-parse", f"{source['runtime_head']}^{{tree}}") == source["runtime_tree"]
    )
    git("merge-base", "--is-ancestor", source["runtime_head"], "HEAD")


def test_receipt_bytes_match_the_committed_object(raw):
    tracked = subprocess.run(
        ("git", "-C", str(ROOT), "show", f"HEAD:docs/evidence/{RECEIPT.name}"),
        capture_output=True,
        timeout=30,
        check=False,
    )
    if tracked.returncode:
        pytest.skip("receipt is not committed yet")
    assert hashlib.sha256(tracked.stdout).hexdigest() == hashlib.sha256(raw).hexdigest()
