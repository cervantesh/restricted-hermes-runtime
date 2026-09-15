"""The v3 candidate ledger carries its own receipt set, with provenance.

v2 pins one global receipt set, so every v2 ledger must retain exactly the same
two receipts. That was right while every retained receipt was pre-reconciliation
history, but it cannot express a receipt produced by executing the composed
cycle at a revision this candidate descends from.

A per-ledger set is only safe if every claim is gated on what the ledger
actually lists, so these contracts concentrate on exactly that: a claim must
never be assertable into existence, and a `candidate_ancestor` label must be
established from git rather than declared.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "reconciled_candidate_ledger_v3", ROOT / "tools" / "reconciled_candidate_ledger.py"
)
assert SPEC and SPEC.loader
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)

LEDGER_PATHS = (
    "docs/evidence/reconciled-cold-recovery-candidate-ledger-2026-09-15.json",
    "docs/evidence/reconciled-cold-recovery-candidate-ledger-2026-09-15-blocked.json",
)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()


def build(candidate: str | None = None) -> dict:
    return ledger.build_ledger_v3(
        repo_root=ROOT,
        candidate_revision=candidate or git("rev-parse", "HEAD"),
        extra_receipts=ledger.COLD_RECOVERY_RECEIPTS,
    )


def verify(value: dict) -> list[str]:
    return ledger.verify_ledger(ledger.canonical_bytes(value), repo_root=ROOT)


@pytest.fixture(scope="module")
def good() -> dict:
    return build()


def cold_entry(value: dict) -> dict:
    for item in value["retained_receipts"]:
        if item["schema"] == ledger.COLD_RECOVERY_SCHEMA:
            return item
    raise AssertionError("the cold-recovery receipt is not listed")


def test_v3_ledger_builds_and_verifies(good):
    assert good["schema"] == ledger.SCHEMA_V3
    assert verify(good) == []
    assert good["candidate"]["revision"] == git("rev-parse", "HEAD")
    assert good["historical_receipts_only"] is False
    assert cold_entry(good)["provenance"] == "candidate_ancestor"


def test_v3_keeps_every_escalated_claim_false(good):
    claims = good["claims"]
    assert claims["bounded_source_reconciliation"] is True
    assert claims["cold_recovery_replayed_on_candidate_ancestor"] is True
    for name in (
        "historical_receipts_are_candidate_evidence",
        "published_immutable_subjects_reverified",
        "representative_host_verified",
        "phi_authorized",
        "deployment_conformant",
    ):
        assert claims[name] is False, name


def test_v3_retains_the_v2_receipt_floor_as_historical(good):
    listed = {item["name"]: item for item in good["retained_receipts"]}
    for name, path, head, tree, schema in ledger.RECEIPTS:
        entry = listed[name]
        assert entry["provenance"] == "historical", name
        assert entry["path"] == path and entry["schema"] == schema
        assert entry["source"]["runtime_head"] == head
        assert entry["source"]["runtime_tree"] == tree


@pytest.mark.parametrize("name", ("clinical_egress", "clinical_composed"))
def test_v3_rejects_dropping_a_floor_receipt(good, name):
    value = copy.deepcopy(good)
    value["retained_receipts"] = [
        item for item in value["retained_receipts"] if item["name"] != name
    ]
    assert verify(value) == ["receipts"]


def test_v3_rejects_promoting_a_historical_receipt(good):
    value = copy.deepcopy(good)
    for item in value["retained_receipts"]:
        if item["name"] == "clinical_composed":
            item["provenance"] = "candidate_ancestor"
    assert verify(value) == ["receipts"]


def test_v3_rejects_a_candidate_that_does_not_descend_from_the_replay(good):
    """The whole meaning of `candidate_ancestor` is established, not declared."""
    replay_head = cold_entry(good)["source"]["runtime_head"]
    earlier = git("rev-parse", f"{replay_head}~1")
    value = copy.deepcopy(good)
    value["candidate"] = {
        "revision": earlier,
        "tree": git("rev-parse", f"{earlier}^{{tree}}"),
    }
    assert verify(value) == ["receipt-ancestry"]
    # The builder refuses the same thing rather than emitting it.
    with pytest.raises(ValueError, match="not a candidate ancestor"):
        build(earlier)


def test_v3_rejects_a_replay_claim_without_a_qualifying_receipt(good):
    value = copy.deepcopy(good)
    value["retained_receipts"] = [
        item
        for item in value["retained_receipts"]
        if item["schema"] != ledger.COLD_RECOVERY_SCHEMA
    ]
    value["historical_receipts_only"] = True
    # Claim retained, evidence removed.
    assert value["claims"]["cold_recovery_replayed_on_candidate_ancestor"] is True
    assert verify(value) == ["claims"]


def test_v3_rejects_an_inconsistent_provenance_summary(good):
    value = copy.deepcopy(good)
    value["historical_receipts_only"] = True
    assert verify(value) == ["provenance"]


def test_v3_rejects_a_tampered_receipt_hash(good):
    value = copy.deepcopy(good)
    cold_entry(value)["sha256"] = "f" * 64
    assert verify(value) == ["receipts"]


def test_v3_rejects_a_substituted_receipt_source(good):
    value = copy.deepcopy(good)
    entry = cold_entry(value)
    entry["source"] = dict(entry["source"], runtime_tree="0" * 40)
    assert verify(value) == ["receipts"]


def test_v3_rejects_a_foreign_hrh_frame(good):
    value = copy.deepcopy(good)
    entry = cold_entry(value)
    entry["source"] = dict(entry["source"], hrh_head="0" * 40)
    assert verify(value) == ["receipts"]


@pytest.mark.parametrize(
    "mutation",
    [
        {"representative_host_verified": True},
        {"phi_authorized": True},
        {"deployment_conformant": True},
        {"published_immutable_subjects_reverified": True},
        {"historical_receipts_are_candidate_evidence": True},
        {"bounded_source_reconciliation": False},
    ],
)
def test_v3_rejects_claim_escalation(good, mutation):
    value = copy.deepcopy(good)
    value["claims"] = {**value["claims"], **mutation}
    assert verify(value) == ["claims"]


def test_v3_rejects_an_unknown_or_missing_claim(good):
    value = copy.deepcopy(good)
    value["claims"] = {**value["claims"], "invented": True}
    assert verify(value) == ["claims"]
    value = copy.deepcopy(good)
    value["claims"].pop("phi_authorized")
    assert verify(value) == ["claims"]


def test_v3_rejects_a_source_line_outside_the_candidate(good):
    value = copy.deepcopy(good)
    value["required_source_lines"][0] = dict(
        value["required_source_lines"][0], tree="0" * 40
    )
    assert verify(value) == ["source-lines"]


def test_v2_ledgers_are_unaffected_by_the_v3_dispatch():
    """Adding v3 must not change how an existing v2 ledger verifies."""
    for name in (
        "reconciled-a0-candidate-ledger-2026-09-11.json",
        "p2-collector-candidate-ledger-2026-09-11.json",
    ):
        raw = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"HEAD:docs/evidence/{name}"],
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
        assert json.loads(raw)["schema"] == ledger.SCHEMA
        assert ledger.verify_ledger(raw, repo_root=ROOT) == [], name


@pytest.mark.parametrize("path", LEDGER_PATHS)
def test_retained_v3_ledger_verifies_and_names_its_preceding_candidate(path):
    """Each retained v3 ledger stays valid, including the superseded one."""
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:{path}"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if tracked.returncode:
        pytest.skip("the v3 ledger is not committed yet")
    raw = tracked.stdout
    assert ledger.verify_ledger(raw, repo_root=ROOT) == []
    value = json.loads(raw)
    ledger_commit = git("log", "-1", "--format=%H", "--", path)
    candidate = git("rev-parse", f"{ledger_commit}~1")
    assert value["candidate"] == {
        "revision": candidate,
        "tree": git("rev-parse", f"{candidate}^{{tree}}"),
    }
