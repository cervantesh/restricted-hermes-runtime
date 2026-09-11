from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


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


def test_ledger_can_be_retained_in_a_later_evidence_frame() -> None:
    """The evidence file need not exist in the tree of the code subject it binds."""
    candidate = git(ROOT, "rev-parse", "HEAD~1")
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=candidate)
    assert value["candidate"]["revision"] == candidate
    assert ledger.verify_ledger(ledger.canonical_bytes(value), repo_root=ROOT) == []


@pytest.mark.parametrize(
    "name",
    (
        "reconciled-a0-candidate-ledger-2026-09-11.json",
        "p2-collector-candidate-ledger-2026-09-11.json",
        "p2-admission-candidate-ledger-2026-09-11.json",
    ),
)
def test_retained_candidate_ledgers_verify_from_the_evidence_frame(name: str) -> None:
    raw = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:docs/evidence/{name}"],
        capture_output=True,
        check=True,
    ).stdout
    assert ledger.verify_ledger(raw, repo_root=ROOT) == []


@pytest.mark.parametrize(
    "name",
    (
        "p2-collector-candidate-ledger-2026-09-11.json",
        "p2-admission-candidate-ledger-2026-09-11.json",
    ),
)
def test_p2_candidate_ledgers_name_their_immediately_preceding_candidate_subject(name: str) -> None:
    path = "docs/evidence/" + name
    raw = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:{path}"],
        capture_output=True,
        check=True,
    ).stdout
    value = json.loads(raw)
    ledger_commit = git(ROOT, "log", "-1", "--format=%H", "--", path)
    candidate = git(ROOT, "rev-parse", f"{ledger_commit}~1")

    assert value["candidate"] == {
        "revision": candidate,
        "tree": git(ROOT, "rev-parse", f"{candidate}^{{tree}}"),
    }


def test_a0_card_is_bound_to_the_p2_admission_candidate_and_its_real_guard() -> None:
    ledger_path = "docs/evidence/p2-admission-candidate-ledger-2026-09-11.json"
    raw = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"HEAD:{ledger_path}"],
        capture_output=True,
        check=True,
    ).stdout
    candidate = json.loads(raw)["candidate"]
    card = subprocess.run(
        ["git", "-C", str(ROOT), "show", "HEAD:docs/governance/a0-candidate-evaluation-closure.md"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    assert candidate["revision"] in card
    assert candidate["tree"] in card
    assert "immutable-candidate-<date>-" + candidate["revision"][:7] in card

    admission = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{candidate['revision']}:tools/p2_host_platform_admission.py"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    harness = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{candidate['revision']}:tests/deployment/test_representative_clinical_egress.sh"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    assert "ubuntu-24.04-lts-x86_64" in admission
    assert "p2_host_platform_admission.py" in harness
    assert harness.index("p2_host_platform_admission.py") < harness.index("docker info")
    assert harness.index("DOCKER_HOST") < harness.index("docker info")

    workflow = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{candidate['revision']}:.github/workflows/immutable-candidate.yml"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    assert 'tags: ["immutable-candidate-*"]' in workflow
    assert "restricted-mattermost-ingress" in workflow
    assert "restricted-clinical-adapter" in workflow
    assert "--closed-subjects-only" in workflow
    for path in (
        "Dockerfile.mattermost-ingress",
        "Dockerfile.clinical-adapter",
        "tools/verify_immutable_candidate.py",
    ):
        subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{candidate['revision']}:{path}"],
            check=True,
        )


def test_receipt_hashes_bind_committed_git_bytes_not_worktree_line_endings() -> None:
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=git(ROOT, "rev-parse", "HEAD"))
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


def test_candidate_ledger_rejects_v1_or_elevated_historical_receipt_claim() -> None:
    value = ledger.build_ledger(repo_root=ROOT, candidate_revision=git(ROOT, "rev-parse", "HEAD"))
    changed_schema = copy.deepcopy(value)
    changed_schema["schema"] = "restricted-runtime-reconciled-candidate-ledger.v1"
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_schema), repo_root=ROOT) == ["schema"]
    changed_scope = copy.deepcopy(value)
    changed_scope["claims"]["historical_receipts_are_candidate_evidence"] = True
    assert ledger.verify_ledger(ledger.canonical_bytes(changed_scope), repo_root=ROOT) == ["claims"]


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
