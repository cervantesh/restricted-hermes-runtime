from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "a0_tag_preflight", ROOT / "tools" / "a0_tag_preflight.py"
)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _candidate_repo(tmp_path: Path) -> tuple[Path, Path, str, str]:
    repo = tmp_path / "source"
    remote = tmp_path / "remote.git"
    repo.mkdir()
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "user.name", "test")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "immutable-candidate.yml").write_text(
        "on:\n  push:\n    tags: [immutable-candidate-*]\nsteps:\n  - run: restricted-mattermost-ingress restricted-clinical-adapter --closed-subjects-only\n",
        encoding="utf-8",
    )
    for name in (
        "Dockerfile.mattermost-ingress",
        "Dockerfile.clinical-adapter",
        "tools/verify_immutable_candidate.py",
    ):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("placeholder\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "candidate")
    git(tmp_path, "init", "--bare", str(remote))
    git(repo, "remote", "add", "origin", str(remote))
    git(repo, "push", "origin", "HEAD:main")
    revision = git(repo, "rev-parse", "HEAD")
    return repo, remote, revision, git(repo, "rev-parse", "HEAD^{tree}")


def _tag(revision: str) -> str:
    return "immutable-candidate-2026-09-11-" + revision[:7]


def test_real_git_absent_tag_writes_bounded_canonical_receipt(tmp_path: Path) -> None:
    repo, _remote, revision, tree = _candidate_repo(tmp_path)
    output = tmp_path / "receipt.json"
    assert (
        preflight.main(
            [
                "--repo-root",
                str(repo),
                "--candidate-revision",
                revision,
                "--candidate-tree",
                tree,
                "--tag",
                _tag(revision),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    value = json.loads(output.read_text(encoding="utf-8"))
    assert value == {
        "schema": preflight.SCHEMA,
        "synthetic_non_phi_only": True,
        "candidate": {"revision": revision, "tree": tree},
        "tag": _tag(revision),
        "remote": "origin",
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
    assert output.read_bytes() == preflight._canonical(value)


def test_real_remote_existing_tag_denies_before_receipt(tmp_path: Path, capsys) -> None:
    repo, _remote, revision, tree = _candidate_repo(tmp_path)
    tag = _tag(revision)
    git(repo, "tag", tag)
    git(repo, "push", "origin", f"refs/tags/{tag}")
    output = tmp_path / "receipt.json"
    assert (
        preflight.main(
            [
                "--repo-root",
                str(repo),
                "--candidate-revision",
                revision,
                "--candidate-tree",
                tree,
                "--tag",
                tag,
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert capsys.readouterr().out == "a0-tag-preflight: DENIED class=tag-exists\n"
    assert not output.exists()


def test_passing_preflight_never_replaces_an_existing_receipt(tmp_path: Path) -> None:
    repo, _remote, revision, tree = _candidate_repo(tmp_path)
    output = tmp_path / "receipt.json"
    output.write_bytes(b"existing")
    assert (
        preflight.main(
            [
                "--repo-root",
                str(repo),
                "--candidate-revision",
                revision,
                "--candidate-tree",
                tree,
                "--tag",
                _tag(revision),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert output.read_bytes() == b"existing"


def test_invalid_binding_tag_or_workflow_denies_before_receipt(tmp_path: Path) -> None:
    repo, _remote, revision, tree = _candidate_repo(tmp_path)
    for name, candidate_tree, tag in (
        ("tree", "0" * 40, _tag(revision)),
        ("tag", tree, "immutable-candidate-bad"),
        ("ambiguous-prefix", tree, "immutable-candidate-2026-09-11-" + revision[:8]),
    ):
        output = tmp_path / f"{name}.json"
        status = preflight.main(
            [
                "--repo-root",
                str(repo),
                "--candidate-revision",
                revision,
                "--candidate-tree",
                candidate_tree,
                "--tag",
                tag,
                "--output",
                str(output),
            ]
        )
        assert status == 2
        assert not output.exists()
    (repo / ".github" / "workflows" / "immutable-candidate.yml").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "remove workflow")
    missing = git(repo, "rev-parse", "HEAD")
    output = tmp_path / "workflow.json"
    assert (
        preflight.main(
            [
                "--repo-root",
                str(repo),
                "--candidate-revision",
                missing,
                "--candidate-tree",
                git(repo, "rev-parse", "HEAD^{tree}"),
                "--tag",
                _tag(missing),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()
