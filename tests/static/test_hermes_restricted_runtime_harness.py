"""Static contract for the real four-container Hermes restricted witness."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_harness_keeps_the_hermes_client_on_the_closed_uds_surface():
    source = (ROOT / "tests/deployment/test_hermes_restricted_runtime_e2e.sh").read_text(encoding="utf-8")
    for required in (
        "4f457a55e84be6d40394f86ad45988fba50a5b07",
        "9032d66ac674ccac3b6f49d76dc454d2483c5247",
        "--network none",
        "--group-add 20000",
        ":/run/restricted-inference:ro",
        "e2e_socket_identity",
        "peer=0:10006:20001",
        "e2e_client_readiness",
        "restricted enable",
        "restricted doctor",
        "restricted run --stdin",
        "RESTRICTED_POLICY_MISMATCH",
        "RESTRICTED_RUNTIME_UNAVAILABLE",
        "readiness_altered_fail_closed=passed",
        "exact_cleanup=completed",
        "-c core.autocrlf=false archive --format=tar \"$runtime_head\"",
        "runtime_stage=exact_git_head_lf_blob_export",
        "runtime_stage_archive_sha256",
        "runtime_images=(",
        "refusing pre-existing target image",
        'image rm "$image"',
    ):
        assert required in source


def test_client_image_copies_only_the_closed_hermes_surface():
    source = (ROOT / "tests/deployment/Dockerfile.restricted_hermes_client").read_text(encoding="utf-8")
    for allowed in (
        "restricted_bootstrap.py",
        "restricted_entry.py",
        "restricted_runtime.py",
        "subcommands/restricted.py",
    ):
        assert allowed in source
    for prohibited in ("run_agent.py", "model_tools.py", "plugins/"):
        assert prohibited not in source


def test_client_build_uses_only_exact_runtime_and_hermes_git_archives():
    source = (ROOT / "tests/deployment/test_hermes_restricted_runtime_e2e.sh").read_text(encoding="utf-8")
    for required in (
        'hermes_stage_archive="$runtime/hermes-head.tar"',
        'hermes_stage_root="$runtime/hermes-head"',
        '-c core.autocrlf=false archive --format=tar "$hermes_head"',
        'tar -xf "$hermes_stage_archive" -C "$hermes_stage_root"',
        'hermes_build_context="$hermes_stage_root"',
        'client_dockerfile="$stage_root/tests/deployment/Dockerfile.restricted_hermes_client"',
        "hermes_tree",
        "hermes_stage_archive_sha256",
        "hermes_stage=exact_git_head_blob_export",
    ):
        assert required in source
    # The exact archives, not tracked, staged, or untracked worktree content,
    # are the only two build inputs after their commits are resolved.
    assert 'hermes_build_context="$hermes_source"' not in source
    assert 'client_dockerfile="$runtime_root/' not in source
    assert 'diff --quiet -- "$source_file"' not in source


def test_fourth_client_keeps_a_separate_pid_namespace():
    source = (ROOT / "tests/deployment/test_hermes_restricted_runtime_e2e.sh").read_text(encoding="utf-8")
    assert "--pid" not in source
