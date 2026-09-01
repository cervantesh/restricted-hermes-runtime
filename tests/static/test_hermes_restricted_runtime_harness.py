"""Static contract for the real four-container Hermes restricted witness."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_harness_keeps_the_hermes_client_on_the_closed_uds_surface():
    source = (ROOT / "tests/deployment/test_hermes_restricted_runtime_e2e.sh").read_text(encoding="utf-8")
    for required in (
        "7ce40dad644521c658f2985958be6cfc745d06be",
        "f04d9162a98902926f36e94034821be8f0027bff",
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


def test_fourth_client_keeps_a_separate_pid_namespace():
    source = (ROOT / "tests/deployment/test_hermes_restricted_runtime_e2e.sh").read_text(encoding="utf-8")
    assert "--pid" not in source
