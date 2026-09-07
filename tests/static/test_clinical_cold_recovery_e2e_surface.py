from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_cold_recovery_drill_exercises_real_wrapper_and_causal_controls():
    script = (ROOT / "tests" / "deployment" / "test_clinical_cold_recovery_e2e.py").read_text(encoding="utf-8")
    for command in ("staging.init()", "staging.stop()", "staging.backup(backup)", "staging.destroy()", "restored.restore("):
        assert command in script
    for invariant in (
        "source deletion did not preserve the erased unknown result",
        "already delivered work was delivered again after restore",
        "ordinary known-success delivery did not authorize exactly once",
        "restore did not erase the unknown delivery result",
        "restored unknown delivery produced a post",
        "cold-isolation",
        "cold-expired",
        "restored Compose logs or exported evidence leaked synthetic fixture content",
        "finalize_cold_recovery_verification",
        "causal_e2e_verified",
        "1200-second bound",
    ):
        assert invariant in script
    assert "synthetic_only" in script
    assert "not PHI" in script


def test_cold_recovery_drill_only_reports_success_after_verified_teardown():
    script = (ROOT / "tests" / "deployment" / "test_clinical_cold_recovery_e2e.py").read_text(encoding="utf-8")
    assert "cold recovery E2E cleanup was not verified" in script
    assert "teardown._assert_destroyed_absent()" in script
    assert "ignore_errors=True" not in script
    assert script.index("teardown._assert_destroyed_absent()") < script.rindex("print(json.dumps(report, sort_keys=True))")


def test_cold_fence_hard_kills_the_delayed_ingress_after_barriers_before_backup():
    script = (ROOT / "tests" / "deployment" / "test_clinical_cold_recovery_e2e.py").read_text(encoding="utf-8")
    helper_start = script.index("def hard_kill_delayed_ingress")
    helper_end = script.index("\ndef main()", helper_start)
    helper = script[helper_start:helper_end]
    assert 'staging.compose("kill", "--signal", "SIGKILL", "ingress", check=False)' in helper
    assert "ingress did not stop after SIGKILL" in helper
    assert '"stop", "ingress"' not in helper
    unknown_start = script.index('grants_before_unknown =')
    hard_kill = script.index("hard_kill_delayed_ingress(staging)", unknown_start)
    graceful_stop = script.index("staging.stop()", unknown_start)
    cold_backup = script.index("staging.backup(backup)", unknown_start)
    assert unknown_start < hard_kill < graceful_stop < cold_backup
