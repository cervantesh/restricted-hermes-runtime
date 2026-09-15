"""The composed cold-recovery witness must exercise the lifecycle, not helpers.

The reconciliation card names this falsifier explicitly: a cold-recovery test
that only calls codec helpers, rather than driving the staging lifecycle across
a real restart boundary, is insufficient. These contracts run in the ordinary
contracts job, so the *shape* of the composed witness is proven on every exact
head even where Docker is unavailable.
"""

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "deployment" / "test_clinical_cold_recovery_e2e.py"
STAGING = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"


def harness() -> str:
    return HARNESS.read_text(encoding="utf-8")


def load_staging():
    spec = importlib.util.spec_from_file_location("clinical_staging_surface", STAGING)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_witness_drives_the_real_lifecycle_in_order():
    source = harness()
    ordered = [
        "staging.init()",
        "staging.stop()",
        "staging.backup(backup)",
        "staging.destroy()",
        "restored.restore(backup, external_manifest_hash)",
        "restored.status()",
        "restored.finalize_cold_recovery_verification(",
    ]
    positions = []
    for call in ordered:
        assert call in source, call
        positions.append(source.index(call))
    assert positions == sorted(positions), (
        "the composed witness is out of lifecycle order"
    )


def test_witness_crosses_a_real_restart_boundary():
    source = harness()
    # A graceful stop lets the delayed client terminalize before backup, which
    # would make the restart classification untestable.
    assert '"kill", "--signal", "SIGKILL", "ingress"' in source
    assert "hard_kill_delayed_ingress(staging)" in source
    assert source.index("hard_kill_delayed_ingress(staging)") < source.index(
        "staging.stop()"
    )


def test_witness_asserts_all_three_distinct_terminal_delivery_contracts():
    source = harness()
    # Three faults, three terminal contracts, all erased and none posting:
    #   unknown result, source deleted        -> AMBIGUOUS(delivery_authorization_unknown)
    #   unknown result across a restart       -> AMBIGUOUS(restart_in_flight)
    #   known authorization, source rejected  -> BLOCKED(post_authorization_source_rejected)
    assert '"reason": "delivery_authorization_unknown"' in source
    assert '"reason": "restart_in_flight"' in source
    assert '"reason": "post_authorization_source_rejected"' in source
    assert source.count('"state": "AMBIGUOUS"') == 2
    assert source.count('"state": "BLOCKED"') == 1
    assert source.count('"nonce_erased": True') == 3
    assert source.count('"ciphertext_erased": True') == 3
    assert 'post-count", "cold-unknown")) != 0' in source
    assert "already delivered work was delivered again after restore" in source


def test_witness_separates_known_rejection_from_unknown_result():
    """The two faults must be induced by different mutations, not spelled differently."""
    source = harness()
    # `crash-delay` exceeds the adapter's upstream deadline, so the result is
    # unknown; `source-delete-delay` stays inside it, so the authorization is
    # known and only the later source lookup is rejected.
    assert '"mutate", "crash-delay"' in source
    assert '"mutate", "source-delete-delay"' in source
    assert '"mutate", "drop-source-delete-delay"' in source
    assert "blocked_source_record(staging)" in source
    # The blocked record must be carried across the fence and re-checked.
    assert 'snapshot(restored, str(blocked_after["record_tag"])) != [blocked_after]' in source
    assert 'post-count", "cold-blocked")) != 0' in source
    assert source.index("blocked_source_record(staging)") < source.index("staging.stop()")


def test_witness_recomposes_the_non_recovery_controls_after_restore():
    source = harness()
    assert "assert_composed_controls(restored_status)" in source
    for control in (
        "tls_probe",
        "privileged_provisioner_running",
        "mattermost_publisher",
        "restricted_container_controls",
        "restricted_process_identities",
        "built_images",
    ):
        assert control in source, control
    # Isolation and policy expiry are re-proven on the restored stack.
    assert '"denied", "denied_dm"' in source
    # The lifetime itself is contracted below: it must clear the policy clock
    # skew, which `-1` did not.
    assert '"policy", "cold-expired", str(EXPIRED_POLICY_SECONDS)' in source


def test_witness_binds_the_published_immutable_subjects_when_present():
    source = harness()
    assert "RESTRICTED_IMMUTABLE_CANDIDATE_MANIFEST" in source
    assert "read_subject_admission" in source
    assert source.count("subject_admission=subject_admission") == 3


def test_witness_refuses_to_run_outside_its_bounded_environment():
    source = harness()
    assert 'sys.platform.startswith("linux")' in source
    assert "CLINICAL_E2E_HRH_ROOT must name the clean frozen HRH checkout" in source


def test_witness_verifies_its_own_teardown_and_leaks_nothing():
    source = harness()
    assert "_assert_destroyed_absent()" in source
    assert "cold recovery E2E cleanup was not verified" in source
    assert "leaked synthetic fixture content" in source
    assert "shutil.rmtree(backup)" in source


def test_witness_causal_checks_are_exactly_the_staging_contract():
    module = load_staging()
    source = harness()
    # `duration_bounded` is computed, not a literal; every other check must
    # appear verbatim so the harness cannot quietly drop one.
    for name in module.CAUSAL_RECOVERY_CHECKS:
        if name == "duration_bounded":
            continue
        assert f'"{name}": True' in source, name
    assert '"duration_bounded": elapsed <= DURATION_BOUND_SECONDS' in source


def test_witness_publishes_only_bounded_claims():
    source = harness()
    for nonclaim in ("not PHI", "not production", "not a representative host"):
        assert nonclaim in source, nonclaim
    assert '"synthetic_only": True' in source
    # The mechanical receipt may never be relabelled by this harness.
    assert 'receipt["verification"] != "mechanical_restore_only"' in source
    assert 'verified["verification"] != "causal_e2e_verified"' in source


def test_recovery_helper_image_matches_the_admitted_composed_subject():
    module = load_staging()
    compose = (
        ROOT / "tests" / "deployment" / "clinical-composed-e2e" / "compose.yaml"
    ).read_text(encoding="utf-8")
    assert f"image: {module.RECOVERY_HELPER_IMAGE}" in compose


def test_witness_reobserves_delivery_counts_after_restore():
    """`post-count` is a cached value that the restore repopulates.

    Reading it after restore without a fresh live observation would compare the
    archived number with itself, so `already_delivered_not_redelivered` could
    never fail. The live `expect` has to come first.
    """
    source = harness()
    live = 'restored.control("expect", "cold-already-delivered", "reply")'
    cached = 'restored.control("post-count", "cold-already-delivered")'
    assert live in source
    assert cached in source
    assert source.index(live) < source.index(cached)


def test_witness_expires_the_policy_past_the_clock_skew():
    """A policy that expired one second ago is still valid.

    The generated policy carries `clock_skew_seconds: 30` and the predicate is
    `now - skew > expires_at`, so the fixture has to clear the skew or it
    records a success it never observed.
    """
    source = harness()
    assert "EXPIRED_POLICY_SECONDS" in source
    namespace: dict = {}
    for line in source.splitlines():
        if line.startswith("EXPIRED_POLICY_SECONDS"):
            exec(line, namespace)  # noqa: S102 - reading our own constant
    value = namespace["EXPIRED_POLICY_SECONDS"]
    assert value <= -60, "the expiry fixture must clear the 30s policy clock skew"
    assert 'restored.control("policy", "cold-expired", str(EXPIRED_POLICY_SECONDS))' in source
    assert '"cold-expired", "-1"' not in source


def test_witness_observes_the_refusal_not_merely_the_silence():
    """An expired policy is refused at load, so ingress exits instead of serving.

    Silence right after `up --detach` is unreadiness, not a fail-closed
    control, so the witness must observe the refusal itself and must reject the
    outcome where ingress becomes ready anyway.
    """
    source = harness()
    assert "restored._await_ingress_ready(started_at)" in source
    assert "ingress became authenticated-ready with an expired policy" in source
    assert "exited before authenticated readiness" in source
    assert "ingress exited cleanly rather than refusing the expired policy" in source
    ready = source.index("restored._await_ingress_ready(started_at)")
    send = source.index('restored.control("send", "actor", "actor_dm", PATIENT, "cold-expired")')
    assert ready < send
