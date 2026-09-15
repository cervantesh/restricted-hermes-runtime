#!/usr/bin/env python3
"""Linux-only composed proof that cold recovery preserves the bounded controls.

This is the composition step: one exact candidate, one synthetic run, in which
the delivery/reauthorization, isolation, policy, TLS and immutable-subject
controls are observed *through* a real backup -> destroy -> restore cycle
rather than beside it.

`restore` alone can only witness that the bytes came back and the stack
started, which is why it publishes `mechanical_restore_only`. The behaviors
below are the ones a composed run must establish before
`finalize_cold_recovery_verification` will publish anything stronger.

Nonclaims: synthetic only. Not PHI, not a representative host, not production,
not a compliance certification.
"""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HRH_ROOT = Path(os.environ.get("CLINICAL_E2E_HRH_ROOT", ""))
CANDIDATE_MANIFEST = os.environ.get("RESTRICTED_IMMUTABLE_CANDIDATE_MANIFEST")
PATIENT = "018f22bb-414d-7cc4-b5a4-83cc8ec92cb1"
PORT = int(os.environ.get("CLINICAL_E2E_RECOVERY_PORT", "18473"))
DURATION_BOUND_SECONDS = 1800


def load_wrapper():
    path = ROOT / "deploy" / "clinical-staging" / "clinical_staging.py"
    spec = importlib.util.spec_from_file_location("clinical_staging_recovery", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("clinical staging wrapper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def admission(module):
    """Use the published immutable subjects when the candidate names them."""
    if not CANDIDATE_MANIFEST:
        return None
    return module.read_subject_admission(Path(CANDIDATE_MANIFEST), runtime=ROOT)


def wait_until(probe, message: str, *, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.25)
    raise RuntimeError(message)


def snapshot(staging, record_tag: str | None = None) -> list[dict[str, object]]:
    staging.compose("pause", "ingress")
    try:
        args = (
            ("snapshot-outbox-records", record_tag)
            if record_tag
            else ("snapshot-outbox-records",)
        )
        value = json.loads(staging.control(*args))
    finally:
        staging.compose("unpause", "ingress", check=False)
    if not isinstance(value, list):
        raise RuntimeError("outbox snapshot was not a list")
    return value


def reauthorizations(staging, tag: str) -> int:
    evidence = json.loads(staging.control("grant-evidence", tag))
    return int(evidence["audits"].get("restricted_hermes_delivery_reauthorized", 0))


def hard_kill_delayed_ingress(staging) -> None:
    """Freeze the observed IN_FLIGHT record without its client catch path.

    A graceful stop can let the delayed client catch the disconnect and
    terminalize before backup. SIGKILL is deliberately limited to ingress, and
    only after both the audit and IN_FLIGHT barriers, so restore must classify
    this durable stale claim as `restart_in_flight`.
    """
    killed = staging.compose("kill", "--signal", "SIGKILL", "ingress", check=False)
    if killed.returncode:
        raise RuntimeError(
            "could not SIGKILL delayed ingress for the cold-fence witness"
        )

    def ingress_is_stopped() -> bool:
        rows = [
            row
            for row in staging._containers(all_containers=True)
            if row.get("Service") == "ingress"
        ]
        if len(rows) != 1:
            raise RuntimeError(
                "could not identify the exact ingress process after SIGKILL"
            )
        return str(rows[0].get("State", "")).lower() in {"exited", "dead"}

    wait_until(ingress_is_stopped, "ingress did not stop after SIGKILL")


def pause_one_in_flight(staging, tag: str) -> dict[str, object]:
    """Authorize one delivery and stop it mid-flight, before any terminal state."""
    staging.control("mutate", "reset")
    before_grants = int(staging.control("grant-count"))
    staging.control("mutate", "crash-delay")
    staging.control("send", "actor", "actor_dm", PATIENT, tag)
    wait_until(
        lambda: int(staging.control("grant-count")) > before_grants,
        f"clinical read was not granted for {tag}",
    )
    wait_until(
        lambda: int(staging.control("delivery-delay-active")) == 1,
        f"delivery did not enter pause for {tag}",
    )
    in_flight = [row for row in snapshot(staging) if row.get("state") == "IN_FLIGHT"]
    if len(in_flight) != 1:
        raise RuntimeError(f"fixture did not isolate one IN_FLIGHT record for {tag}")
    record = in_flight[0]
    record_tag = record.get("record_tag")
    if not isinstance(record_tag, str) or len(record_tag) != 64:
        raise RuntimeError(f"record tag is invalid for {tag}")
    return record


def ambiguous_source_record(staging) -> tuple[dict[str, object], dict[str, object]]:
    """A definitively rejected later source lookup, erased before the fence."""
    before = pause_one_in_flight(staging, "cold-source-deleted")
    tag = str(before["record_tag"])
    staging.control("delete-source", "cold-source-deleted")
    staging.control("mutate", "drop-crash-delay")
    wait_until(
        lambda: reauthorizations(staging, "cold-source-deleted") == 1,
        "source-deletion unknown authorization did not commit exactly once",
    )
    staging.control("expect", "cold-source-deleted", "no-reply")
    rows = snapshot(staging, tag)
    if len(rows) != 1:
        raise RuntimeError("terminal source-deletion record is missing")
    after = rows[0]
    expected = {
        "record_tag": tag,
        "state": "AMBIGUOUS",
        "reason": "delivery_authorization_unknown",
        "generation": int(before["generation"]) + 1,
        "nonce_erased": True,
        "ciphertext_erased": True,
    }
    if after != expected:
        raise RuntimeError("source deletion did not preserve the erased unknown result")
    return before, after


def assert_composed_controls(status: dict[str, object]) -> None:
    """The restored stack must still satisfy the non-recovery controls.

    These are the controls the reconciliation is composing with cold recovery:
    a CA-verified TLS probe, the sole loopback publisher, the internal network
    topology, the restricted container and process confinement, the absent
    privileged provisioner, and an authenticated-ready ingress.
    """
    if status.get("tls_probe", {}).get("verified") is not True:
        raise RuntimeError("restored stack did not pass the CA-verified TLS probe")
    if status.get("privileged_provisioner_running") is not False:
        raise RuntimeError("restored stack retained the privileged provisioner")
    publisher = status.get("mattermost_publisher")
    if not isinstance(publisher, dict) or not publisher:
        raise RuntimeError("restored stack did not report its bounded publisher")
    for key in (
        "restricted_container_controls",
        "restricted_process_identities",
        "built_images",
    ):
        if not isinstance(status.get(key), dict) or not status[key]:
            raise RuntimeError(f"restored status is missing composed evidence: {key}")
    if not str(status.get("ingress_started_at", "")):
        raise RuntimeError("restored status did not observe the ingress start time")


def main() -> None:
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise RuntimeError("cold recovery E2E requires local Linux Docker/Compose")
    if not HRH_ROOT.is_dir():
        raise RuntimeError(
            "CLINICAL_E2E_HRH_ROOT must name the clean frozen HRH checkout"
        )
    module = load_wrapper()
    subject_admission = admission(module)
    project = "clinicalstagingrecovery" + secrets.token_hex(4)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="restricted-clinical-recovery-") as raw:
        root = Path(raw)
        state = root / f"{project}.synthetic-clinical-staging"
        backup = root / "cold-backup"
        staging = module.ClinicalStaging(
            ROOT, HRH_ROOT, state, project, PORT, subject_admission=subject_admission
        )
        report: dict[str, object] | None = None
        try:
            staging.init()

            # An ordinary success first: the normal one-authorization, one-post
            # path has to hold before the cold fence means anything.
            staging.control(
                "send", "actor", "actor_dm", PATIENT, "cold-already-delivered"
            )
            staging.control("expect", "cold-already-delivered", "reply")
            delivered_before = int(
                staging.control("post-count", "cold-already-delivered")
            )
            if delivered_before != 1:
                raise RuntimeError("baseline delivery count was not exactly one")
            if reauthorizations(staging, "cold-already-delivered") != 1:
                raise RuntimeError(
                    "ordinary known-success delivery did not authorize exactly once"
                )

            source_before, source_after = ambiguous_source_record(staging)

            # This item is IN_FLIGHT at the cold fence with a deliberately
            # unknown authorization outcome.  Restore must classify it
            # ambiguous and erase it, never reauthorize or post it.
            unknown_before = pause_one_in_flight(staging, "cold-unknown")
            unknown_tag = str(unknown_before["record_tag"])
            hard_kill_delayed_ingress(staging)

            staging.stop()
            backup_receipt = staging.backup(backup)
            external_manifest_hash = backup_receipt["manifest_sha256"]
            if not isinstance(external_manifest_hash, str):
                raise RuntimeError("backup did not provide an external manifest hash")
            # `backup` tears down the Compose objects it archived around, so
            # the target it leaves is cold, not stopped.
            if backup_receipt["lifecycle"] != "cold":
                raise RuntimeError("backup did not record the teardown it performed")
            staging.destroy()

            restored = module.ClinicalStaging(
                ROOT,
                HRH_ROOT,
                state,
                project,
                PORT,
                subject_admission=subject_admission,
            )
            receipt = restored.restore(backup, external_manifest_hash)
            if receipt["manifest_sha256"] != external_manifest_hash:
                raise RuntimeError(
                    "restore receipt did not bind the external manifest hash"
                )
            if receipt["verification"] != "mechanical_restore_only":
                raise RuntimeError("restore published more than a mechanical claim")

            restored_status = restored.status()
            assert_composed_controls(restored_status)

            restored.control("mutate", "drop-crash-delay")
            wait_until(
                lambda: reauthorizations(restored, "cold-unknown") == 1,
                "restored unknown authorization did not commit exactly once",
            )
            restored.control("expect", "cold-unknown", "no-reply")
            unknown_rows = snapshot(restored, unknown_tag)
            if len(unknown_rows) != 1:
                raise RuntimeError("restored unknown terminal record is missing")
            unknown_after = unknown_rows[0]
            expected_unknown = {
                "record_tag": unknown_tag,
                "state": "AMBIGUOUS",
                "reason": "restart_in_flight",
                "generation": int(unknown_before["generation"]) + 1,
                "nonce_erased": True,
                "ciphertext_erased": True,
            }
            if unknown_after != expected_unknown:
                raise RuntimeError("restore did not erase the unknown delivery result")
            if int(restored.control("post-count", "cold-unknown")) != 0:
                raise RuntimeError("restored unknown delivery produced a post")

            if (
                int(restored.control("post-count", "cold-already-delivered"))
                != delivered_before
            ):
                raise RuntimeError(
                    "already delivered work was delivered again after restore"
                )
            if snapshot(restored, str(source_after["record_tag"])) != [source_after]:
                raise RuntimeError(
                    "deleted-source terminal erased state changed after restore"
                )

            restored.control("send", "denied", "denied_dm", PATIENT, "cold-isolation")
            restored.control("expect", "cold-isolation", "no-reply")
            restored.control("send", "actor", "actor_dm", PATIENT, "cold-allowed")
            restored.control("expect", "cold-allowed", "reply")

            # Expired policy is a post-restore fail-closed control, not a new
            # backup feature.  It must not revive a response path.
            restored.compose("stop", "ingress")
            restored.control("policy", "cold-expired", "-1")
            restored.compose("up", "--detach", "ingress")
            restored.control("send", "actor", "actor_dm", PATIENT, "cold-expired")
            restored.control("expect", "cold-expired", "no-reply")

            fixture_tokens = (
                "cold-source-deleted",
                "cold-unknown",
                "cold-allowed",
                PATIENT,
            )
            evidence_text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (state / "evidence").rglob("*")
                if path.is_file()
            )
            compose_logs = restored.compose("logs", "--no-color", check=False).stdout
            if any(
                value in evidence_text or value in compose_logs
                for value in fixture_tokens
            ):
                raise RuntimeError(
                    "restored Compose logs or exported evidence leaked synthetic fixture content"
                )

            elapsed = time.monotonic() - started
            causal_checks = {
                "source_deletion_persisted": True,
                "unknown_delivery_is_ambiguous_once": True,
                "already_delivered_not_redelivered": True,
                "isolation_preserved": True,
                "expired_policy_fails_closed": True,
                "artifacts_clean": True,
                "duration_bounded": elapsed <= DURATION_BOUND_SECONDS,
            }
            verified = restored.finalize_cold_recovery_verification(
                external_manifest_hash, causal_checks
            )
            if verified["verification"] != "causal_e2e_verified":
                raise RuntimeError(
                    "causal recovery verification receipt was not published"
                )

            report = {
                "schema": module.BACKUP_SCHEMA,
                "synthetic_only": True,
                "project": project,
                "manifest_sha256": external_manifest_hash,
                "source": verified["source"],
                "subject_admitted": bool(subject_admission),
                "source_deletion_before": source_before,
                "source_deletion_after": source_after,
                "delivered_count_before_after": delivered_before,
                "unknown_delivery_before": unknown_before,
                "unknown_delivery_after": unknown_after,
                "restored_tls_probe": restored_status["tls_probe"],
                "restored_built_images": restored_status["built_images"],
                "restored_policy_digest": restored_status["policy_digest"],
                "elapsed_seconds": round(elapsed, 3),
                "nonclaims": [
                    "not PHI",
                    "not production",
                    "not a representative host",
                    "not a compliance certification",
                ],
            }
            if elapsed > DURATION_BOUND_SECONDS:
                raise RuntimeError(
                    f"synthetic cold recovery exceeded the {DURATION_BOUND_SECONDS}-second bound"
                )
        finally:
            cleanup_failures: list[Exception] = []
            teardown = module.ClinicalStaging(
                ROOT,
                HRH_ROOT,
                state,
                project,
                PORT,
                subject_admission=subject_admission,
            )
            if state.exists():
                try:
                    teardown.destroy()
                except Exception as exc:
                    cleanup_failures.append(exc)
            try:
                # `destroy` already performs this on its success path.  Repeat
                # it even when destroy raised, so a partial teardown cannot be
                # mistaken for a passing composed witness.
                teardown._assert_destroyed_absent()
            except Exception as exc:
                cleanup_failures.append(exc)
            try:
                if backup.exists():
                    shutil.rmtree(backup)
            except Exception as exc:
                cleanup_failures.append(exc)
            if cleanup_failures:
                detail = "; ".join(str(error) for error in cleanup_failures)
                raise RuntimeError(
                    f"cold recovery E2E cleanup was not verified: {detail}"
                ) from cleanup_failures[0]
        if report is None:
            raise RuntimeError("cold recovery E2E did not produce a report")
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
